/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2026 ScyllaDB Ltd.
 */
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/api.hh>
#include <cstdint>
#include <chrono>
#include <optional>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <seastar/quic/quic.hh>


namespace seastar::quic::experimental {

    ngtcp2_tstamp now_ns() {
        using namespace std::chrono;
        return duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    void rand_bytes(uint8_t* dst, size_t len) {
        if (gnutls_rnd(GNUTLS_RND_RANDOM, dst, len) == 0) return;
        for (size_t i = 0; i < len; ++i) dst[i] = (uint8_t)std::rand();
    }

    // Helper functions are hidden in internal namespace.
namespace internal {
    void sa_to_storage_v6(const seastar::socket_address& sa, sockaddr_storage& out, socklen_t& outlen) {
        std::memset(&out, 0, sizeof(out));
        auto in6 = sa.as_posix_sockaddr_in6();
        outlen = sizeof(sockaddr_in6);
        std::memcpy(&out, &in6, sizeof(sockaddr_in6));
    }

    const ngtcp2_mem* get_ngtcp2_allocator() {
        thread_local static const ngtcp2_mem mem = {
            nullptr,
            seastar_malloc,
            seastar_free,
            seastar_calloc,
            seastar_realloc
        };
        return &mem;
    }

    void fill_transport_params(ngtcp2_transport_params& params, const connection_config& config) {
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local  = config.initial_max_stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote = config.initial_max_stream_data_bidi_remote;
        params.initial_max_data                    = config.initial_max_data;
        params.initial_max_streams_bidi            = config.initial_max_streams_bidi;
        params.max_idle_timeout                    = config.max_idle_timeout_ns;
    }

    ngtcp2_callbacks get_default_callbacks() {
        ngtcp2_callbacks callbacks{};
        callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.rand = [](uint8_t *dest, size_t len, const ngtcp2_rand_ctx*) {
            rand_bytes(dest, len);
        };
        return callbacks;
    }

    ngtcp2_settings get_default_settings() {
        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.initial_ts = now_ns();
        return settings;
    }

    size_t max_tx_udp_payload(ngtcp2_conn* conn) {
        if (!conn) return default_udp_payload;
        auto max_sz = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn);
        if (max_sz == 0) return default_udp_payload;
        if (max_sz > max_udp_payload) max_sz = max_udp_payload;
        return static_cast<size_t>(max_sz);
    }
} // namespace internal

using SettingsConfigurator = std::function<void(ngtcp2_settings&)>;
using ParamsConfigurator = std::function<void(ngtcp2_transport_params&)>;
using CallbacksConfigurator = std::function<void(ngtcp2_callbacks&)>;

QuicConfig::QuicConfig() {
    std::memset(&settings_, 0, sizeof(settings_));
    std::memset(&params_, 0, sizeof(params_));
    std::memset(&callbacks_, 0, sizeof(callbacks_));

    settings_ = internal::get_default_settings();

    internal::connection_config config;
    internal::fill_transport_params(params_, config);
    
    callbacks_ = internal::get_default_callbacks();
}

// Possible to use lambdas to set settings, params or callbacks.
QuicConfig& QuicConfig::withSettings(SettingsConfigurator func) {
    if (func) {
        func(settings_);
    }
    return *this;
}

QuicConfig& QuicConfig::withTransportParams(ParamsConfigurator func) {
    if (func) {
        func(params_);
    }
    return *this;
}

QuicConfig& QuicConfig::withCallbacks(CallbacksConfigurator func) {
    if (func) {
        func(callbacks_);
    }
    return *this;
}


quic_cid::quic_cid() {
    ngtcp2_cid_init(&_cid, nullptr, 0);
}

quic_cid::quic_cid(const uint8_t* data, size_t len) {
    ngtcp2_cid_init(&_cid, data, std::min(len, (size_t)NGTCP2_MAX_CIDLEN));
}

quic_cid quic_cid::random(size_t len) {
    quic_cid c;
    c._cid.datalen = std::min(len, (size_t)NGTCP2_MAX_CIDLEN);
    rand_bytes(c._cid.data, c._cid.datalen);
    return c;
}

std::string quic_cid::to_string() const {
    if (_cid.datalen == 0) return "unknown";
    
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(_cid.datalen * 2);
    for (size_t i = 0; i < _cid.datalen; ++i) {
        result.push_back(hex_chars[(_cid.data[i] >> 4) & 0x0F]);
        result.push_back(hex_chars[_cid.data[i] & 0x0F]);
    }
    return result;
}

bool quic_cid::operator==(const quic_cid& other) const {
    return _cid.datalen == other._cid.datalen &&
        std::memcmp(_cid.data, other._cid.data, _cid.datalen) == 0;
}

bool quic_cid::operator!=(const quic_cid& other) const {
    return !(*this == other);
}

quic_cid& quic_cid::operator=(const quic_cid& other) {
    if (this != &other) {
        _cid = other._cid;
    }
    return *this;
}

quic_cid& quic_cid::operator=(const ngtcp2_cid& other) {
    _cid = other;
    return *this;
}


Connection::Connection(const seastar::socket_address& local, const seastar::socket_address& remote) {
    set_local_addr(local);
    set_remote_addr(remote);
}

Connection::~Connection() {
    if (_conn) {
        ngtcp2_conn_del(_conn);
        _conn = nullptr;
    }
    if (_tls) {
        gnutls_deinit(_tls);
        _tls = nullptr;
    }
}

void Connection::set_local_addr(const seastar::socket_address& sa) {
    internal::sa_to_storage_v6(sa, _local_ss, _local_ss_len);
}

void Connection::set_remote_addr(const seastar::socket_address& sa) {
    internal::sa_to_storage_v6(sa, _remote_ss, _remote_ss_len);
}

void Connection::fill_path(ngtcp2_path& p) {
    internal::init_ngtcp2_addr(&p.local,  (sockaddr*)&_local_ss,  _local_ss_len);
    internal::init_ngtcp2_addr(&p.remote, (sockaddr*)&_remote_ss, _remote_ss_len);
}

// Functions using ngtcp2 functions.

void Connection::init_client(const QuicConfig& config, void* user_data) {
    ngtcp2_path path{};
    fill_path(path);

    int rv = ngtcp2_conn_client_new(&_conn,
                                _dcid.get(),
                                _scid.get(),
                                &path,
                                NGTCP2_PROTO_VER_V1,
                                config.getCallbacksPtr(), 
                                config.getSettingsPtr(), 
                                config.getTransportParamsPtr(),
                                internal::get_ngtcp2_allocator(),
                                user_data);

    if (rv != 0) {
        throw std::runtime_error("ngtcp2_conn_client_new failed: " + std::string(ngtcp2_strerror(rv)));
    }

    if (_tls) {
        ngtcp2_conn_set_tls_native_handle(_conn, _tls);
    }
    
    _conn_ref.user_data = _conn;
}

void Connection::init_server(const QuicConfig& config, void* user_data) {
    ngtcp2_path path{};
    fill_path(path);

    int rv = ngtcp2_conn_server_new(&_conn, 
                                _dcid.get(), 
                                _scid.get(), 
                                &path,
                                NGTCP2_PROTO_VER_V1, 
                                config.getCallbacksPtr(), 
                                config.getSettingsPtr(),
                                config.getTransportParamsPtr(), 
                                internal::get_ngtcp2_allocator(), 
                                user_data);

    if (rv != 0) throw std::runtime_error(std::string("server_new: ") + ngtcp2_strerror(rv));

    if (_tls) {
        ngtcp2_conn_set_tls_native_handle(_conn, _tls);
    }
    
    _conn_ref.user_data = _conn;
}

int64_t Connection::open_bidi_stream(int64_t& stream_id) {
    if (!_conn) return NGTCP2_ERR_INTERNAL;
    return ngtcp2_conn_open_bidi_stream(_conn, &stream_id, nullptr);
}

quic_cid Connection::parse_initial_packet(const uint8_t* data, size_t len) {
    ngtcp2_version_cid vc;
    int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, NGTCP2_MAX_CIDLEN);
    
    if (rv < 0) {
        throw std::runtime_error("Failed to decode version CID");
    }

    _dcid = quic_cid(vc.scid, vc.scidlen);

    return quic_cid(vc.dcid, vc.dcidlen);
}

ssize_t Connection::write_pending_packet(uint8_t* dest, size_t dest_len) {
    if (!_conn) return NGTCP2_ERR_INTERNAL;

    ngtcp2_path path;
    fill_path(path);

    ngtcp2_pkt_info pi;
    std::memset(&pi, 0, sizeof(pi));

    ssize_t nwrite = ngtcp2_conn_write_pkt(_conn, &path, &pi, dest, dest_len, now_ns());
    
    return nwrite;
}

ssize_t Connection::write_stream_packet(int64_t stream_id,
                                const uint8_t* data, size_t datalen, 
                                ssize_t& bytes_consumed, 
                                uint8_t* dest, size_t dest_len) {
    
    if (!_conn) return NGTCP2_ERR_INTERNAL;

    ngtcp2_path path;
    fill_path(path);
    
    ngtcp2_pkt_info pi;
    std::memset(&pi, 0, sizeof(pi));

    ngtcp2_vec vec;
    vec.base = const_cast<uint8_t*>(data);
    vec.len = datalen;

    return ngtcp2_conn_writev_stream(_conn, &path, &pi, 
                                    dest, dest_len, 
                                    &bytes_consumed, 
                                    0, 
                                    stream_id,
                                    &vec, 1, 
                                    now_ns());
}

int Connection::read_packet(const uint8_t* data, size_t len) {
    if (!_conn) return NGTCP2_ERR_INTERNAL;

    ngtcp2_path path;
    fill_path(path);

    ngtcp2_pkt_info pi;
    std::memset(&pi, 0, sizeof(pi));

    return ngtcp2_conn_read_pkt(_conn, &path, &pi, data, len, now_ns());
}

ssize_t Connection::write_connection_close(uint8_t* dest, size_t dest_len) {
    if (!_conn) return NGTCP2_ERR_INTERNAL;

    ngtcp2_path path;
    fill_path(path);

    ngtcp2_pkt_info pi;
    std::memset(&pi, 0, sizeof(pi));

    ngtcp2_ccerr err;
    ngtcp2_ccerr_default(&err); 

    return ngtcp2_conn_write_connection_close(
        _conn, &path, &pi,
        dest, dest_len,
        &err,
        now_ns()
    );
}

ngtcp2_tstamp Connection::get_expiry() const {
    if (!_conn) return UINT64_MAX;
    return ngtcp2_conn_get_expiry(_conn);
}

int Connection::handle_expiry() {
    if (!_conn) return NGTCP2_ERR_INTERNAL;
    return ngtcp2_conn_handle_expiry(_conn, now_ns());
}

size_t Connection::max_tx_udp_payload_size() {
    return internal::max_tx_udp_payload(_conn);
}

void Connection::generate_random_cids(size_t len) {
    _scid = quic_cid::random(len);
    _dcid = quic_cid::random(len);
}

void Connection::generate_scid(size_t len) {
    _scid = quic_cid::random(len);
}

void Connection::set_dcid(const quic_cid& cid) {
            _dcid = cid;
        }

void Connection::set_dcid(const uint8_t* data, size_t len) {
    _dcid = quic_cid(data, len);
}

}