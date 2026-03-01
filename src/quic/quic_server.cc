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

#include <seastar/quic/quic_server.hh>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/util/log.hh>

namespace seastar::quic::experimental {

namespace {

constexpr size_t max_cid_len = 20;
constexpr size_t server_short_cid_len = 8;
constexpr size_t max_udp_payload_size = 65527;
constexpr size_t default_udp_payload_size = 1200;

static logger quic_server_log("quic_server");

class gnutls_global_guard {
public:
    gnutls_global_guard() {
        gnutls_global_init();
    }
    ~gnutls_global_guard() {
        gnutls_global_deinit();
    }
};

void ensure_gnutls_global() {
    static gnutls_global_guard guard;
}

ngtcp2_tstamp now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

void rand_bytes(uint8_t* dst, size_t len) {
    if (gnutls_rnd(GNUTLS_RND_RANDOM, dst, len) == 0) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        dst[i] = static_cast<uint8_t>(std::rand());
    }
}

void* mem_malloc(size_t size, void*) {
    return std::malloc(size);
}

void mem_free(void* ptr, void*) {
    std::free(ptr);
}

void* mem_calloc(size_t n, size_t s, void*) {
    return std::calloc(n, s);
}

void* mem_realloc(void* ptr, size_t s, void*) {
    return std::realloc(ptr, s);
}

const ngtcp2_mem* ngtcp2_mem_for_thread() {
    thread_local const ngtcp2_mem mem = {
      nullptr,
      mem_malloc,
      mem_free,
      mem_calloc,
      mem_realloc,
    };
    return &mem;
}

void init_ngtcp2_addr(ngtcp2_addr* addr, const sockaddr* sa, size_t len) {
    addr->addr = const_cast<sockaddr*>(sa);
    addr->addrlen = static_cast<socklen_t>(len);
}

void to_sockaddr_storage_v6(const socket_address& sa, sockaddr_storage& out, socklen_t& outlen) {
    std::memset(&out, 0, sizeof(out));
    auto in6 = sa.as_posix_sockaddr_in6();
    std::memcpy(&out, &in6, sizeof(in6));
    outlen = sizeof(in6);
}

temporary_buffer<char> linearize_packet(std::span<temporary_buffer<char>> bufs) {
    size_t total = 0;
    for (const auto& b : bufs) {
        total += b.size();
    }

    temporary_buffer<char> result(total);
    char* dst = result.get_write();
    size_t offset = 0;
    for (const auto& b : bufs) {
        std::memcpy(dst + offset, b.get(), b.size());
        offset += b.size();
    }
    return result;
}

future<> send_datagram(net::datagram_channel& channel, const socket_address& dst, const uint8_t* data, size_t len) {
    if (len == 0) {
        co_return;
    }
    quic_server_log.trace("udp send datagram: dst={} bytes={}", dst, len);
    temporary_buffer<char> tb(len);
    std::memcpy(tb.get_write(), data, len);
    std::array<temporary_buffer<char>, 1> bufs{std::move(tb)};
    co_await channel.send(dst, std::span<temporary_buffer<char>>(bufs));
}

std::string cid_key(const uint8_t* data, size_t len) {
    return std::string(reinterpret_cast<const char*>(data), len);
}

enum class quic_long_type : uint8_t {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

struct dcid_parse_result {
    bool ok = false;
    bool long_header = false;
    quic_long_type long_type = quic_long_type::initial;
    std::array<uint8_t, max_cid_len> dcid{};
    size_t dcid_len = 0;
};

dcid_parse_result parse_dcid(const uint8_t* pkt, size_t len, size_t short_dcid_len) {
    dcid_parse_result result{};
    if (len < 1) {
        return result;
    }

    const uint8_t long_header = (pkt[0] & 0x80u) != 0;
    result.long_header = long_header;
    if (long_header) {
        if (len < 1 + 4 + 1) {
            return result;
        }

        result.long_type = static_cast<quic_long_type>((pkt[0] >> 4) & 0x03u);
        size_t off = 1 + 4;
        const uint8_t cid_len = pkt[off++];
        if (cid_len > result.dcid.size() || off + cid_len > len) {
            return result;
        }

        std::memcpy(result.dcid.data(), pkt + off, cid_len);
        result.dcid_len = cid_len;
        result.ok = true;
        return result;
    }

    if (len < 1 + short_dcid_len) {
        return result;
    }
    std::memcpy(result.dcid.data(), pkt + 1, short_dcid_len);
    result.dcid_len = short_dcid_len;
    result.ok = true;
    return result;
}

class quic_server_impl;

struct conn_rx_event {
    socket_address src;
    temporary_buffer<char> packet;
};

struct server_connection : public enable_lw_shared_from_this<server_connection> {
    quic_server_impl* server = nullptr;
    internal::session_runtime_ptr runtime;

    ngtcp2_conn* conn = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    gnutls_session_t tls = nullptr;

    socket_address peer{};
    sockaddr_storage local_ss{};
    socklen_t local_ss_len = 0;
    sockaddr_storage peer_ss{};
    socklen_t peer_ss_len = 0;

    queue<std::unique_ptr<conn_rx_event>> rx_queue{1024};
    queue<std::unique_ptr<quic_message>> tx_queue{1024};
    std::optional<promise<>> actor_waiter;
    condition_variable timer_cv;
    bool timer_rearm_requested = false;
    bool tick_pending = false;
    bool queues_aborted = false;
    bool unregistered = false;
    bool stop_requested = false;
    std::optional<quic_error> stop_error;
    sstring stop_error_detail;

    bool closing = false;
    size_t tx_payload_limit = default_udp_payload_size;
    std::unordered_set<std::string> mapped_dcids;

    ~server_connection() {
        abort_event_queues("server connection destroyed");
        wake_actor();
        if (conn) {
            ngtcp2_conn_del(conn);
            conn = nullptr;
        }
        if (tls) {
            gnutls_deinit(tls);
            tls = nullptr;
        }
    }

    void fill_path(ngtcp2_path& path) {
        init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&local_ss), local_ss_len);
        init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&peer_ss), peer_ss_len);
    }

    bool has_pending_actor_work() const noexcept {
        return stop_requested || !rx_queue.empty() || !tx_queue.empty() || tick_pending;
    }

    future<> wait_for_actor_wakeup() {
        if (has_pending_actor_work() || closing) {
            co_return;
        }
        actor_waiter.emplace();
        try {
            co_await actor_waiter->get_future();
        } catch (...) {
        }
    }

    void wake_actor() {
        if (!actor_waiter) {
            return;
        }
        auto waiter = std::move(*actor_waiter);
        actor_waiter.reset();
        waiter.set_value();
    }

    void signal_tick() {
        if (closing || tick_pending) {
            return;
        }
        tick_pending = true;
        wake_actor();
    }

    void request_timer_rearm() {
        timer_rearm_requested = true;
        timer_cv.signal();
    }

    void abort_event_queues(const char* why) {
        if (queues_aborted) {
            return;
        }
        queues_aborted = true;
        auto ex = std::make_exception_ptr(std::runtime_error(why));
        rx_queue.abort(ex);
        tx_queue.abort(std::move(ex));
    }

    bool active() const noexcept;
    void stop_transport();
    void fail(quic_error error, const sstring& detail);
};

using conn_ptr = lw_shared_ptr<server_connection>;

class quic_server_impl {
public:
    future<> start(quic_server_config cfg) {
        if (_started) {
            throw_quic_error(quic_error::invalid_state, "server already started");
        }
        ensure_gnutls_global();
        quic_server_log.info(
          "server start: listen={} crt_file='{}' key_file='{}' alpn_count={}",
          cfg.listen_address,
          cfg.crt_file,
          cfg.key_file,
          cfg.alpns.size());

        _cfg = std::move(cfg);
        int rv = gnutls_certificate_allocate_credentials(&_cred);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        rv = gnutls_certificate_set_x509_key_file(
          _cred, _cfg.crt_file.c_str(), _cfg.key_file.c_str(), GNUTLS_X509_FMT_PEM);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        _channel = engine().net().make_bound_datagram_channel(_cfg.listen_address);
        _channel_ready = true;
        _listen_address = _channel.local_address();
        _started = true;
        _stopping = false;
        quic_server_log.info("server listening on {}", _listen_address);

        (void)with_gate(_task_gate, [this] { return receive_loop(); })
          .handle_exception([this](std::exception_ptr) {
              if (!_stopping) {
                  quic_server_log.error("server receive loop failed");
                  _stopping = true;
                  _accept_cv.signal();
              }
          })
          .or_terminate();
        co_return;
    }

    future<internal::session_runtime_ptr> accept() {
        if (!_started) {
            throw_quic_error(quic_error::invalid_state, "server is not started");
        }
        quic_server_log.debug("server accept wait: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());

        while (_accepted.empty()) {
            if (_stopping) {
                throw_quic_error(quic_error::closed, "server stopped");
            }
            co_await _accept_cv.wait();
        }

        auto runtime = std::move(_accepted.front());
        _accepted.pop_front();
        quic_server_log.info("server accept ready: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());
        co_return runtime;
    }

    future<> stop() {
        if (!_started) {
            quic_server_log.debug("server stop ignored: not started");
            co_return;
        }

        quic_server_log.info(
          "server stop start: listen={} active_conns={} pending_accepted={} mapped_dcids={}",
          _listen_address,
          _conns.size(),
          _accepted.size(),
          _by_dcid.size());
        _stopping = true;
        _accept_cv.signal();

        auto conns_copy = _conns;
        for (auto& conn : conns_copy) {
            conn->stop_transport();
        }

        if (_channel_ready && !_channel.is_closed()) {
            _channel.shutdown_input();
        }

        co_await _task_gate.close();

        if (_channel_ready && !_channel.is_closed()) {
            _channel.shutdown_output();
            _channel.close();
        }

        _conns.clear();
        _by_dcid.clear();
        _accepted.clear();
        if (_cred) {
            gnutls_certificate_free_credentials(_cred);
            _cred = nullptr;
        }

        _started = false;
        _stopping = false;
        _channel_ready = false;
        quic_server_log.info("server stop complete");
    }

    bool stopping() const noexcept {
        return _stopping;
    }

    net::datagram_channel& channel() {
        return _channel;
    }

    void map_dcid(const conn_ptr& conn, const uint8_t* cid, size_t len) {
        auto key = cid_key(cid, len);
        _by_dcid[key] = conn;
        conn->mapped_dcids.insert(std::move(key));
        quic_server_log.debug("server map DCID: len={} total_mapped={} conn_mapped={}", len, _by_dcid.size(), conn->mapped_dcids.size());
    }

    void unmap_dcid(const conn_ptr& conn, const uint8_t* cid, size_t len) {
        auto key = cid_key(cid, len);
        auto it = _by_dcid.find(key);
        if (it != _by_dcid.end() && it->second == conn) {
            _by_dcid.erase(it);
        }
        conn->mapped_dcids.erase(key);
        quic_server_log.debug("server unmap DCID: len={} total_mapped={} conn_mapped={}", len, _by_dcid.size(), conn->mapped_dcids.size());
    }

    void unregister_connection(const conn_ptr& conn) {
        if (!conn || conn->unregistered) {
            return;
        }
        conn->unregistered = true;
        quic_server_log.info("server unregister connection: peer={} mapped_dcids={} active_conns_before={}", conn->peer, conn->mapped_dcids.size(), _conns.size());
        for (const auto& key : conn->mapped_dcids) {
            auto it = _by_dcid.find(key);
            if (it != _by_dcid.end() && it->second == conn) {
                _by_dcid.erase(it);
            }
        }
        conn->mapped_dcids.clear();

        _conns.erase(std::remove(_conns.begin(), _conns.end(), conn), _conns.end());
        quic_server_log.info("server connection unregistered: active_conns={} mapped_dcids={}", _conns.size(), _by_dcid.size());
    }

    void enqueue_accepted_session(const internal::session_runtime_ptr& runtime) {
        _accepted.push_back(runtime);
        quic_server_log.debug("server queued accepted session: pending_accepted={}", _accepted.size());
        _accept_cv.signal();
    }

    gnutls_certificate_credentials_t credentials() const {
        return _cred;
    }

    const quic_server_config& config() const {
        return _cfg;
    }

    const socket_address& listen_address() const {
        return _listen_address;
    }

private:
    friend struct server_connection;

    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<ngtcp2_conn*>(ref->user_data);
    }

    static void rand_cb(uint8_t* dest, size_t len, const ngtcp2_rand_ctx*) {
        rand_bytes(dest, len);
    }

    static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void*) {
        cid->datalen = cidlen;
        rand_bytes(cid->data, cidlen);
        rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
        return 0;
    }

    static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
        rand_bytes(data, 8);
        return 0;
    }

    static int handshake_completed_cb(ngtcp2_conn*, void*) {
        quic_server_log.info("server handshake completed");
        return 0;
    }

    static int dcid_status_cb(ngtcp2_conn*, ngtcp2_connection_id_status_type type, uint64_t, const ngtcp2_cid* cid, const uint8_t*, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->server || !cid) {
            return 0;
        }
        auto self = conn->shared_from_this();
        if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE) {
            quic_server_log.debug("server dcid activate: peer={} len={}", conn->peer, cid->datalen);
            conn->server->map_dcid(self, cid->data, cid->datalen);
        } else if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE) {
            quic_server_log.debug("server dcid deactivate: peer={} len={}", conn->peer, cid->datalen);
            conn->server->unmap_dcid(self, cid->data, cid->datalen);
        }
        return 0;
    }

    static int recv_stream_data_cb(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, const uint8_t* data, size_t datalen, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->runtime || !conn->runtime->is_open()) {
            quic_server_log.trace("server drop recv_stream_data: sid={} bytes={} conn_valid={} runtime_open={}",
              sid, datalen, conn != nullptr, conn && conn->runtime && conn->runtime->is_open());
            return 0;
        }
        quic_server_log.trace("server recv_stream_data: peer={} sid={} bytes={}", conn->peer, sid, datalen);
        conn->runtime->mark_ready(sid);
        temporary_buffer<char> tb(datalen);
        if (datalen) {
            std::memcpy(tb.get_write(), data, datalen);
        }
        conn->runtime->push_incoming(quic_message(sid, std::move(tb), false));
        return 0;
    }

    gnutls_session_t make_tls_session(server_connection& conn) const {
        gnutls_session_t tls = nullptr;
        int rv = gnutls_init(&tls, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
        rv = gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, _cred);
        if (rv < 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
        rv = gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr);
        if (rv < 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        std::vector<gnutls_datum_t> alpns;
        alpns.reserve(_cfg.alpns.size());
        for (const auto& alpn : _cfg.alpns) {
            alpns.push_back(gnutls_datum_t{
              reinterpret_cast<unsigned char*>(const_cast<char*>(alpn.data())),
              static_cast<unsigned int>(alpn.size()),
            });
        }
        if (!alpns.empty()) {
            rv = gnutls_alpn_set_protocols(tls, alpns.data(), alpns.size(), 0);
            if (rv < 0) {
                gnutls_deinit(tls);
                throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
            }
        }

        rv = ngtcp2_crypto_gnutls_configure_server_session(tls);
        if (rv != 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        }

        conn.conn_ref.get_conn = get_conn;
        conn.conn_ref.user_data = nullptr;
        gnutls_session_set_ptr(tls, &conn.conn_ref);
        return tls;
    }

    conn_ptr init_connection(const socket_address& peer, const uint8_t* pkt, size_t pkt_len) {
        quic_server_log.info("server init_connection: peer={} first_packet_bytes={}", peer, pkt_len);
        auto conn = make_lw_shared<server_connection>();
        conn->server = this;
        conn->runtime = internal::make_session_runtime(_cfg.session_options);
        conn->peer = peer;
        to_sockaddr_storage_v6(_listen_address, conn->local_ss, conn->local_ss_len);
        to_sockaddr_storage_v6(peer, conn->peer_ss, conn->peer_ss_len);
        conn->tls = make_tls_session(*conn);

        ngtcp2_version_cid vc{};
        int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pkt_len, NGTCP2_MAX_CIDLEN);
        if (rv < 0) {
            throw_quic_error(quic_error::protocol, "failed to decode Initial CID");
        }

        ngtcp2_cid dcid{};
        dcid.datalen = vc.scidlen;
        std::memcpy(dcid.data, vc.scid, vc.scidlen);

        ngtcp2_cid odcid{};
        odcid.datalen = vc.dcidlen;
        std::memcpy(odcid.data, vc.dcid, vc.dcidlen);

        ngtcp2_cid scid{};
        scid.datalen = server_short_cid_len;
        rand_bytes(scid.data, scid.datalen);

        ngtcp2_callbacks callbacks{};
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.rand = rand_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.get_path_challenge_data = get_path_challenge_data_cb;
        callbacks.handshake_completed = handshake_completed_cb;
        callbacks.dcid_status = dcid_status_cb;
        callbacks.recv_stream_data = recv_stream_data_cb;

        ngtcp2_settings settings{};
        ngtcp2_settings_default(&settings);
        settings.initial_ts = now_ns();

        ngtcp2_transport_params params{};
        ngtcp2_transport_params_default(&params);
        params.original_dcid_present = 1;
        params.original_dcid = odcid;
        params.initial_max_stream_data_bidi_local =
          _cfg.session_options.transport.initial_max_stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote =
          _cfg.session_options.transport.initial_max_stream_data_bidi_remote;
        params.initial_max_data = _cfg.session_options.transport.initial_max_data;
        params.initial_max_streams_bidi = _cfg.session_options.transport.initial_max_streams_bidi;
        params.max_idle_timeout = _cfg.session_options.transport.max_idle_timeout_ns;

        ngtcp2_path path{};
        conn->fill_path(path);
        rv = ngtcp2_conn_server_new(
          &conn->conn,
          &dcid,
          &scid,
          &path,
          NGTCP2_PROTO_VER_V1,
          &callbacks,
          &settings,
          &params,
          ngtcp2_mem_for_thread(),
          conn.get());
        if (rv != 0) {
            throw_quic_error(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        }

        ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls);
        conn->conn_ref.user_data = conn->conn;

        auto payload = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn->conn);
        if (payload == 0) {
            payload = default_udp_payload_size;
        }
        if (payload > max_udp_payload_size) {
            payload = max_udp_payload_size;
        }
        conn->tx_payload_limit = payload;

        map_dcid(conn, odcid.data, odcid.datalen);
        map_dcid(conn, scid.data, scid.datalen);
        _conns.push_back(conn);
        enqueue_accepted_session(conn->runtime);
        quic_server_log.info(
          "server connection initialized: peer={} tx_payload_limit={} active_conns={} odcid_len={} scid_len={}",
          conn->peer,
          conn->tx_payload_limit,
          _conns.size(),
          odcid.datalen,
          scid.datalen);

        (void)with_gate(_task_gate, [conn] { return conn_actor_loop(conn); })
          .handle_exception([conn](std::exception_ptr) {
              conn->closing = true;
              conn->abort_event_queues("server actor loop failed");
              if (conn->runtime && conn->runtime->is_open()) {
                  conn->runtime->mark_error(quic_error::io, "server actor loop failed");
              }
              if (conn->server) {
                  conn->server->unregister_connection(conn);
              }
          })
          .or_terminate();
        (void)with_gate(_task_gate, [conn] { return conn_tx_loop(conn); })
          .handle_exception([conn](std::exception_ptr) {
              conn->fail(quic_error::io, "server tx loop failed");
          })
          .or_terminate();
        (void)with_gate(_task_gate, [conn] { return conn_timer_loop(conn); })
          .handle_exception([conn](std::exception_ptr) {
              conn->fail(quic_error::io, "server timer loop failed");
          })
          .or_terminate();

        return conn;
    }

    static future<> flush_pending_packets_actor(conn_ptr conn) {
        if (!conn->conn || !conn->server) {
            co_return;
        }
        std::vector<uint8_t> outbuf(conn->tx_payload_limit);
        while (conn->active()) {
            ngtcp2_path path{};
            conn->fill_path(path);
            ngtcp2_pkt_info pkt_info{};

            ngtcp2_ssize nwrite =
              ngtcp2_conn_write_pkt(conn->conn, &path, &pkt_info, outbuf.data(), outbuf.size(), now_ns());
            if (nwrite == 0) {
                quic_server_log.trace("server flush_pending_packets: no packet produced peer={}", conn->peer);
                co_return;
            }
            if (nwrite < 0) {
                if (ngtcp2_is_write_more(nwrite)) {
                    quic_server_log.trace("server flush_pending_packets: write_more peer={}", conn->peer);
                    continue;
                }
                if (ngtcp2_is_draining(nwrite)) {
                    quic_server_log.info("server flush_pending_packets: draining peer={}", conn->peer);
                    conn->stop_transport();
                    co_return;
                }
                quic_server_log.warn("server flush_pending_packets failed: peer={} nwrite={} msg={}",
                  conn->peer, nwrite, ngtcp2_error_message((int)nwrite));
                conn->fail(classify_ngtcp2_error(nwrite), ngtcp2_error_message((int)nwrite));
                co_return;
            }
            quic_server_log.trace("server flush_pending_packets: peer={} wrote {} bytes", conn->peer, nwrite);
            co_await send_datagram(conn->server->channel(), conn->peer, outbuf.data(), static_cast<size_t>(nwrite));
        }
    }

    static future<> send_stream_message_actor(conn_ptr conn, quic_message msg) {
        if (!conn->conn || msg.stream == invalid_stream_id) {
            quic_server_log.debug("server send_stream_message skipped: peer={} conn_present={} sid={}",
              conn->peer, conn->conn != nullptr, msg.stream);
            co_return;
        }
        quic_server_log.debug("server send_stream_message start: peer={} sid={} bytes={} fin={}",
          conn->peer, msg.stream, msg.payload.size(), msg.fin);

        size_t offset = 0;
        bool send_fin = msg.fin;
        std::vector<uint8_t> outbuf(conn->tx_payload_limit);

        while (conn->active()) {
            const bool remaining = offset < msg.payload.size();
            if (!remaining && !send_fin) {
                break;
            }

            ngtcp2_path path{};
            conn->fill_path(path);
            ngtcp2_pkt_info pkt_info{};
            ngtcp2_vec vec{};
            ngtcp2_ssize consumed = 0;

            const uint8_t* ptr = remaining ? reinterpret_cast<const uint8_t*>(msg.payload.get() + offset) : nullptr;
            const size_t len = remaining ? (msg.payload.size() - offset) : 0;
            if (remaining) {
                vec.base = const_cast<uint8_t*>(ptr);
                vec.len = len;
            }

            uint32_t flags = (!remaining && send_fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
            ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
              conn->conn,
              &path,
              &pkt_info,
              outbuf.data(),
              outbuf.size(),
              &consumed,
              flags,
              msg.stream,
              remaining ? &vec : nullptr,
              remaining ? 1 : 0,
              now_ns());

            if (nwrite < 0) {
                if (ngtcp2_is_write_more(nwrite)) {
                    if (consumed > 0) {
                        offset += static_cast<size_t>(consumed);
                    }
                    quic_server_log.trace("server writev_stream: write_more peer={} sid={} consumed={} offset={}",
                      conn->peer, msg.stream, consumed, offset);
                    co_await flush_pending_packets_actor(conn);
                    continue;
                }
                if (ngtcp2_is_draining(nwrite)) {
                    quic_server_log.info("server writev_stream: draining peer={} sid={}", conn->peer, msg.stream);
                    conn->stop_transport();
                    co_return;
                }
                quic_server_log.warn("server writev_stream failed: peer={} sid={} nwrite={} msg={}",
                  conn->peer, msg.stream, nwrite, ngtcp2_error_message((int)nwrite));
                conn->fail(classify_ngtcp2_error(nwrite), ngtcp2_error_message((int)nwrite));
                co_return;
            }
            if (nwrite == 0) {
                quic_server_log.trace("server writev_stream produced 0 bytes: peer={} sid={}", conn->peer, msg.stream);
                co_await flush_pending_packets_actor(conn);
                continue;
            }

            if (consumed > 0) {
                offset += static_cast<size_t>(consumed);
            }
            if (!remaining && send_fin) {
                send_fin = false;
            }
            quic_server_log.trace(
              "server writev_stream sent packet: peer={} sid={} packet_bytes={} consumed={} offset={} total={} fin_pending={}",
              conn->peer,
              msg.stream,
              nwrite,
              consumed,
              offset,
              msg.payload.size(),
              send_fin);
            co_await send_datagram(conn->server->channel(), conn->peer, outbuf.data(), static_cast<size_t>(nwrite));

            if (offset >= msg.payload.size() && !send_fin) {
                break;
            }
        }

        co_await flush_pending_packets_actor(conn);
        quic_server_log.debug("server send_stream_message done: peer={} sid={} bytes={} fin={}",
          conn->peer, msg.stream, msg.payload.size(), msg.fin);
    }

    static future<> conn_tx_send_actor(conn_ptr conn, quic_message msg) {
        if (!conn->active()) {
            co_return;
        }
        co_await send_stream_message_actor(conn, std::move(msg));
        conn->request_timer_rearm();
    }

    static future<> conn_handle_timer_actor(conn_ptr conn) {
        if (!conn->active() || !conn->conn) {
            co_return;
        }
        auto now_local = now_ns();
        if (ngtcp2_conn_get_expiry(conn->conn) <= now_local) {
            int rv = ngtcp2_conn_handle_expiry(conn->conn, now_local);
            if (rv < 0) {
                if (ngtcp2_is_idle_close(rv) || ngtcp2_is_draining(rv)) {
                    quic_server_log.info("server timer expiry: closing/draining peer={} rv={}", conn->peer, rv);
                    conn->stop_transport();
                    co_return;
                }
                quic_server_log.warn("server timer expiry handling failed: peer={} rv={} msg={}",
                  conn->peer, rv, ngtcp2_error_message(rv));
                conn->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
                co_return;
            }
        }
        co_await flush_pending_packets_actor(conn);
    }

    static future<> handle_conn_datagram_actor(conn_ptr conn, temporary_buffer<char> pkt) {
        if (!conn->active() || !conn->conn) {
            co_return;
        }
        quic_server_log.trace("server handle_conn_datagram_actor: peer={} bytes={}", conn->peer, pkt.size());

        ngtcp2_path path{};
        conn->fill_path(path);
        ngtcp2_pkt_info pkt_info{};

        int rv = ngtcp2_conn_read_pkt(
          conn->conn, &path, &pkt_info, reinterpret_cast<const uint8_t*>(pkt.get()), pkt.size(), now_ns());
        if (rv < 0) {
            if (ngtcp2_is_draining(rv)) {
                quic_server_log.info("server read_pkt draining: peer={}", conn->peer);
                conn->stop_transport();
                co_return;
            }
            quic_server_log.warn("server read_pkt failed: peer={} rv={} msg={}",
              conn->peer, rv, ngtcp2_error_message(rv));
            conn->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
            co_return;
        }

        co_await flush_pending_packets_actor(conn);
        conn->request_timer_rearm();
    }

    static future<> conn_tx_loop(conn_ptr conn) {
        while (conn->active()) {
            quic_message msg;
            try {
                msg = co_await conn->runtime->pop_outgoing();
            } catch (const quic_exception& e) {
                if (e.code() == quic_error::closed) {
                    quic_server_log.debug("server conn_tx_loop exiting on closed runtime: peer={}", conn->peer);
                    co_return;
                }
                quic_server_log.warn("server conn_tx_loop pop_outgoing error: peer={} code={} detail='{}'",
                  conn->peer, to_string(e.code()), e.what());
                conn->fail(e.code(), e.what());
                co_return;
            } catch (...) {
                quic_server_log.error("server conn_tx_loop unexpected pop_outgoing failure: peer={}", conn->peer);
                conn->fail(quic_error::internal, "server pop_outgoing failed");
                co_return;
            }
            quic_server_log.trace("server conn_tx_loop popped message: peer={} sid={} bytes={} fin={}",
              conn->peer, msg.stream, msg.payload.size(), msg.fin);

            try {
                auto out = std::make_unique<quic_message>(std::move(msg));
                co_await conn->tx_queue.push_eventually(std::move(out));
                conn->wake_actor();
            } catch (...) {
                if (!conn->active()) {
                    co_return;
                }
                conn->fail(quic_error::io, "server tx queue push failed");
                co_return;
            }
        }
    }

    static future<> send_connection_close_actor(conn_ptr conn) {
        if (!conn->conn || !conn->server) {
            co_return;
        }

        auto& server = *conn->server;
        auto& channel = server.channel();
        if (channel.is_closed()) {
            co_return;
        }

        ngtcp2_path path{};
        conn->fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        std::vector<uint8_t> outbuf(conn->tx_payload_limit);

        ngtcp2_ccerr ccerr{};
        ngtcp2_ccerr_default(&ccerr);
        ngtcp2_ccerr_set_application_error(&ccerr, 0, nullptr, 0);

        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
          conn->conn, &path, &pkt_info, outbuf.data(), outbuf.size(), &ccerr, now_ns());
        if (nwrite == 0) {
            quic_server_log.debug("server stop: no CONNECTION_CLOSE packet produced peer={}", conn->peer);
            co_return;
        }
        if (nwrite < 0) {
            quic_server_log.warn(
              "server stop: failed to write CONNECTION_CLOSE peer={} nwrite={} msg={}",
              conn->peer,
              nwrite,
              ngtcp2_error_message((int)nwrite));
            co_return;
        }

        quic_server_log.info("server sent CONNECTION_CLOSE packet: peer={} bytes={}", conn->peer, nwrite);
        co_await send_datagram(channel, conn->peer, outbuf.data(), static_cast<size_t>(nwrite));
    }

    static future<> conn_timer_loop(conn_ptr conn) {
        constexpr auto max_timer_sleep = std::chrono::hours(24);
        while (conn->active()) {
            if (!conn->conn) {
                co_return;
            }

            auto expiry = ngtcp2_conn_get_expiry(conn->conn);
            auto now = now_ns();
            if (expiry <= now) {
                conn->signal_tick();
                try {
                    co_await conn->timer_cv.wait([conn] {
                        return !conn->active() || conn->stop_requested || conn->timer_rearm_requested || !conn->tick_pending;
                    });
                } catch (...) {
                }
                conn->timer_rearm_requested = false;
                continue;
            }

            auto wait_ns = expiry - now;
            auto max_wait_ns = static_cast<uint64_t>(
              std::chrono::duration_cast<std::chrono::nanoseconds>(max_timer_sleep).count());
            auto sleep_ns = std::min(wait_ns, max_wait_ns);
            conn->timer_rearm_requested = false;

            try {
                co_await conn->timer_cv.wait(std::chrono::nanoseconds(sleep_ns), [conn] {
                    return !conn->active() || conn->stop_requested || conn->timer_rearm_requested;
                });
                conn->timer_rearm_requested = false;
            } catch (const condition_variable_timed_out&) {
                if (!conn->active()) {
                    co_return;
                }
                conn->signal_tick();
            } catch (...) {
                if (!conn->active()) {
                    co_return;
                }
            }
        }
    }

    static future<> conn_actor_loop(conn_ptr conn) {
        while (conn->active()) {
            if (!conn->has_pending_actor_work()) {
                co_await conn->wait_for_actor_wakeup();
                if (!conn->active()) {
                    co_return;
                }
            }

            if (conn->stop_requested) {
                auto stop_error = conn->stop_error;
                auto stop_error_detail = conn->stop_error_detail;
                conn->stop_requested = false;

                co_await send_connection_close_actor(conn);

                conn->closing = true;
                conn->abort_event_queues(stop_error ? "server connection failed" : "server connection stopped");
                if (conn->runtime && conn->runtime->is_open()) {
                    if (stop_error) {
                        conn->runtime->mark_error(*stop_error, stop_error_detail);
                    } else {
                        conn->runtime->mark_transport_closed();
                    }
                }

                if (conn->server) {
                    conn->server->unregister_connection(conn);
                }
                co_return;
            }

            while (conn->active() && !conn->stop_requested && !conn->rx_queue.empty()) {
                auto evt = conn->rx_queue.pop();
                if (!evt) {
                    continue;
                }
                co_await handle_conn_datagram_actor(conn, std::move(evt->packet));
            }

            while (conn->active() && !conn->stop_requested && !conn->tx_queue.empty()) {
                auto out = conn->tx_queue.pop();
                if (!out) {
                    continue;
                }
                co_await conn_tx_send_actor(conn, std::move(*out));
            }

            if (conn->active() && !conn->stop_requested && conn->tick_pending) {
                conn->tick_pending = false;
                co_await conn_handle_timer_actor(conn);
            }
        }
    }

    future<> handle_datagram(net::datagram d) {
        auto src = d.get_src();
        auto pkt = linearize_packet(d.get_buffers());
        const auto* data = reinterpret_cast<const uint8_t*>(pkt.get());
        const size_t len = pkt.size();
        quic_server_log.trace("server received datagram: src={} bytes={}", src, len);

        auto parsed = parse_dcid(data, len, server_short_cid_len);
        if (!parsed.ok) {
            quic_server_log.debug("server drop datagram: failed to parse DCID src={} bytes={}", src, len);
            co_return;
        }

        conn_ptr conn;
        auto it = _by_dcid.find(cid_key(parsed.dcid.data(), parsed.dcid_len));
        if (it != _by_dcid.end()) {
            conn = it->second;
        }

        if (!conn) {
            if (!parsed.long_header || parsed.long_type != quic_long_type::initial) {
                quic_server_log.debug("server drop datagram: unknown DCID and not Initial src={} long_header={} long_type={}",
                  src, parsed.long_header, static_cast<unsigned>(parsed.long_type));
                co_return;
            }
            try {
                conn = init_connection(src, data, len);
            } catch (...) {
                quic_server_log.warn("server failed to initialize connection from Initial packet: src={} bytes={}", src, len);
                co_return;
            }
        }

        if (!conn || conn->closing) {
            quic_server_log.debug("server drop datagram: conn missing/closing src={}", src);
            co_return;
        }

        if (conn->peer != src) {
            quic_server_log.info("server peer address updated: old={} new={}", conn->peer, src);
            conn->peer = src;
            to_sockaddr_storage_v6(src, conn->peer_ss, conn->peer_ss_len);
        }

        try {
            auto evt = std::make_unique<conn_rx_event>(conn_rx_event{src, std::move(pkt)});
            co_await conn->rx_queue.push_eventually(std::move(evt));
            conn->wake_actor();
        } catch (...) {
            if (!conn->active()) {
                co_return;
            }
            conn->fail(quic_error::io, "server rx queue push failed");
        }
    }

    future<> receive_loop() {
        while (!_stopping) {
            try {
                auto d = co_await _channel.receive();
                co_await handle_datagram(std::move(d));
            } catch (...) {
                if (_stopping) {
                    co_return;
                }
                quic_server_log.error("server receive_loop channel receive failed");
            }
        }
    }

    quic_server_config _cfg{};
    gnutls_certificate_credentials_t _cred = nullptr;
    net::datagram_channel _channel{};
    bool _channel_ready = false;
    socket_address _listen_address{};

    bool _started = false;
    bool _stopping = false;

    gate _task_gate;
    condition_variable _accept_cv;
    std::deque<internal::session_runtime_ptr> _accepted;
    std::unordered_map<std::string, conn_ptr> _by_dcid;
    std::vector<conn_ptr> _conns;
};

bool server_connection::active() const noexcept {
    return !closing && runtime && runtime->is_open() && server;
}

void server_connection::stop_transport() {
    quic_server_log.info("server connection request stop: peer={} closing={} mapped_dcids={}", peer, closing, mapped_dcids.size());
    if (closing || stop_requested) {
        return;
    }
    stop_requested = true;
    wake_actor();
    request_timer_rearm();
}

void server_connection::fail(quic_error error, const sstring& detail) {
    quic_server_log.error(
      "server connection failure: peer={} error={} detail='{}' closing={} mapped_dcids={}",
      peer,
      to_string(error),
      detail,
      closing,
      mapped_dcids.size());
    if (closing) {
        return;
    }
    if (!stop_error) {
        stop_error = error;
        stop_error_detail = detail;
    }
    stop_requested = true;
    wake_actor();
    request_timer_rearm();
}

} // namespace

class quic_server::impl final : public quic_server_impl {
};

quic_server::quic_server()
    : _impl(std::make_unique<impl>()) {
}

quic_server::~quic_server() = default;
quic_server::quic_server(quic_server&&) noexcept = default;
quic_server& quic_server::operator=(quic_server&&) noexcept = default;

future<> quic_server::start(quic_server_config config) {
    quic_server_log.debug("quic_server::start");
    co_await _impl->start(std::move(config));
}

future<connection> quic_server::accept() {
    quic_server_log.debug("quic_server::accept");
    auto runtime = co_await _impl->accept();
    co_return connection(std::move(runtime));
}

future<> quic_server::stop() {
    quic_server_log.debug("quic_server::stop");
    co_await _impl->stop();
}

} // namespace seastar::quic::experimental
