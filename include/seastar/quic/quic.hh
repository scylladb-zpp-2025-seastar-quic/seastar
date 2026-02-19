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

#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/api.hh>
#include <seastar/core/condition-variable.hh>
#include <cstdint>
#include <chrono>
#include <optional>
#include <functional>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>


namespace seastar::quic::experimental {

    ngtcp2_tstamp now_ns();

    void rand_bytes(uint8_t* dst, size_t len);

// Helper functions are hidden in internal namespace.
namespace internal {
    inline constexpr size_t default_udp_payload = 1200;
    inline constexpr size_t max_udp_payload = 65527;

    void sa_to_storage_v6(const seastar::socket_address& sa, sockaddr_storage& out, socklen_t& outlen);

    struct connection_config {
        uint64_t max_idle_timeout_ns = 60ULL * 1000 * 1000 * 1000;

        uint64_t initial_max_stream_data_bidi_local  = 256 * 1024;
        uint64_t initial_max_stream_data_bidi_remote = 256 * 1024;
        uint64_t initial_max_data = 4 * 1024 * 1024;

        uint64_t initial_max_streams_bidi = 128;
    };

    inline void* seastar_malloc(size_t size, void*) { return std::malloc(size); }
    inline void  seastar_free(void* ptr, void*)     { std::free(ptr); }
    inline void* seastar_calloc(size_t n, size_t s, void*) { return std::calloc(n, s); }
    inline void* seastar_realloc(void* p, size_t s, void*) { return std::realloc(p, s); }
    
    const ngtcp2_mem* get_ngtcp2_allocator();

    inline void init_ngtcp2_addr(ngtcp2_addr* addr, const sockaddr* sa, size_t len) {
        addr->addr    = const_cast<sockaddr*>(sa);
        addr->addrlen = (socklen_t)len;
    }

    void fill_transport_params(ngtcp2_transport_params& params, const connection_config& config);

    ngtcp2_callbacks get_default_callbacks();

    ngtcp2_settings get_default_settings();

    size_t max_tx_udp_payload(ngtcp2_conn* conn);
} // namespace internal

// Class used to set configuration of ngtcp2 - settings, transfer parameters and callbacks.
class QuicConfig {
public:
    using SettingsConfigurator = std::function<void(ngtcp2_settings&)>;
    using ParamsConfigurator = std::function<void(ngtcp2_transport_params&)>;
    using CallbacksConfigurator = std::function<void(ngtcp2_callbacks&)>;

    QuicConfig();

    // Possible to use lambdas to set settings, params or callbacks.
    QuicConfig& withSettings(SettingsConfigurator func);

    QuicConfig& withTransportParams(ParamsConfigurator func);

    QuicConfig& withCallbacks(CallbacksConfigurator func);

    QuicConfig& withOriginalDcid(const uint8_t* data, size_t len);

    // Getters.
    const ngtcp2_settings* getSettingsPtr() const { return &settings_; }
    const ngtcp2_transport_params* getTransportParamsPtr() const { return &params_; }
    const ngtcp2_callbacks* getCallbacksPtr() const { return &callbacks_; }

    const ngtcp2_settings& getSettings() const { return settings_; }
    const ngtcp2_transport_params& getTransportParams() const { return params_; }
    const ngtcp2_callbacks& getCallbacks() const { return callbacks_; }
private:
    ngtcp2_settings settings_;
    ngtcp2_transport_params params_;
    ngtcp2_callbacks callbacks_;
};

class udp_channel {
public:
    explicit udp_channel(seastar::net::datagram_channel ch);

    seastar::future<> send_to(const seastar::socket_address& to, seastar::net::packet p);
    seastar::future<> send_to(const seastar::socket_address& to, seastar::temporary_buffer<char> tb);
    
    seastar::future<seastar::net::datagram> recv_datagram();
    
    void close();
    
    seastar::socket_address local_address() const;

private:
    seastar::net::datagram_channel _ch;
};

using udp_channel_ptr = seastar::lw_shared_ptr<udp_channel>;

seastar::temporary_buffer<char> datagram_to_temporary_buffer(seastar::net::datagram& d);

// Class used to represent connection id.
class quic_cid {
public:
    quic_cid();

    explicit quic_cid(const ngtcp2_cid& other) : _cid(other) {}

    quic_cid(const uint8_t* data, size_t len);

    const ngtcp2_cid* get() const { return &_cid; }

    const uint8_t* data() const { return _cid.data; }
    size_t size() const { return _cid.datalen; }
    bool empty() const { return _cid.datalen == 0; }

    static quic_cid random(size_t len = 8);

    std::string to_string() const;
    // Operators.

    bool operator==(const quic_cid& other) const;

    bool operator!=(const quic_cid& other) const;

    quic_cid& operator=(const quic_cid& other);

    quic_cid& operator=(const ngtcp2_cid& other);

private:
    ngtcp2_cid _cid;
};

struct crypto_context {
    virtual ~crypto_context() = default;
};

// Main class used for connection purposes - sending and receiving data etc.
class Connection {
public:
    using HandshakeHandler = std::function<void(Connection&)>;
    using StreamDataHandler = std::function<void(Connection&, int64_t, std::string_view)>;
    using DcidStatusHandler = std::function<void(Connection&, const quic_cid&, bool)>;

    Connection() = default;

    explicit Connection(const seastar::socket_address& local, const seastar::socket_address& remote);

    ~Connection();
    
    // Getters.
    ngtcp2_conn* conn() const { return _conn; }   
    seastar::socket_address peer() const { return _peer; }
    gnutls_session_t tls() const { return _tls; }
    const ngtcp2_cid* scid_ptr() const { return _scid.get(); }
    const ngtcp2_cid* dcid_ptr() const { return _dcid.get(); }

    ngtcp2_crypto_conn_ref* conn_ref_ptr() { return &_conn_ref; }

    // Setters.
    void set_tls(gnutls_session_t t) { _tls = t; }

    void set_local_addr(const seastar::socket_address& sa);

    void set_remote_addr(const seastar::socket_address& sa);

    void set_peer(seastar::socket_address p);

    void fill_path(ngtcp2_path& p);


    seastar::future<> flush_pending(udp_channel_ptr sock,
                                                const seastar::socket_address& peer);

    seastar::future<> send(int64_t stream_id, std::string_view data, 
                           udp_channel_ptr sock, const seastar::socket_address& peer);

    seastar::future<int> handle_packet(const uint8_t* data, size_t len, 
                                udp_channel_ptr sock);

    // Functions using ngtcp2 functions.

    void init_client(const QuicConfig& config, void* user_data);

    void init_server(const QuicConfig& config, void* user_data);

    int64_t open_bidi_stream(int64_t& stream_id);

    quic_cid parse_initial_packet(const uint8_t* data, size_t len);

    ssize_t write_pending_packet(uint8_t* dest, size_t dest_len);

    ssize_t write_stream_packet(int64_t stream_id,
                                    const uint8_t* data, size_t datalen, 
                                    ssize_t& bytes_consumed, 
                                    uint8_t* dest, size_t dest_len);

    int read_packet(const uint8_t* data, size_t len);

    ssize_t write_connection_close(uint8_t* dest, size_t dest_len);

    ngtcp2_tstamp get_expiry() const;

    int handle_expiry();

    size_t max_tx_udp_payload_size();

    void generate_random_cids(size_t len = 8);

    void generate_scid(size_t len = 8);

    void set_dcid(const quic_cid& cid);
    
    void set_dcid(const uint8_t* data, size_t len);

    void on_handshake_completed(HandshakeHandler handler);

    void on_stream_data(StreamDataHandler handler);

    void on_dcid_status(DcidStatusHandler handler);

    void apply_default_callbacks(QuicConfig& config);

    seastar::condition_variable& timer_cv() { return _timer_cv; }

    void reschedule();

private:
    ngtcp2_conn* _conn = nullptr;
    gnutls_session_t _tls = nullptr;
    ngtcp2_crypto_conn_ref _conn_ref{};

    seastar::socket_address _peer;

    sockaddr_storage _local_ss{};
    socklen_t        _local_ss_len = 0;
    sockaddr_storage _remote_ss{};
    socklen_t        _remote_ss_len = 0;

    HandshakeHandler _on_handshake_completed;
    StreamDataHandler _on_stream_data;
    DcidStatusHandler _on_dcid_status;

    static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void*);
    static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t *data, void*);
    static int handshake_completed_cb(ngtcp2_conn*, void* user_data);
    static int recv_stream_data_cb(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t,
            const uint8_t* data, size_t datalen, void* user_data, void*);
    static int dcid_status_cb(ngtcp2_conn*, ngtcp2_connection_id_status_type type, uint64_t,
            const ngtcp2_cid* cid, const uint8_t*, void* user_data);

    quic_cid _scid{};
    quic_cid _dcid{};

    seastar::condition_variable _timer_cv;
};

class init_gnutls {
public:
    init_gnutls();
    ~init_gnutls();


    init_gnutls(const init_gnutls&) = delete;
    init_gnutls& operator=(const init_gnutls&) = delete;

};

namespace client {

class client_crypto_config : public seastar::quic::experimental::crypto_context {
public:
    explicit client_crypto_config(const std::vector<std::string>& alpns);
    ~client_crypto_config();

    void add_alpn(const std::string& protocol);

    gnutls_session_t make_session(const std::string& sni_hostname, ngtcp2_crypto_conn_ref* ref);

private:
    gnutls_certificate_credentials_t _cred = nullptr;
    std::vector<std::string> _alpns;
};

struct connect_options {
    std::string host = "localhost";
    std::string ip = "::1";
    uint16_t port = 4433;
    std::vector<std::string> alpns = {"h3"};
    QuicConfig config;
};

class session {
public:
    session(seastar::lw_shared_ptr<Connection> connection, udp_channel_ptr channel);

    Connection& connection();
    const Connection& connection() const;

    udp_channel_ptr channel() const;

    seastar::future<> send(std::string_view data);
    seastar::future<int> receive_once();
    seastar::future<> close();

private:
    seastar::lw_shared_ptr<Connection> _connection;
    udp_channel_ptr _channel;
    int64_t _stream_id = -1;
};

seastar::future<udp_channel_ptr> setup_quic_client(
    Connection& c,
    std::string host,
    std::string ip,
    uint16_t port,
    QuicConfig config,
    seastar::lw_shared_ptr<client_crypto_config> crypto);

seastar::future<seastar::lw_shared_ptr<session>> connect(connect_options options);

} // namespace client

using client_crypto_config_ptr = seastar::lw_shared_ptr<client::client_crypto_config>;

namespace server {

class server_crypto_config {
public:
    explicit server_crypto_config(const std::string& cert_file, const std::string& key_file,
            const std::vector<std::string>& alpns);

    ~server_crypto_config();

    void add_alpn(const std::string& protocol);

    gnutls_session_t make_session(ngtcp2_crypto_conn_ref* ref);

private:
    gnutls_certificate_credentials_t _cred = nullptr;
    std::vector<std::string> _alpns;
};

struct listen_options {
    std::string ip = "::1";
    uint16_t port = 4433;
    std::string cert_file;
    std::string key_file;
    std::vector<std::string> alpns = {"h3"};
};

class listener {
public:
    listener(udp_channel_ptr channel, seastar::socket_address local_address,
            seastar::lw_shared_ptr<server_crypto_config> crypto);

    udp_channel_ptr channel() const;
    const seastar::socket_address& local_address() const;
    seastar::lw_shared_ptr<server_crypto_config> crypto() const;

    void stop();

private:
    udp_channel_ptr _channel;
    seastar::socket_address _local_address;
    seastar::lw_shared_ptr<server_crypto_config> _crypto;
};

seastar::future<seastar::lw_shared_ptr<listener>> listen(listen_options options);

} // namespace server

using server_crypto_config_ptr = seastar::lw_shared_ptr<server::server_crypto_config>;

} // namespace seastar::quic::experimental


// Adding hashing for quic_cid - we use it as key in map.
namespace std {
    template<>
    struct hash<seastar::quic::experimental::quic_cid> {
        size_t operator()(const seastar::quic::experimental::quic_cid& k) const {
            size_t h = 14695981039346656037ULL;
            const uint8_t* data = k.data();
            for (size_t i = 0; i < k.size(); ++i) {
                h ^= static_cast<size_t>(data[i]);
                h *= 1099511628211ULL;
            }
            return h;
        }
    };
}

// Adding for logger how to show quic_cid.
template <>
struct fmt::formatter<seastar::quic::experimental::quic_cid> {
    constexpr auto parse(format_parse_context& ctx) { return ctx.begin(); }

    template <typename FormatContext>
    auto format(const seastar::quic::experimental::quic_cid& c, FormatContext& ctx) const {
        return fmt::format_to(ctx.out(), "{}", c.to_string());
    }
};
