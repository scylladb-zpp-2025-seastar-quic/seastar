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
#include <seastar/core/reactor.hh>
#include <seastar/core/coroutine.hh>
#include <arpa/inet.h>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <seastar/quic/quic_client.hh>

namespace seastar::quic::experimental::client {

client_crypto_config::client_crypto_config(const std::vector<std::string>& alpns) {
    int grv = gnutls_certificate_allocate_credentials(&_cred);
    if (grv < 0) throw std::runtime_error("gnutls cert alloc failed");
    _alpns = alpns;
}

client_crypto_config::~client_crypto_config() {
    if (_cred) gnutls_certificate_free_credentials(_cred);
}

void client_crypto_config::add_alpn(const std::string& protocol) {
    _alpns.push_back(protocol);
}

gnutls_session_t client_crypto_config::make_session(const std::string& sni_hostname, ngtcp2_crypto_conn_ref* ref) {
    gnutls_session_t tls;
    int grv = gnutls_init(&tls, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA);
    if (grv < 0) throw std::runtime_error("gnutls_init failed");

    gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, _cred);
    gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr);

    std::vector<gnutls_datum_t> gnutls_alpns;
    for (const auto& a : _alpns) {
        gnutls_alpns.push_back({(unsigned char*)a.data(), (unsigned int)a.size()});
    }
    gnutls_alpn_set_protocols(tls, gnutls_alpns.data(), gnutls_alpns.size(), 0);

    if (!sni_hostname.empty()) {
        gnutls_server_name_set(tls, GNUTLS_NAME_DNS, sni_hostname.c_str(), sni_hostname.size());
    }

    ngtcp2_crypto_gnutls_configure_client_session(tls);

    ref->get_conn = [](ngtcp2_crypto_conn_ref* r) { return (ngtcp2_conn*)r->user_data; };
    ref->user_data = nullptr; 
    gnutls_session_set_ptr(tls, ref);
    return tls;
}

seastar::future<udp_channel_ptr> setup_quic_client(
    Connection& c, 
    std::string host, std::string ip, uint16_t port, QuicConfig config,
    seastar::lw_shared_ptr<client_crypto_config> crypto) 
{
    c.set_tls(crypto->make_session(host, c.conn_ref_ptr()));

    auto ch = seastar::engine().net().make_bound_datagram_channel(
        seastar::socket_address(seastar::ipv6_addr{0}));
    auto sock = seastar::make_lw_shared<udp_channel>(std::move(ch));

    sockaddr_in6 r{};
    r.sin6_family = AF_INET6;
    r.sin6_port = htons(port);
    inet_pton(AF_INET6, ip.c_str(), &r.sin6_addr);
    seastar::socket_address remote{r};

    c.set_peer(remote);
    c.set_remote_addr(remote);
    c.set_local_addr(sock->local_address());

    c.init_client(config, &c);
    co_await c.flush_pending(sock, remote);

    co_return sock;
}

session::session(seastar::lw_shared_ptr<Connection> connection, udp_channel_ptr channel)
    : _connection(std::move(connection))
    , _channel(std::move(channel)) {}

Connection& session::connection() {
    if (!_connection) {
        throw std::runtime_error("client session has no connection");
    }
    return *_connection;
}

const Connection& session::connection() const {
    if (!_connection) {
        throw std::runtime_error("client session has no connection");
    }
    return *_connection;
}

udp_channel_ptr session::channel() const {
    return _channel;
}

seastar::future<> session::send(std::string_view data) {
    if (!_connection || !_channel || data.empty()) {
        co_return;
    }

    if (_stream_id < 0) {
        int64_t sid = -1;
        int rv = _connection->open_bidi_stream(sid);
        if (rv != 0) {
            throw std::runtime_error("open_bidi_stream failed: " + std::string(ngtcp2_strerror(rv)));
        }
        _stream_id = sid;
    }

    co_await _connection->send(_stream_id, data, _channel, _connection->peer());
}

seastar::future<int> session::receive_once() {
    if (!_connection || !_channel) {
        co_return NGTCP2_ERR_INTERNAL;
    }

    auto d = co_await _channel->recv_datagram();
    auto tb = datagram_to_temporary_buffer(d);
    co_return co_await _connection->handle_packet(
            reinterpret_cast<const uint8_t*>(tb.get()), tb.size(), _channel);
}

seastar::future<> session::close() {
    if (!_channel) {
        co_return;
    }

    if (_connection && _connection->conn()) {
        std::vector<uint8_t> outbuf(_connection->max_tx_udp_payload_size());
        ssize_t nwrite = _connection->write_connection_close(outbuf.data(), outbuf.size());
        if (nwrite > 0) {
            auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
            std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
            co_await _channel->send_to(_connection->peer(), std::move(tb));
        }
        _connection->reschedule();
    }

    _channel->close();
}

seastar::future<seastar::lw_shared_ptr<session>> connect(connect_options options) {
    if (options.alpns.empty()) {
        options.alpns.push_back("h3");
    }

    auto connection = seastar::make_lw_shared<Connection>();
    auto crypto = seastar::make_lw_shared<client_crypto_config>(options.alpns);

    auto sock = co_await setup_quic_client(
            *connection,
            std::move(options.host),
            std::move(options.ip),
            options.port,
            std::move(options.config),
            std::move(crypto));

    co_return seastar::make_lw_shared<session>(std::move(connection), std::move(sock));
}

using client_crypto_config_ptr = seastar::lw_shared_ptr<client::client_crypto_config>;

} // namespace seastar::quic::experimental
