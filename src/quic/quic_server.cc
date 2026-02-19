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
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/coroutine.hh>
#include <arpa/inet.h>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <seastar/quic/quic_server.hh>

namespace seastar::quic::experimental::server {

server_crypto_config::server_crypto_config(const std::string& cert_file, const std::string& key_file,
                            const std::vector<std::string>& alpns) {
    int grv = gnutls_certificate_allocate_credentials(&_cred);
    if (grv < 0) throw std::runtime_error("gnutls cert alloc failed");

    grv = gnutls_certificate_set_x509_key_file(_cred, cert_file.c_str(), key_file.c_str(), GNUTLS_X509_FMT_PEM);
    if (grv < 0) throw std::runtime_error("Failed to load cert/key files: " + cert_file + ", " + key_file);

    _alpns = alpns; 
}

server_crypto_config::~server_crypto_config() {
    if (_cred) gnutls_certificate_free_credentials(_cred);
}

void server_crypto_config::add_alpn(const std::string& protocol) {
    _alpns.push_back(protocol);
}

gnutls_session_t server_crypto_config::make_session(ngtcp2_crypto_conn_ref* ref) {
    gnutls_session_t tls;

    int grv = gnutls_init(&tls, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
    if (grv < 0) throw std::runtime_error("gnutls_init failed");

    gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, _cred);

    const char* errpos = nullptr;
    grv = gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", &errpos);
    if (grv < 0) throw std::runtime_error("gnutls priority set failed");

    std::vector<gnutls_datum_t> gnutls_alpns;
    for (const auto& a : _alpns) gnutls_alpns.push_back({(unsigned char*)a.data(), (unsigned int)a.size()});
    gnutls_alpn_set_protocols(tls, gnutls_alpns.data(), gnutls_alpns.size(), 0);

    if (ngtcp2_crypto_gnutls_configure_server_session(tls) != 0) {
        throw std::runtime_error("ngtcp2_crypto_gnutls_configure_server_session failed");
    }

    ref->get_conn = [](ngtcp2_crypto_conn_ref* r) { return (ngtcp2_conn*)r->user_data; };
    ref->user_data = nullptr; 
    gnutls_session_set_ptr(tls, ref);

    return tls;
}

listener::listener(udp_channel_ptr channel, seastar::socket_address local_address,
        seastar::lw_shared_ptr<server_crypto_config> crypto)
    : _channel(std::move(channel))
    , _local_address(local_address)
    , _crypto(std::move(crypto)) {}

udp_channel_ptr listener::channel() const {
    return _channel;
}

const seastar::socket_address& listener::local_address() const {
    return _local_address;
}

seastar::lw_shared_ptr<server_crypto_config> listener::crypto() const {
    return _crypto;
}

void listener::stop() {
    if (_channel) {
        _channel->close();
    }
}

seastar::future<seastar::lw_shared_ptr<listener>> listen(listen_options options) {
    if (options.cert_file.empty() || options.key_file.empty()) {
        throw std::runtime_error("listen requires cert_file and key_file");
    }
    if (options.alpns.empty()) {
        options.alpns.push_back("h3");
    }

    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(options.port);
    if (inet_pton(AF_INET6, options.ip.c_str(), &a.sin6_addr) != 1) {
        throw std::runtime_error("inet_pton failed for listen ip: " + options.ip);
    }

    auto channel = seastar::make_lw_shared<udp_channel>(
            seastar::engine().net().make_bound_datagram_channel(seastar::socket_address(a)));
    auto crypto = seastar::make_lw_shared<server_crypto_config>(
            options.cert_file, options.key_file, options.alpns);

    co_return seastar::make_lw_shared<listener>(
            std::move(channel), seastar::socket_address(a), std::move(crypto));
}

using server_crypto_config_ptr = seastar::lw_shared_ptr<server::server_crypto_config>;

} // namespace seastar::quic::experimental::server
