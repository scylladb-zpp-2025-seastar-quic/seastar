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

using client_crypto_config_ptr = seastar::lw_shared_ptr<client::client_crypto_config>;

} // namespace seastar::quic::experimental