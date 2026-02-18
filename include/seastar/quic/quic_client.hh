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
#include <seastar/core/shared_ptr.hh>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

namespace seastar::quic::experimental {

namespace client {
        
class client_crypto_config {
public:
    explicit client_crypto_config(const std::vector<std::string>& alpns);    

    ~client_crypto_config();

    void add_alpn(const std::string& protocol);

    gnutls_session_t make_session(const std::string& sni_hostname, ngtcp2_crypto_conn_ref* ref);

private:
    gnutls_certificate_credentials_t _cred = nullptr;
    std::vector<std::string> _alpns;
};

} // namespace client

using client_crypto_config_ptr = seastar::lw_shared_ptr<client::client_crypto_config>;

} // namespace seastar::quic::experimental