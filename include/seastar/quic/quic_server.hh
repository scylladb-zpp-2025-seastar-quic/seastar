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
#include <seastar/core/reactor.hh>
#include <seastar/core/coroutine.hh>
#include <arpa/inet.h>

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <seastar/quic/quic.hh>


namespace seastar::quic::experimental {

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

} // namespace server

using server_crypto_config_ptr = seastar::lw_shared_ptr<server::server_crypto_config>;

} // namespace seastar::quic::experimental