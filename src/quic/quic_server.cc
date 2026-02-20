/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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

namespace seastar::quic::experimental {

class quic_server::impl {
};

quic_server::quic_server()
    : _impl(std::make_unique<impl>()) {
}

quic_server::~quic_server() = default;
quic_server::quic_server(quic_server&&) noexcept = default;
quic_server& quic_server::operator=(quic_server&&) noexcept = default;

future<> quic_server::start(quic_server_config) {
    return make_exception_future<>(
        quic_exception(quic_error::unsupported, "quic_server backend is not implemented yet"));
}

future<quic_session> quic_server::accept() {
    return make_exception_future<quic_session>(
        quic_exception(quic_error::unsupported, "quic_server backend is not implemented yet"));
}

future<> quic_server::stop() {
    return make_ready_future<>();
}

} // namespace seastar::quic::experimental
