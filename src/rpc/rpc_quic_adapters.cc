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

#include <seastar/rpc/rpc_quic_adapters.hh>

#include <seastar/core/coroutine.hh>
#include <seastar/net/api.hh>
#include <seastar/net/stack.hh>
#include <seastar/quic/quic.hh>

namespace seastar::rpc::experimental {

namespace {

// server_socket_impl backed by a QUIC server.
// On accept(), starts the QUIC server (lazily), accepts a QUIC connection,
// waits for the client to open a bidirectional stream, and returns
// a connected_socket wrapping that stream.
class quic_server_socket_impl final : public net::server_socket_impl {
public:
    explicit quic_server_socket_impl(quic::experimental::quic_server_config config)
        : _config(std::move(config)) {
    }

    future<accept_result> accept() override {
        if (!_started) {
            co_await _server.start(_config);
            _started = true;
        }

        auto conn = co_await _server.accept();
        auto addr = conn.peer_address();
        auto stream = co_await conn.accept_stream();
        auto cs = quic::experimental::to_connected_socket(std::move(stream));

        co_return accept_result{std::move(cs), addr};
    }

    void abort_accept() override {
        if (_started && !_stopping) {
            _stopping = true;
            _stop_future = _server.stop();
        }
    }

    socket_address local_address() const override {
        return _config.listen_address;
    }

    ~quic_server_socket_impl() {
        if (_stop_future.available()) {
            _stop_future.ignore_ready_future();
        }
    }

private:
    quic::experimental::quic_server _server;
    quic::experimental::quic_server_config _config;
    bool _started = false;
    bool _stopping = false;
    future<> _stop_future = make_ready_future<>();
};

// socket_impl backed by a QUIC client.
// On connect(), establishes a QUIC connection to the target address,
// opens a bidirectional stream, and returns a connected_socket
// wrapping that stream.
class quic_client_socket_impl final : public net::socket_impl {
public:
    explicit quic_client_socket_impl(quic::experimental::quic_client_config config)
        : _base_config(std::move(config)) {
    }

    future<connected_socket> connect(socket_address sa, socket_address local, transport) override {
        auto cfg = _base_config;
        cfg.remote_address = sa;
        if (local != socket_address{}) {
            cfg.local_address = local;
        }

        auto conn = co_await _client.connect(std::move(cfg));
        auto stream = co_await conn.open_stream();

        co_return quic::experimental::to_connected_socket(std::move(stream));
    }

    void set_reuseaddr(bool reuseaddr) override {
        _reuseaddr = reuseaddr;
    }

    bool get_reuseaddr() const override {
        return _reuseaddr;
    }

    void shutdown() override {
        (void)_client.stop();
    }

private:
    quic::experimental::quic_client _client;
    quic::experimental::quic_client_config _base_config;
    bool _reuseaddr = false;
};

} // anonymous namespace

server_socket make_quic_server_socket(quic::experimental::quic_server_config config) {
    return server_socket(std::make_unique<quic_server_socket_impl>(std::move(config)));
}

seastar::socket make_quic_client_socket(quic::experimental::quic_client_config config) {
    return seastar::socket(std::make_unique<quic_client_socket_impl>(std::move(config)));
}

} // namespace seastar::rpc::experimental
