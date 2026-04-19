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
#include <seastar/core/future.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/queue.hh>
#include <seastar/net/api.hh>
#include <seastar/net/stack.hh>
#include <seastar/quic/quic.hh>

#include <exception>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace seastar {

class net::get_impl {
public:
    static std::unique_ptr<connected_socket_impl> get(connected_socket s) {
        return std::move(s._csi);
    }

    static connected_socket_impl* maybe_get_ptr(connected_socket& s) {
        if (s._csi) {
            return s._csi.get();
        }
        return nullptr;
    }
};

} // namespace seastar

namespace seastar::rpc::experimental {

namespace {

class quic_client_connection_pool;

class quic_no_batching_sink_impl final : public data_sink_impl {
public:
    explicit quic_no_batching_sink_impl(data_sink sink)
        : _sink(std::move(sink)) {
    }

    temporary_buffer<char> allocate_buffer(size_t size) override {
        return _sink.allocate_buffer(size);
    }

    future<> put(std::span<temporary_buffer<char>> data) override {
        return _sink.put(data);
    }

    future<> flush() override {
        return _sink.flush();
    }

    future<> close() override {
        return _sink.flush();
    }

    size_t buffer_size() const noexcept override {
        return _sink.buffer_size();
    }

private:
    data_sink _sink;
};

class quic_connected_socket_impl final : public net::connected_socket_impl {
public:
    quic_connected_socket_impl(connected_socket socket, std::shared_ptr<quic_client_connection_pool> pool = {})
        : _socket(std::move(socket))
        , _pool(std::move(pool))
        , _impl(net::get_impl::maybe_get_ptr(_socket)) {
    }

    ~quic_connected_socket_impl() override;

    data_source source() override {
        return _impl->source();
    }

    data_source source(connected_socket_input_stream_config cfg) override {
        return _impl->source(cfg);
    }

    data_sink sink() override {
        return data_sink(std::make_unique<quic_no_batching_sink_impl>(_impl->sink()));
    }

    void shutdown_input() override {
        _impl->shutdown_input();
    }

    void shutdown_output() override {
        _impl->shutdown_output();
    }

    void set_nodelay(bool nodelay) override {
        _impl->set_nodelay(nodelay);
    }

    bool get_nodelay() const override {
        return _impl->get_nodelay();
    }

    void set_keepalive(bool keepalive) override {
        _impl->set_keepalive(keepalive);
    }

    bool get_keepalive() const override {
        return _impl->get_keepalive();
    }

    void set_keepalive_parameters(const net::keepalive_params& params) override {
        _impl->set_keepalive_parameters(params);
    }

    net::keepalive_params get_keepalive_parameters() const override {
        return _impl->get_keepalive_parameters();
    }

    void set_sockopt(int level, int optname, const void* data, size_t len) override {
        _impl->set_sockopt(level, optname, data, len);
    }

    int get_sockopt(int level, int optname, void* data, size_t len) const override {
        return _impl->get_sockopt(level, optname, data, len);
    }

    socket_address local_address() const noexcept override {
        return _impl->local_address();
    }

    socket_address remote_address() const noexcept override {
        return _impl->remote_address();
    }

    future<> wait_input_shutdown() override {
        return _impl->wait_input_shutdown();
    }

private:
    void release_pool();

    connected_socket _socket;
    std::shared_ptr<quic_client_connection_pool> _pool;
    net::connected_socket_impl* _impl;
    bool _released = false;
};

class quic_client_connection_pool final : public std::enable_shared_from_this<quic_client_connection_pool> {
public:
    explicit quic_client_connection_pool(quic::experimental::quic_client_config config)
        : _config(std::move(config)) {
    }

    bool matches(const quic::experimental::quic_client_config& config) const {
        return !_stopping
            && _config.remote_address == config.remote_address
            && _config.local_address == config.local_address
            && _config.server_name == config.server_name
            && _config.ca_file == config.ca_file
            && _config.alpns == config.alpns;
    }

    future<connected_socket> open_stream() {
        if (!_connection) {
            _connection = co_await _client.connect(_config);
        }
        auto stream = co_await _connection->open_stream();
        ++_refs;
        auto cs = quic::experimental::to_connected_socket(std::move(stream));
        co_return connected_socket(std::make_unique<quic_connected_socket_impl>(std::move(cs), shared_from_this()));
    }

    void release() {
        if (_refs > 0) {
            --_refs;
        }
        if (_refs == 0) {
            request_stop();
        }
    }

    void stop_now() {
        request_stop();
    }

private:
    void request_stop() {
        if (_stopping) {
            return;
        }
        _stopping = true;
        _connection.reset();
        _stop_future = _client.stop().handle_exception([] (std::exception_ptr) {
        });
    }

    quic::experimental::quic_client _client;
    quic::experimental::quic_client_config _config;
    std::optional<quic::experimental::connection> _connection;
    size_t _refs = 0;
    bool _stopping = false;
    future<> _stop_future = make_ready_future<>();
};

quic_connected_socket_impl::~quic_connected_socket_impl() {
    release_pool();
}

void quic_connected_socket_impl::release_pool() {
    if (!_pool || _released) {
        return;
    }
    _released = true;
    _pool->release();
}

struct client_pool_entry {
    std::weak_ptr<quic_client_connection_pool> pool;
};

thread_local std::vector<client_pool_entry> client_pools;

std::shared_ptr<quic_client_connection_pool> get_client_pool(quic::experimental::quic_client_config config) {
    for (auto it = client_pools.begin(); it != client_pools.end();) {
        auto pool = it->pool.lock();
        if (!pool) {
            it = client_pools.erase(it);
            continue;
        }
        if (pool->matches(config)) {
            return pool;
        }
        ++it;
    }

    auto pool = std::make_shared<quic_client_connection_pool>(std::move(config));
    client_pools.push_back({pool});
    return pool;
}

struct quic_server_socket_state {
    explicit quic_server_socket_state(quic::experimental::quic_server_config config)
        : config(std::move(config)) {
    }

    quic::experimental::quic_server server;
    quic::experimental::quic_server_config config;
    queue<accept_result> accepted{1024};
    bool started = false;
    bool stopping = false;
};

class quic_server_socket_impl final : public net::server_socket_impl {
public:
    explicit quic_server_socket_impl(quic::experimental::quic_server_config config)
        : _state(std::make_shared<quic_server_socket_state>(std::move(config))) {
    }

    future<accept_result> accept() override {
        if (!_state->started) {
            co_await _state->server.start(_state->config);
            _state->started = true;
            _accept_loop = accept_connections(_state);
        }

        co_return co_await _state->accepted.pop_eventually();
    }

    void abort_accept() override {
        auto state = _state;
        if (!state->started || state->stopping) {
            return;
        }
        state->stopping = true;
        state->accepted.abort(std::make_exception_ptr(std::runtime_error("QUIC RPC server socket stopped")));
        _stop_future = state->server.stop().handle_exception([] (std::exception_ptr) {
        });
    }

    socket_address local_address() const override {
        return _state->config.listen_address;
    }

    ~quic_server_socket_impl() override {
        abort_accept();
        if (_accept_loop.available()) {
            _accept_loop.ignore_ready_future();
        }
        if (_stop_future.available()) {
            _stop_future.ignore_ready_future();
        }
    }

private:
    static future<> accept_connections(std::shared_ptr<quic_server_socket_state> state) noexcept {
        try {
            while (!state->stopping) {
                auto conn = co_await state->server.accept();
                auto addr = conn.peer_address();
                (void)accept_streams(state, std::move(conn), addr);
            }
        } catch (...) {
            if (!state->stopping) {
                state->accepted.abort(std::current_exception());
            }
        }
    }

    static future<> accept_streams(std::shared_ptr<quic_server_socket_state> state, quic::experimental::connection conn, socket_address addr) noexcept {
        try {
            while (!state->stopping && conn.is_open()) {
                auto stream = co_await conn.accept_stream();
                auto cs = quic::experimental::to_connected_socket(std::move(stream));
                cs = connected_socket(std::make_unique<quic_connected_socket_impl>(std::move(cs)));
                co_await state->accepted.push_eventually(accept_result{std::move(cs), addr});
            }
        } catch (...) {
        }
    }

    future<> _accept_loop = make_ready_future<>();
    future<> _stop_future = make_ready_future<>();
    std::shared_ptr<quic_server_socket_state> _state;
};

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

        _pool = get_client_pool(std::move(cfg));
        co_return co_await _pool->open_stream();
    }

    void set_reuseaddr(bool reuseaddr) override {
        _reuseaddr = reuseaddr;
    }

    bool get_reuseaddr() const override {
        return _reuseaddr;
    }

    void shutdown() override {
        if (_pool) {
            _pool->stop_now();
        }
    }

private:
    quic::experimental::quic_client_config _base_config;
    std::shared_ptr<quic_client_connection_pool> _pool;
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
