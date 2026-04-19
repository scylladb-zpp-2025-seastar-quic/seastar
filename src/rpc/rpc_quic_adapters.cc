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
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/stack.hh>
#include <seastar/quic/quic_error.hh>

#include <memory>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace seastar::rpc::experimental {
namespace {

using quic::experimental::connection;
using quic::experimental::quic_client_config;
using quic::experimental::quic_server_config;
using quic::experimental::quic_client;
using quic::experimental::quic_server;
using quic::experimental::stream;
using quic::experimental::stream_open_options;
using quic::experimental::stream_type;
using quic::experimental::to_connected_socket;

void constrain_to_single_bidirectional_stream(quic_client_config& config) noexcept {
    config.session_options.transport.initial_max_streams_bidi = 0;
    config.session_options.transport.initial_max_streams_uni = 0;
}

void constrain_to_single_bidirectional_stream(quic_server_config& config) noexcept {
    config.session_options.transport.initial_max_streams_bidi = 1;
    config.session_options.transport.initial_max_streams_uni = 0;
}


class quic_transport_holder final {
    std::optional<connection> _session;
    lw_shared_ptr<quic_client> _client;
    bool _connected = false;
    bool _close_requested = false;

public:
    quic_transport_holder() = default;
    explicit quic_transport_holder(connection session)
        : _session(std::move(session))
        , _connected(true) {
    }

    ~quic_transport_holder() {
        close();
    }

    quic_transport_holder(const quic_transport_holder&) = delete;
    quic_transport_holder& operator=(const quic_transport_holder&) = delete;

    void set_session(connection session) {
        _session.emplace(std::move(session));
        _connected = true;
    }

    void set_client(lw_shared_ptr<quic_client> client) {
        _client = std::move(client);
    }

    connection& session() {
        return *_session;
    }

    lw_shared_ptr<quic_client> client() {
        return _client;
    }

    bool close_requested() const noexcept {
        return _close_requested;
    }

    void close() noexcept {
        _close_requested = true;
        _session.reset();
        if (_client) {
            auto client = std::exchange(_client, {});
            (void)client->stop().finally([client = std::move(client)] {}).handle_exception([] (std::exception_ptr) {});
        }
    }
};

class eof_on_quic_closed_source_impl final : public data_source_impl {
    data_source _source;
    lw_shared_ptr<quic_transport_holder> _transport;

public:
    eof_on_quic_closed_source_impl(data_source source, lw_shared_ptr<quic_transport_holder> transport)
        : _source(std::move(source))
        , _transport(std::move(transport)) {
    }

    future<temporary_buffer<char>> get() override {
        try {
            co_return co_await _source.get();
        } catch (const quic::experimental::quic_error& e) {
            if (e.code() == quic::experimental::quic_error::closed) {
                co_return temporary_buffer<char>();
            }
            throw;
        }
    }

    future<temporary_buffer<char>> skip(uint64_t n) override {
        try {
            co_return co_await _source.skip(n);
        } catch (const quic::experimental::quic_error& e) {
            if (e.code() == quic::experimental::quic_error::closed) {
                co_return temporary_buffer<char>();
            }
            throw;
        }
    }

    future<> close() override {
        return _source.close();
    }
};

data_source eof_on_quic_closed(data_source source, lw_shared_ptr<quic_transport_holder> transport) {
    return data_source(std::make_unique<eof_on_quic_closed_source_impl>(std::move(source), std::move(transport)));
}


class close_aware_quic_sink_impl final : public data_sink_impl {
    data_sink _sink;
    lw_shared_ptr<quic_transport_holder> _transport;

public:
    close_aware_quic_sink_impl(data_sink sink, lw_shared_ptr<quic_transport_holder> transport)
        : _sink(std::move(sink))
        , _transport(std::move(transport)) {
    }

    temporary_buffer<char> allocate_buffer(size_t size) override {
        return _sink.allocate_buffer(size);
    }

    future<> put(std::span<temporary_buffer<char>> data) override {
        if (_transport->close_requested()) {
            return make_exception_future<>(quic::experimental::quic_error(
                    quic::experimental::quic_error::closed, "QUIC RPC transport is closing"));
        }
        return _sink.put(data);
    }

    future<> flush() override {
        if (_transport->close_requested()) {
            return make_ready_future<>();
        }
        return _sink.flush();
    }

    future<> close() override {
        if (_transport->close_requested()) {
            co_return;
        }
        try {
            co_await _sink.close();
        } catch (const quic::experimental::quic_error& e) {
            if (e.code() != quic::experimental::quic_error::closed) {
                throw;
            }
        }
    }

    size_t buffer_size() const noexcept override {
        return _sink.buffer_size();
    }

    bool can_batch_flushes() const noexcept override {
        return _sink.can_batch_flushes();
    }

    void on_batch_flush_error() noexcept override {
        _sink.on_batch_flush_error();
    }
};

data_sink close_aware_quic_sink(data_sink sink, lw_shared_ptr<quic_transport_holder> transport) {
    return data_sink(std::make_unique<close_aware_quic_sink_impl>(std::move(sink), std::move(transport)));
}

class owned_quic_connected_socket_impl final : public net::connected_socket_impl {
    connected_socket _stream_socket;
    lw_shared_ptr<quic_transport_holder> _transport;

public:
    owned_quic_connected_socket_impl(connected_socket stream_socket, lw_shared_ptr<quic_transport_holder> transport)
        : _stream_socket(std::move(stream_socket))
        , _transport(std::move(transport)) {
    }

    data_source source() override {
        return eof_on_quic_closed(std::move(_stream_socket.input()).detach(), _transport);
    }

    data_source source(connected_socket_input_stream_config cfg) override {
        return eof_on_quic_closed(std::move(_stream_socket.input(cfg)).detach(), _transport);
    }

    data_sink sink() override {
        return close_aware_quic_sink(std::move(_stream_socket.output()).detach(), _transport);
    }

    void shutdown_input() override {
        if (!_transport->close_requested()) {
            _stream_socket.shutdown_input();
        }
    }

    void shutdown_output() override {
        if (!_transport->close_requested()) {
            _stream_socket.shutdown_output();
        }
    }

    void set_nodelay(bool nodelay) override {
        _stream_socket.set_nodelay(nodelay);
    }

    bool get_nodelay() const override {
        return _stream_socket.get_nodelay();
    }

    void set_keepalive(bool keepalive) override {
        _stream_socket.set_keepalive(keepalive);
    }

    bool get_keepalive() const override {
        return _stream_socket.get_keepalive();
    }

    void set_keepalive_parameters(const net::keepalive_params& params) override {
        _stream_socket.set_keepalive_parameters(params);
    }

    net::keepalive_params get_keepalive_parameters() const override {
        return _stream_socket.get_keepalive_parameters();
    }

    void set_sockopt(int level, int optname, const void* data, size_t len) override {
        _stream_socket.set_sockopt(level, optname, data, len);
    }

    int get_sockopt(int level, int optname, void* data, size_t len) const override {
        return _stream_socket.get_sockopt(level, optname, data, len);
    }

    socket_address local_address() const noexcept override {
        return _stream_socket.local_address();
    }

    socket_address remote_address() const noexcept override {
        return _stream_socket.remote_address();
    }

    future<> wait_input_shutdown() override {
        return _stream_socket.wait_input_shutdown();
    }
};

connected_socket make_owned_quic_connected_socket(stream&& quic_stream, lw_shared_ptr<quic_transport_holder> transport) {
    return connected_socket(std::make_unique<owned_quic_connected_socket_impl>(
            to_connected_socket(std::move(quic_stream)), std::move(transport)));
}

class quic_rpc_socket_impl final : public net::socket_impl {
    quic_client_config _config;
    bool _reuseaddr = false;
    bool _shutdown = false;
    bool _connect_started = false;
    lw_shared_ptr<quic_transport_holder> _active_transport;

public:
    explicit quic_rpc_socket_impl(quic_client_config config)
        : _config(std::move(config)) {
        constrain_to_single_bidirectional_stream(_config);
    }

    future<connected_socket> connect(socket_address sa, socket_address, transport = transport::TCP) override {
        if (_shutdown) {
            return make_exception_future<connected_socket>(std::system_error(ECONNABORTED, std::system_category()));
        }
        if (_connect_started) {
            return make_exception_future<connected_socket>(std::logic_error("QUIC RPC socket can only connect once"));
        }
        _connect_started = true;
        if (_config.remote_address.is_unspecified()) {
            _config.remote_address = sa;
        }

        _active_transport = make_lw_shared<quic_transport_holder>();
        auto client = make_lw_shared<quic_client>();
        _active_transport->set_client(client);
        return client->connect(std::move(_config)).then([transport = _active_transport, client] (connection session) mutable {
            transport->set_session(std::move(session));
            if (transport->close_requested()) {
                transport->close();
                return make_exception_future<connected_socket>(std::system_error(ECONNABORTED, std::system_category()));
            }
            return transport->session().open_stream(stream_open_options{.type = stream_type::bidirectional}).then(
                    [transport, client] (stream quic_stream) mutable {
                return make_ready_future<connected_socket>(make_owned_quic_connected_socket(
                        std::move(quic_stream), std::move(transport)));
            });
        });
    }

    void set_reuseaddr(bool reuseaddr) override {
        _reuseaddr = reuseaddr;
    }

    bool get_reuseaddr() const override {
        return _reuseaddr;
    }

    void shutdown() override {
        _shutdown = true;
        if (_active_transport) {
            _active_transport->close();
        }
    }
};

class quic_rpc_server_socket_impl final : public net::server_socket_impl {
    quic_server_config _config;
    socket_address _local_address;
    quic_server _server;
    shared_future<> _started;
    bool _start_requested = false;
    bool _aborted = false;

    future<> ensure_started() {
        if (!_start_requested) {
            _start_requested = true;
            _started = shared_future<>(_server.start(std::move(_config)));
        }
        return _started.get_future();
    }

public:
    explicit quic_rpc_server_socket_impl(quic_server_config config)
        : _config(std::move(config))
        , _local_address(_config.listen_address) {
        constrain_to_single_bidirectional_stream(_config);
    }

    future<accept_result> accept() override {
        if (_aborted) {
            return make_exception_future<accept_result>(std::system_error(ECONNABORTED, std::system_category()));
        }
        return ensure_started().then([this] {
            return _server.accept();
        }).then([] (connection session) mutable {
            auto peer = session.peer_address();
            auto transport = make_lw_shared<quic_transport_holder>(std::move(session));
            return transport->session().accept_stream().then([peer, transport] (stream quic_stream) mutable {
                if (quic_stream.type() != stream_type::bidirectional) {
                    return make_exception_future<accept_result>(quic::experimental::quic_error(
                            quic::experimental::quic_error::invalid_state,
                            "RPC over QUIC requires a bidirectional stream"));
                }
                return make_ready_future<accept_result>(accept_result{
                    .connection = make_owned_quic_connected_socket(std::move(quic_stream), std::move(transport)),
                    .remote_address = peer,
                });
            });
        });
    }

    void abort_accept() override {
        _aborted = true;
        (void)_server.stop().handle_exception([] (std::exception_ptr) {});
    }

    socket_address local_address() const override {
        return _local_address;
    }
};

} // namespace

socket make_quic_client_socket(quic_client_config config) {
    return socket(std::make_unique<quic_rpc_socket_impl>(std::move(config)));
}

server_socket make_quic_server_socket(quic_server_config config) {
    return server_socket(std::make_unique<quic_rpc_server_socket_impl>(std::move(config)));
}

} // namespace seastar::rpc::experimental
