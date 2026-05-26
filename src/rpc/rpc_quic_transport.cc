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

#include <seastar/rpc/rpc_quic_transport.hh>

namespace seastar::rpc {

connected_socket_transport::connected_socket_transport(connected_socket fd) noexcept
    : _fd(std::move(fd))
    , _input(_fd.input())
    , _output(_fd.output()) {
}

input_stream<char>& connected_socket_transport::input() {
    return _input;
}

output_stream<char>& connected_socket_transport::output() {
    return _output;
}

void connected_socket_transport::shutdown_input() {
    _fd.shutdown_input();
}

void connected_socket_transport::shutdown_output() {
    _fd.shutdown_output();
}

namespace experimental {

namespace {

class quic_server_acceptor final : public server::acceptor {
    quic::experimental::quic_server _server;
    quic::experimental::quic_server_config _config;
    bool _started = false;

public:
    explicit quic_server_acceptor(quic::experimental::quic_server_config config)
            : _config(std::move(config)) {
    }

    future<server::accepted_connection> accept() override {
        if (!_started) {
            co_await _server.start(std::move(_config));
            _started = true;
        }

        auto session = co_await _server.accept();
        auto addr = session.peer_address();
        try {
            auto control_stream = co_await session.accept_stream();
            co_return server::accepted_connection{
                .remote_address = std::move(addr),
                .transport = std::make_unique<quic_server_transport>(std::move(session), std::move(control_stream)),
            };
        } catch (...) {
            auto ep = std::current_exception();
            (void)session.close().handle_exception([] (std::exception_ptr) {});
            std::rethrow_exception(ep);
        }
    }

    future<> stop() override {
        co_await _server.stop();
    }
};

bool is_quic_closed_exception(std::exception_ptr ep) noexcept {
    try {
        std::rethrow_exception(ep);
    } catch (const quic::experimental::quic_error& ex) {
        return ex.code() == quic::experimental::quic_error::closed;
    } catch (...) {
        return false;
    }
}

future<> ignore_quic_closed_exception(std::exception_ptr ep) {
    if (is_quic_closed_exception(ep)) {
        return make_ready_future<>();
    }
    return make_exception_future<>(ep);
}

future<> abort_quic_stream(quic::experimental::stream& stream) {
    co_await stream.reset().handle_exception([] (std::exception_ptr ep) {
        return ignore_quic_closed_exception(ep);
    });
    co_await stream.stop_sending().handle_exception([] (std::exception_ptr ep) {
        return ignore_quic_closed_exception(ep);
    });
}

class quic_transport_stream final : public connection::transport::stream {
    quic::experimental::stream _stream;
    input_stream<char> _input;
    output_stream<char> _output;
    bool _output_closed = false;

public:
    explicit quic_transport_stream(quic::experimental::stream stream)
            : _stream(std::move(stream))
            , _input(_stream.input())
            , _output(_stream.output()) {
    }

    input_stream<char>& input() override {
        return _input;
    }

    output_stream<char>& output() override {
        return _output;
    }

    future<> close_output() override {
        if (_output_closed) {
            return make_ready_future<>();
        }
        _output_closed = true;
        return _output.close().handle_exception([] (std::exception_ptr ep) {
            return ignore_quic_closed_exception(ep);
        });
    }

    future<> stop_input() override {
        return _stream.stop_sending().handle_exception([] (std::exception_ptr ep) {
            return ignore_quic_closed_exception(ep);
        });
    }

    future<> abort() override {
        return abort_quic_stream(_stream);
    }
};

} // anonymous namespace

std::unique_ptr<server::acceptor> make_quic_server_acceptor(quic::experimental::quic_server_config config) {
    return std::make_unique<quic_server_acceptor>(std::move(config));
}

quic_client_transport::quic_client_transport(
        seastar::quic::experimental::quic_client client,
        seastar::quic::experimental::connection conn,
        seastar::quic::experimental::stream control_stream)
        : _client(std::move(client))
        , _conn(std::move(conn))
        , _control_stream(std::move(control_stream))
        , _control_input(_control_stream.input())
        , _control_output(_control_stream.output()) {
}

quic_client_transport::quic_client_transport(
        seastar::quic::experimental::connection conn,
        seastar::quic::experimental::stream control_stream)
        : _conn(std::move(conn))
        , _control_stream(std::move(control_stream))
        , _control_input(_control_stream.input())
        , _control_output(_control_stream.output()) {
}

input_stream<char>& quic_client_transport::input() {
    return _control_input;
}

output_stream<char>& quic_client_transport::output() {
    return _control_output;
}

void quic_client_transport::shutdown_input() {
    (void)_control_stream.stop_sending().handle_exception([] (std::exception_ptr) {});
}

void quic_client_transport::shutdown_output() {
    (void)_control_output.close().handle_exception([] (std::exception_ptr) {});
}

bool quic_client_transport::supports_multiplexed_requests() const {
    return true;
}

future<> quic_client_transport::stop() {
    try {
        co_await _control_stream.stop_sending();
    } catch (...) {
    }
    try {
        co_await _control_output.close();
    } catch (...) {
    }
    if (_client) {
        try {
            co_await _client->stop();
        } catch (...) {
        }
    } else {
        try {
            co_await _conn.close();
        } catch (...) {
        }
    }
}

future<std::unique_ptr<connection::transport::stream>> quic_client_transport::open_request_stream() {
    auto stream = co_await _conn.open_stream();
    co_return std::make_unique<quic_transport_stream>(std::move(stream));
}

quic_server_transport::quic_server_transport(
        seastar::quic::experimental::connection conn,
        seastar::quic::experimental::stream control_stream)
        : _conn(std::move(conn))
        , _control_stream(std::move(control_stream))
        , _control_input(_control_stream.input())
        , _control_output(_control_stream.output()) {
}

input_stream<char>& quic_server_transport::input() {
    return _control_input;
}

output_stream<char>& quic_server_transport::output() {
    return _control_output;
}

void quic_server_transport::shutdown_input() {
    (void)_control_stream.stop_sending().handle_exception([] (std::exception_ptr) {});
}

void quic_server_transport::shutdown_output() {
    (void)_control_output.close().handle_exception([] (std::exception_ptr) {});
}

future<> quic_server_transport::stop() {
    try {
        co_await _control_stream.stop_sending();
    } catch (...) {
    }
    try {
        co_await _control_output.close();
    } catch (...) {
    }
    try {
        co_await _conn.close();
    } catch (...) {
    }
}

bool quic_server_transport::supports_multiplexed_requests() const {
    return true;
}

future<std::unique_ptr<connection::transport::stream>> quic_server_transport::accept_request_stream() {
    auto stream = co_await _conn.accept_stream();
    co_return std::make_unique<quic_transport_stream>(std::move(stream));
}

} // namespace experimental

} // namespace seastar::rpc
