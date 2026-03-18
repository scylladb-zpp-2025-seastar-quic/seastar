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

#include <seastar/quic/quic.hh>

#include <chrono>
#include <deque>
#include <exception>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/stack.hh>
namespace seastar::quic::experimental {

namespace {

using transport_command = internal::transport_command;
using stream_event = internal::stream_event;

class queue_session_runtime final : public internal::session_runtime {
public:
    explicit queue_session_runtime(connection_options options)
        : _options(std::move(options)) {
    }

    bool is_open() const noexcept override {
        return !_closed && !_closing && _error == quic_error::none;
    }

    socket_address local_address() const override {
        return _local_address;
    }

    socket_address peer_address() const override {
        return _peer_address;
    }

    sstring selected_alpn() const override {
        return _selected_alpn;
    }

    future<> send(internal::quic_message msg) override {
        const auto msg_size = msg.payload.size();
        while (_options.max_pending_send_bytes &&
               _pending_send_bytes + msg_size > _options.max_pending_send_bytes) {
            throw_if_terminal("send");
            co_await _command_space_cv.wait();
        }
        throw_if_terminal("send");

        _pending_send_bytes += msg_size;
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::send,
          .msg = std::move(msg),
        });
        _command_cv.signal();
        co_return;
    }

    future<stream_id> open_stream(stream_type type) override {
        throw_if_terminal("open_stream");
        auto result = std::make_shared<promise<stream_id>>();
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::open_stream,
          .type = type,
          .open_result = result,
        });
        _command_cv.signal();
        co_return co_await result->get_future();
    }

    future<> reset_stream(stream_id sid, application_error_code app_error_code) override {
        throw_if_terminal("reset_stream");
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::reset_stream,
          .msg = internal::quic_message{
            .stream = sid,
          },
          .app_error_code = app_error_code,
        });
        _command_cv.signal();
        co_return;
    }

    future<> stop_sending(stream_id sid, application_error_code app_error_code) override {
        throw_if_terminal("stop_sending");
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::stop_sending,
          .msg = internal::quic_message{
            .stream = sid,
          },
          .app_error_code = app_error_code,
        });
        _command_cv.signal();
        co_return;
    }

    future<stream_event> receive_event() override {
        while (_events.empty()) {
            throw_if_terminal("receive_event");
            co_await _event_cv.wait();
        }

        auto evt = std::move(_events.front());
        _events.pop_front();
        _pending_receive_bytes -= evt.payload.size();
        _event_space_cv.signal();
        co_return evt;
    }

    future<> close() override {
        if (_closing || _closed) {
            co_return;
        }
        _closing = true;
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::close_connection,
        });
        _command_cv.signal();
        co_return;
    }

    future<transport_command> pop_command() override {
        while (_commands.empty()) {
            throw_if_terminal("pop_command");
            co_await _command_cv.wait();
        }

        auto cmd = std::move(_commands.front());
        _commands.pop_front();
        if (cmd.op == transport_command::kind::send) {
            _pending_send_bytes -= cmd.msg.payload.size();
            _command_space_cv.signal();
        }
        co_return cmd;
    }

    void push_event(stream_event evt) override {
        if (_closed || _error != quic_error::none) {
            return;
        }
        auto evt_size = evt.payload.size();
        if (_options.max_pending_receive_bytes &&
            _pending_receive_bytes + evt_size > _options.max_pending_receive_bytes) {
            mark_error(quic_error::io, "receive queue limit exceeded");
            return;
        }

        _pending_receive_bytes += evt_size;
        _events.push_back(std::move(evt));
        _event_cv.signal();
    }

    void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) override {
        if (result) {
            result->set_value(sid);
        }
    }

    void fail_open_stream(std::shared_ptr<promise<stream_id>> result, quic_error error, sstring detail) override {
        if (result) {
            result->set_exception(std::make_exception_ptr(quic_exception(error, detail)));
        }
    }

    void mark_transport_ready(socket_address local, socket_address peer, sstring selected_alpn) override {
        _local_address = local;
        _peer_address = peer;
        _selected_alpn = std::move(selected_alpn);
    }

    void mark_transport_closed() override {
        if (_closed) {
            return;
        }
        _closed = true;
        drain_pending_open_streams(std::make_exception_ptr(quic_exception(quic_error::closed, "transport closed")));
        _command_cv.signal();
        _command_space_cv.signal();
        _event_cv.signal();
        _event_space_cv.signal();
    }

    void mark_error(quic_error error, sstring detail) override {
        if (_error != quic_error::none) {
            return;
        }
        _error = error;
        _error_detail = std::move(detail);
        _closed = true;
        drain_pending_open_streams(std::make_exception_ptr(quic_exception(_error, _error_detail)));
        _command_cv.signal();
        _command_space_cv.signal();
        _event_cv.signal();
        _event_space_cv.signal();
    }

private:
    void throw_if_terminal(const char* op) const {
        if (_error != quic_error::none) {
            throw quic_exception(_error, sstring(op) + ": " + _error_detail);
        }
        if (_closed) {
            throw quic_exception(quic_error::closed, sstring(op) + ": transport closed");
        }
        if (_closing && std::string_view(op) != "pop_command") {
            throw quic_exception(quic_error::closed, sstring(op) + ": connection closing");
        }
    }

    void drain_pending_open_streams(std::exception_ptr ex) {
        for (auto& cmd : _commands) {
            if (cmd.op == transport_command::kind::open_stream && cmd.open_result) {
                cmd.open_result->set_exception(ex);
                cmd.open_result.reset();
            }
        }
    }

    connection_options _options;
    bool _closing = false;
    bool _closed = false;
    quic_error _error = quic_error::none;
    sstring _error_detail;

    socket_address _local_address{};
    socket_address _peer_address{};
    sstring _selected_alpn;

    std::deque<transport_command> _commands;
    std::deque<stream_event> _events;
    size_t _pending_send_bytes = 0;
    size_t _pending_receive_bytes = 0;

    condition_variable _command_cv;
    condition_variable _command_space_cv;
    condition_variable _event_cv;
    condition_variable _event_space_cv;
};

} // namespace

namespace internal {

class stream_state final : public enable_shared_from_this<stream_state> {
    class source_impl;
    class sink_impl;

public:
    stream_state(session_runtime_ptr runtime, stream_id sid, stream_type type, bool peer_initiated)
        : _runtime(std::move(runtime))
        , _id(sid)
        , _type(type)
        , _can_read(type == stream_type::bidirectional || peer_initiated)
        , _can_write(type == stream_type::bidirectional || !peer_initiated) {
        if (!_can_read) {
            notify_input_shutdown();
        }
    }

    bool is_open() const noexcept {
        return !_transport_closed
               && ((_can_read && !_input_shutdown_notified) || (_can_write && !_output_closed));
    }

    stream_id id() const noexcept {
        return _id;
    }

    stream_type type() const noexcept {
        return _type;
    }

    bool can_read() const noexcept {
        return _can_read;
    }

    bool can_write() const noexcept {
        return _can_write;
    }

    input_stream<char> input(connected_socket_input_stream_config cfg);
    output_stream<char> output(size_t buffer_size);

    future<> close_output();
    future<> reset(application_error_code app_error_code);
    future<> stop_sending(application_error_code app_error_code);
    future<> wait_input_shutdown() {
        return _input_shutdown.get_shared_future();
    }

    data_source source(connected_socket_input_stream_config);
    data_sink sink();

    socket_address local_address() const {
        return _runtime ? _runtime->local_address() : socket_address();
    }

    socket_address peer_address() const {
        return _runtime ? _runtime->peer_address() : socket_address();
    }

    void on_data(temporary_buffer<char> payload, bool fin);
    void on_reset(application_error_code app_error_code);
    void on_transport_closed();

private:
    future<> send_one(temporary_buffer<char> payload, bool fin);

    bool push_read_fragment(temporary_buffer<char> payload) {
        if (_read_queue.push(std::move(payload))) {
            return true;
        }
        abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::io, "stream read queue is full")));
        if (_runtime) {
            _runtime->mark_error(quic_error::io, "stream read queue is full");
        }
        return false;
    }

    void notify_input_shutdown() {
        if (_input_shutdown_notified) {
            return;
        }
        _input_shutdown_notified = true;
        _input_shutdown.set_value();
    }

    void abort_read_queue(std::exception_ptr ex) {
        _read_queue.abort(ex);
        notify_input_shutdown();
    }

    session_runtime_ptr _runtime;
    stream_id _id = invalid_stream_id;
    stream_type _type = stream_type::bidirectional;
    bool _can_read = true;
    bool _can_write = true;

    queue<temporary_buffer<char>> _read_queue{1024};
    shared_promise<> _input_shutdown;
    bool _input_shutdown_notified = false;
    bool _output_closed = false;
    bool _transport_closed = false;
};

class connection_state final : public enable_shared_from_this<connection_state> {
public:
    explicit connection_state(session_runtime_ptr runtime)
        : _runtime(std::move(runtime))
        , _accepted_streams(1024) {
    }

    void start() {
        auto self = shared_from_this();
        (void)with_gate(_gate, [self] { return self->run(); })
          .handle_exception([self](std::exception_ptr ep) {
              self->on_transport_failure(ep);
          })
          .or_terminate();
    }

    bool is_open() const noexcept {
        return _runtime && _runtime->is_open();
    }

    socket_address local_address() const {
        return _runtime ? _runtime->local_address() : socket_address();
    }

    socket_address peer_address() const {
        return _runtime ? _runtime->peer_address() : socket_address();
    }

    sstring selected_alpn() const {
        return _runtime ? _runtime->selected_alpn() : sstring();
    }

    future<stream> open_stream(stream_open_options options) {
        auto sid = co_await _runtime->open_stream(options.type);
        auto st = get_or_create_stream(sid, options.type, false);
        co_return stream(std::move(st));
    }

    future<stream> accept_stream() {
        auto st = co_await _accepted_streams.pop_eventually();
        co_return stream(std::move(st));
    }

    future<> close() {
        if (!_runtime) {
            co_return;
        }
        co_await _runtime->close();
        co_await _gate.close();
    }

    shared_ptr<stream_state> get_or_create_stream(stream_id sid, stream_type type, bool peer_initiated) {
        auto [it, inserted] = _streams.emplace(sid, shared_ptr<stream_state>{});
        if (inserted || !it->second) {
            it->second = make_shared<stream_state>(_runtime, sid, type, peer_initiated);
        }
        return it->second;
    }

private:
    future<> run() {
        while (_runtime) {
            auto evt = co_await _runtime->receive_event();
            switch (evt.op) {
            case stream_event::kind::opened: {
                auto st = get_or_create_stream(evt.stream, evt.type, evt.peer_initiated);
                if (evt.peer_initiated && _accepted_stream_ids.emplace(evt.stream).second) {
                    co_await _accepted_streams.push_eventually(shared_ptr<stream_state>(st));
                }
                break;
            }
            case stream_event::kind::data: {
                auto st = get_or_create_stream(evt.stream, evt.type, evt.peer_initiated);
                if (evt.peer_initiated && _accepted_stream_ids.emplace(evt.stream).second) {
                    co_await _accepted_streams.push_eventually(shared_ptr<stream_state>(st));
                }
                st->on_data(std::move(evt.payload), evt.fin);
                break;
            }
            case stream_event::kind::reset: {
                auto st = get_or_create_stream(evt.stream, evt.type, evt.peer_initiated);
                st->on_reset(evt.app_error_code);
                break;
            }
            case stream_event::kind::stop_sending:
                break;
            case stream_event::kind::transport_closed:
                co_return;
            }
        }
    }

    void on_transport_failure(std::exception_ptr ep) {
        _accepted_streams.abort(ep);
        for (auto& [_, st] : _streams) {
            st->on_transport_closed();
        }
    }

    session_runtime_ptr _runtime;
    gate _gate;
    queue<shared_ptr<stream_state>> _accepted_streams;
    std::unordered_map<stream_id, shared_ptr<stream_state>> _streams;
    std::unordered_set<stream_id> _accepted_stream_ids;
};

future<> stream_state::send_one(temporary_buffer<char> payload, bool fin) {
    if (!_can_write) {
        return make_exception_future<>(quic_exception(quic_error::invalid_state, "stream output is unavailable"));
    }
    if (!_runtime) {
        return make_exception_future<>(quic_exception(quic_error::closed, "stream runtime is gone"));
    }
    if (_transport_closed || (_output_closed && !fin)) {
        return make_exception_future<>(quic_exception(quic_error::closed, "stream output is closed"));
    }
    return _runtime->send(internal::quic_message{
      .stream = _id,
      .payload = std::move(payload),
      .fin = fin,
    });
}

future<> stream_state::close_output() {
    if (!_can_write) {
        throw_quic_error(quic_error::invalid_state, "stream output is unavailable");
    }
    if (_output_closed) {
        co_return;
    }
    _output_closed = true;
    co_await send_one(temporary_buffer<char>(), true);
}

future<> stream_state::reset(application_error_code app_error_code) {
    if (!_can_write) {
        throw_quic_error(quic_error::invalid_state, "stream output is unavailable");
    }
    if (_output_closed) {
        co_return;
    }
    _output_closed = true;
    if (!_runtime) {
        co_return;
    }
    co_await _runtime->reset_stream(_id, app_error_code);
}

future<> stream_state::stop_sending(application_error_code app_error_code) {
    if (!_can_read) {
        throw_quic_error(quic_error::invalid_state, "stream input is unavailable");
    }
    if (_input_shutdown_notified) {
        co_return;
    }
    if (!_runtime) {
        co_return;
    }
    abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::closed, "stop_sending")));
    co_await _runtime->stop_sending(_id, app_error_code);
}

void stream_state::on_data(temporary_buffer<char> payload, bool fin) {
    if (_transport_closed) {
        return;
    }
    if (!payload.empty() && !push_read_fragment(std::move(payload))) {
        return;
    }
    if (fin) {
        notify_input_shutdown();
        (void)push_read_fragment(temporary_buffer<char>());
    }
}

void stream_state::on_reset(application_error_code) {
    abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::closed, "peer reset stream")));
}

void stream_state::on_transport_closed() {
    if (_transport_closed) {
        return;
    }
    _transport_closed = true;
    abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::closed, "transport closed")));
}

class stream_state::source_impl final : public data_source_impl {
public:
    explicit source_impl(shared_ptr<stream_state> state)
        : _state(std::move(state)) {
    }

    future<temporary_buffer<char>> get() override {
        return _state->_read_queue.pop_eventually();
    }

    future<> close() override {
        return _state->stop_sending(0);
    }

private:
    shared_ptr<stream_state> _state;
};

class stream_state::sink_impl final : public data_sink_impl {
public:
    explicit sink_impl(shared_ptr<stream_state> state)
        : _state(std::move(state)) {
    }

    future<> put(std::span<temporary_buffer<char>> bufs) override {
        std::vector<temporary_buffer<char>> owned;
        owned.reserve(bufs.size());
        for (auto& buf : bufs) {
            owned.push_back(std::move(buf));
        }
        return do_with(std::move(owned), [this] (auto& stable) {
            return do_for_each(stable, [this] (temporary_buffer<char>& buf) {
                return _state->send_one(std::move(buf), false);
            });
        });
    }

    future<> close() override {
        return _state->close_output();
    }

    size_t buffer_size() const noexcept override {
        return 8192;
    }

private:
    shared_ptr<stream_state> _state;
};

input_stream<char> stream_state::input(connected_socket_input_stream_config cfg) {
    if (!_can_read) {
        throw_quic_error(quic_error::invalid_state, "stream input is unavailable");
    }
    return input_stream<char>(source(cfg));
}

output_stream<char> stream_state::output(size_t buffer_size) {
    if (!_can_write) {
        throw_quic_error(quic_error::invalid_state, "stream output is unavailable");
    }
    return output_stream<char>(sink(), buffer_size);
}

data_source stream_state::source(connected_socket_input_stream_config) {
    if (!_can_read) {
        throw_quic_error(quic_error::invalid_state, "stream input is unavailable");
    }
    return data_source(std::make_unique<source_impl>(shared_from_this()));
}

data_sink stream_state::sink() {
    if (!_can_write) {
        throw_quic_error(quic_error::invalid_state, "stream output is unavailable");
    }
    return data_sink(std::make_unique<sink_impl>(shared_from_this()));
}

session_runtime_ptr make_session_runtime(connection_options options) {
    return make_shared<queue_session_runtime>(std::move(options));
}

} // namespace internal

namespace {

class quic_connected_socket_impl final : public net::connected_socket_impl {
public:
    explicit quic_connected_socket_impl(shared_ptr<internal::stream_state> state)
        : _state(std::move(state)) {
    }

    data_source source() override {
        return _state->source({});
    }

    data_source source(connected_socket_input_stream_config cfg) override {
        return _state->source(cfg);
    }

    data_sink sink() override {
        return _state->sink();
    }

    void shutdown_input() override {
        (void)_state->stop_sending(0);
    }

    void shutdown_output() override {
        (void)_state->close_output();
    }

    void set_nodelay(bool) override {
    }

    bool get_nodelay() const override {
        return true;
    }

    void set_keepalive(bool) override {
    }

    bool get_keepalive() const override {
        return false;
    }

    void set_keepalive_parameters(const net::keepalive_params&) override {
    }

    net::keepalive_params get_keepalive_parameters() const override {
        return net::tcp_keepalive_params{std::chrono::seconds(0), std::chrono::seconds(0), 0};
    }

    void set_sockopt(int, int, const void*, size_t) override {
    }

    int get_sockopt(int, int, void*, size_t) const override {
        return 0;
    }

    socket_address local_address() const noexcept override {
        return _state->local_address();
    }

    socket_address remote_address() const noexcept override {
        return _state->peer_address();
    }

    future<> wait_input_shutdown() override {
        return _state->wait_input_shutdown();
    }

private:
    shared_ptr<internal::stream_state> _state;
};

internal::connection_state_ptr make_connection_state(internal::session_runtime_ptr runtime) {
    auto state = make_shared<internal::connection_state>(std::move(runtime));
    state->start();
    return state;
}

} // namespace

stream::stream() = default;
stream::~stream() = default;
stream::stream(stream&&) noexcept = default;
stream& stream::operator=(stream&&) noexcept = default;

stream::stream(internal::stream_state_ptr state)
    : _state(std::move(state)) {
}

bool stream::is_open() const noexcept {
    return _state && _state->is_open();
}

bool stream::can_read() const noexcept {
    return _state && _state->can_read();
}

bool stream::can_write() const noexcept {
    return _state && _state->can_write();
}

stream_id stream::id() const noexcept {
    return _state ? _state->id() : invalid_stream_id;
}

stream_type stream::type() const noexcept {
    return _state ? _state->type() : stream_type::bidirectional;
}

input_stream<char> stream::input(connected_socket_input_stream_config cfg) {
    if (!_state) {
        throw_quic_error(quic_error::invalid_state, "stream state is null");
    }
    return _state->input(cfg);
}

output_stream<char> stream::output(size_t buffer_size) {
    if (!_state) {
        throw_quic_error(quic_error::invalid_state, "stream state is null");
    }
    return _state->output(buffer_size);
}

future<> stream::close_output() {
    if (!_state) {
        return make_exception_future<>(quic_exception(quic_error::invalid_state, "stream state is null"));
    }
    return _state->close_output();
}

future<> stream::reset(application_error_code app_error_code) {
    if (!_state) {
        return make_exception_future<>(quic_exception(quic_error::invalid_state, "stream state is null"));
    }
    return _state->reset(app_error_code);
}

future<> stream::stop_sending(application_error_code app_error_code) {
    if (!_state) {
        return make_exception_future<>(quic_exception(quic_error::invalid_state, "stream state is null"));
    }
    return _state->stop_sending(app_error_code);
}

future<> stream::wait_input_shutdown() {
    if (!_state) {
        return make_exception_future<>(quic_exception(quic_error::invalid_state, "stream state is null"));
    }
    return _state->wait_input_shutdown();
}

connection::connection() = default;

connection::connection(internal::session_runtime_ptr runtime)
    : _state(make_connection_state(std::move(runtime))) {
}

connection::connection(internal::connection_state_ptr state)
    : _state(std::move(state)) {
}

connection::~connection() = default;
connection::connection(connection&&) noexcept = default;
connection& connection::operator=(connection&&) noexcept = default;

bool connection::is_open() const noexcept {
    return _state && _state->is_open();
}

socket_address connection::local_address() const {
    return _state ? _state->local_address() : socket_address();
}

socket_address connection::peer_address() const {
    return _state ? _state->peer_address() : socket_address();
}

sstring connection::selected_alpn() const {
    return _state ? _state->selected_alpn() : sstring();
}

future<stream> connection::open_stream(stream_open_options options) {
    if (!_state) {
        return make_exception_future<stream>(quic_exception(quic_error::invalid_state, "connection state is null"));
    }
    return _state->open_stream(options);
}

future<stream> connection::accept_stream() {
    if (!_state) {
        return make_exception_future<stream>(quic_exception(quic_error::invalid_state, "connection state is null"));
    }
    return _state->accept_stream();
}

future<> connection::close() {
    if (!_state) {
        co_return;
    }
    co_await _state->close();
}

connected_socket to_connected_socket(stream&& s) {
    if (!s._state) {
        throw_quic_error(quic_error::invalid_state, "stream state is null");
    }
    if (!s._state->can_read() || !s._state->can_write()) {
        throw_quic_error(quic_error::invalid_state, "connected_socket requires a bidirectional stream");
    }
    return connected_socket(std::make_unique<quic_connected_socket_impl>(std::move(s._state)));
}

} // namespace seastar::quic::experimental
