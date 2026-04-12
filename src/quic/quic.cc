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

#include <deque>
#include <exception>
#include <utility>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/shared_ptr.hh>

namespace seastar::quic::experimental {

namespace {

using transport_command = internal::transport_command;

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
        while (send_requires_wait(msg_size)) {
            throw_if_terminal("send");
            co_await _command_space_cv.wait();
        }
        throw_if_terminal("send");

        _pending_send_bytes += msg_size;
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::send,
          .msg = std::move(msg),
        });
        notify_command_ready();
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
        notify_command_ready();
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
        notify_command_ready();
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
        notify_command_ready();
        co_return;
    }

    future<> close() override {
        if (_closing || _closed) {
            co_return;
        }
        _closing = true;
        notify_terminal_waiters();
        _commands.emplace_back(transport_command{
          .op = transport_command::kind::close_connection,
        });
        notify_command_ready();
        co_return;
    }

    bool has_pending_commands() const noexcept override {
        return !_commands.empty();
    }

    std::optional<transport_command> poll_command() override {
        if (_commands.empty()) {
            return std::nullopt;
        }
        auto cmd = std::move(_commands.front());
        _commands.pop_front();
        if (_commands.empty()) {
            _command_ready_notification_pending = false;
        }
        if (cmd.op == transport_command::kind::send) {
            _pending_send_bytes -= cmd.msg.payload.size();
            _command_space_cv.signal();
        }
        return cmd;
    }

    void set_command_notifier(std::function<void()> notifier) override {
        _command_notifier = std::move(notifier);
        if (_command_notifier && _command_ready_notification_pending) {
            _command_notifier();
        }
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
        notify_terminal_waiters();
    }

    void mark_error(quic_error error, sstring detail) override {
        if (_error != quic_error::none) {
            return;
        }
        _error = error;
        _error_detail = std::move(detail);
        _closed = true;
        drain_pending_open_streams(std::make_exception_ptr(quic_exception(_error, _error_detail)));
        notify_terminal_waiters();
    }

private:
    bool send_requires_wait(size_t msg_size) const noexcept {
        const auto limit = _options.max_pending_send_bytes;
        if (!limit) {
            return false;
        }
        if (msg_size > limit) {
            return _pending_send_bytes != 0;
        }
        return _pending_send_bytes > limit - msg_size;
    }

    void throw_if_terminal(const char* op) const {
        if (_error != quic_error::none) {
            throw quic_exception(_error, sstring(op) + ": " + _error_detail);
        }
        if (_closed) {
            throw quic_exception(quic_error::closed, sstring(op) + ": transport closed");
        }
        if (_closing) {
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

    void notify_command_ready() {
        if (_command_ready_notification_pending) {
            return;
        }
        _command_ready_notification_pending = true;
        if (_command_notifier) {
            _command_notifier();
        }
    }

    void notify_terminal_waiters() noexcept {
        _command_space_cv.broadcast();
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
    size_t _pending_send_bytes = 0;
    std::function<void()> _command_notifier;
    bool _command_ready_notification_pending = false;

    condition_variable _command_space_cv;
};

} // namespace

namespace internal {

session_runtime_ptr make_session_runtime(connection_options options) {
    return make_shared<queue_session_runtime>(std::move(options));
}

} // namespace internal

} // namespace seastar::quic::experimental
