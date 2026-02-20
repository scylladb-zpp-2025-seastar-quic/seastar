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

#include <cstring>
#include <deque>
#include <string>
#include <utility>

#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>

namespace seastar::quic::experimental {

namespace {

class basic_session_runtime final : public internal::session_runtime {
public:
    explicit basic_session_runtime(quic_session_options options)
        : _options(std::move(options))
        , _default_stream(_options.initial_stream_id) {
    }

    bool is_open() const noexcept override {
        return !_closed && _error == quic_error::none;
    }

    stream_id default_stream() const noexcept override {
        return _default_stream;
    }

    future<> send(quic_message msg) override {
        auto msg_size = msg.payload.size();

        if (msg.stream == invalid_stream_id) {
            msg.stream = _default_stream;
        }

        while (is_open() && _options.max_pending_send_bytes &&
               _pending_tx_bytes + msg_size > _options.max_pending_send_bytes) {
            co_await _tx_space_cv.wait();
        }

        throw_if_terminal("send");

        _pending_tx_bytes += msg_size;
        _txq.push_back(std::move(msg));
        _tx_cv.signal();
        co_return;
    }

    future<quic_message> receive() override {
        while (_rxq.empty()) {
            throw_if_terminal("receive");
            co_await _rx_cv.wait();
        }

        auto msg = std::move(_rxq.front());
        _rxq.pop_front();
        _pending_rx_bytes -= msg.payload.size();
        _rx_space_cv.signal();

        co_return msg;
    }

    future<> close() override {
        if (_closed) {
            co_return;
        }

        _closed = true;
        _tx_cv.signal();
        _rx_cv.signal();
        _tx_space_cv.signal();
        _rx_space_cv.signal();
        co_return;
    }

    future<quic_message> pop_outgoing() override {
        while (_txq.empty()) {
            throw_if_terminal("pop_outgoing");
            co_await _tx_cv.wait();
        }

        auto msg = std::move(_txq.front());
        _txq.pop_front();
        _pending_tx_bytes -= msg.payload.size();
        _tx_space_cv.signal();

        co_return msg;
    }

    void push_incoming(quic_message msg) override {
        if (!is_open()) {
            return;
        }

        auto msg_size = msg.payload.size();
        if (_options.max_pending_receive_bytes &&
            _pending_rx_bytes + msg_size > _options.max_pending_receive_bytes) {
            mark_error(quic_error::io, "receive queue limit exceeded");
            return;
        }

        _pending_rx_bytes += msg_size;
        _rxq.push_back(std::move(msg));
        _rx_cv.signal();
    }

    void mark_ready(stream_id sid) override {
        _default_stream = sid;
    }

    void mark_transport_closed() override {
        if (_closed) {
            return;
        }

        _closed = true;
        _tx_cv.signal();
        _rx_cv.signal();
        _tx_space_cv.signal();
        _rx_space_cv.signal();
    }

    void mark_error(quic_error error, sstring detail) override {
        if (_error != quic_error::none) {
            return;
        }

        _error = error;
        _error_detail = std::string(detail);
        _closed = true;
        _tx_cv.signal();
        _rx_cv.signal();
        _tx_space_cv.signal();
        _rx_space_cv.signal();
    }

private:
    void throw_if_terminal(const char* op) const {
        if (_error != quic_error::none) {
            throw quic_exception(_error, std::string(op) + ": " + _error_detail);
        }
        if (_closed) {
            throw quic_exception(quic_error::closed, std::string(op) + ": session closed");
        }
    }

    quic_session_options _options;
    stream_id _default_stream = 0;
    bool _closed = false;
    quic_error _error = quic_error::none;
    std::string _error_detail;

    std::deque<quic_message> _txq;
    std::deque<quic_message> _rxq;
    size_t _pending_tx_bytes = 0;
    size_t _pending_rx_bytes = 0;

    condition_variable _tx_cv;
    condition_variable _rx_cv;
    condition_variable _tx_space_cv;
    condition_variable _rx_space_cv;
};

} // namespace

namespace internal {

session_runtime_ptr make_session_runtime(quic_session_options options) {
    return std::make_shared<basic_session_runtime>(std::move(options));
}

} // namespace internal

quic_session::quic_session()
    : _runtime(internal::make_session_runtime()) {
}

quic_session::quic_session(internal::session_runtime_ptr runtime)
    : _runtime(std::move(runtime)) {
    if (!_runtime) {
        _runtime = internal::make_session_runtime();
    }
}

quic_session::~quic_session() = default;
quic_session::quic_session(quic_session&&) noexcept = default;
quic_session& quic_session::operator=(quic_session&&) noexcept = default;

bool quic_session::is_open() const noexcept {
    return _runtime && _runtime->is_open();
}

stream_id quic_session::default_stream() const noexcept {
    if (!_runtime) {
        return invalid_stream_id;
    }
    return _runtime->default_stream();
}

future<> quic_session::send(quic_message msg) {
    if (!_runtime) {
        throw_quic_error(quic_error::invalid_state, "session runtime is null");
    }
    return _runtime->send(std::move(msg));
}

future<> quic_session::send(stream_id sid, temporary_buffer<char> payload, bool fin) {
    return send(quic_message(sid, std::move(payload), fin));
}

future<> quic_session::send(stream_id sid, sstring payload, bool fin) {
    temporary_buffer<char> tb(payload.size());
    std::memcpy(tb.get_write(), payload.data(), payload.size());
    return send(quic_message(sid, std::move(tb), fin));
}

future<quic_message> quic_session::receive() {
    if (!_runtime) {
        throw_quic_error(quic_error::invalid_state, "session runtime is null");
    }
    return _runtime->receive();
}

future<> quic_session::close() {
    if (!_runtime) {
        co_return;
    }
    co_await _runtime->close();
}

internal::session_runtime_ptr quic_session::runtime() const noexcept {
    return _runtime;
}

} // namespace seastar::quic::experimental
