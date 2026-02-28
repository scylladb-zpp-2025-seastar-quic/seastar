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
#include <seastar/util/log.hh>

namespace seastar::quic::experimental {

namespace {

static logger quic_rt_log("quic_runtime");

class basic_session_runtime final : public internal::session_runtime {
public:
    explicit basic_session_runtime(connection_options options)
        : _options(std::move(options))
        , _default_stream(_options.initial_stream_id) {
        quic_rt_log.debug(
          "session runtime created: initial_stream_id={} tx_limit={} rx_limit={} idle_timeout_ns={} max_data={} max_streams_bidi={}",
          _options.initial_stream_id,
          _options.max_pending_send_bytes,
          _options.max_pending_receive_bytes,
          _options.transport.max_idle_timeout_ns,
          _options.transport.initial_max_data,
          _options.transport.initial_max_streams_bidi);
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

        quic_rt_log.trace(
          "send request: sid={} bytes={} fin={} pending_tx_bytes={} tx_queue_len={}",
          msg.stream,
          msg_size,
          msg.fin,
          _pending_tx_bytes,
          _txq.size());

        while (is_open() && _options.max_pending_send_bytes &&
               _pending_tx_bytes + msg_size > _options.max_pending_send_bytes) {
            quic_rt_log.debug(
              "send waiting for tx space: sid={} bytes={} pending_tx_bytes={} limit={} tx_queue_len={}",
              msg.stream,
              msg_size,
              _pending_tx_bytes,
              _options.max_pending_send_bytes,
              _txq.size());
            co_await _tx_space_cv.wait();
        }

        throw_if_terminal("send");

        _pending_tx_bytes += msg_size;
        _txq.push_back(std::move(msg));
        _tx_cv.signal();
        quic_rt_log.trace(
          "send enqueued: pending_tx_bytes={} tx_queue_len={}",
          _pending_tx_bytes,
          _txq.size());
        co_return;
    }

    future<quic_message> receive() override {
        while (_rxq.empty()) {
            quic_rt_log.trace(
              "receive waiting: pending_rx_bytes={} rx_queue_len={} closed={} error={}",
              _pending_rx_bytes,
              _rxq.size(),
              _closed,
              to_string(_error));
            throw_if_terminal("receive");
            co_await _rx_cv.wait();
        }

        auto msg = std::move(_rxq.front());
        _rxq.pop_front();
        _pending_rx_bytes -= msg.payload.size();
        _rx_space_cv.signal();

        quic_rt_log.trace(
          "receive dequeued: sid={} bytes={} fin={} pending_rx_bytes={} rx_queue_len={}",
          msg.stream,
          msg.payload.size(),
          msg.fin,
          _pending_rx_bytes,
          _rxq.size());

        co_return msg;
    }

    future<> close() override {
        if (_closed) {
            quic_rt_log.debug("close ignored: runtime already closed");
            co_return;
        }

        quic_rt_log.info(
          "closing session runtime: pending_tx_bytes={} pending_rx_bytes={} tx_queue_len={} rx_queue_len={}",
          _pending_tx_bytes,
          _pending_rx_bytes,
          _txq.size(),
          _rxq.size());
        _closed = true;
        _tx_cv.signal();
        _rx_cv.signal();
        _tx_space_cv.signal();
        _rx_space_cv.signal();
        co_return;
    }

    future<quic_message> pop_outgoing() override {
        while (_txq.empty()) {
            quic_rt_log.trace(
              "pop_outgoing waiting: pending_tx_bytes={} tx_queue_len={} closed={} error={}",
              _pending_tx_bytes,
              _txq.size(),
              _closed,
              to_string(_error));
            throw_if_terminal("pop_outgoing");
            co_await _tx_cv.wait();
        }

        auto msg = std::move(_txq.front());
        _txq.pop_front();
        _pending_tx_bytes -= msg.payload.size();
        _tx_space_cv.signal();

        quic_rt_log.trace(
          "pop_outgoing dequeued: sid={} bytes={} fin={} pending_tx_bytes={} tx_queue_len={}",
          msg.stream,
          msg.payload.size(),
          msg.fin,
          _pending_tx_bytes,
          _txq.size());

        co_return msg;
    }

    void push_incoming(quic_message msg) override {
        if (!is_open()) {
            quic_rt_log.trace(
              "drop incoming message on closed runtime: sid={} bytes={} fin={} error={} closed={}",
              msg.stream,
              msg.payload.size(),
              msg.fin,
              to_string(_error),
              _closed);
            return;
        }

        auto msg_size = msg.payload.size();
        if (_options.max_pending_receive_bytes &&
            _pending_rx_bytes + msg_size > _options.max_pending_receive_bytes) {
            quic_rt_log.warn(
              "incoming queue limit exceeded: sid={} bytes={} pending_rx_bytes={} limit={} rx_queue_len={}",
              msg.stream,
              msg_size,
              _pending_rx_bytes,
              _options.max_pending_receive_bytes,
              _rxq.size());
            mark_error(quic_error::io, "receive queue limit exceeded");
            return;
        }

        _pending_rx_bytes += msg_size;
        _rxq.push_back(std::move(msg));
        _rx_cv.signal();
        quic_rt_log.trace(
          "incoming message queued: pending_rx_bytes={} rx_queue_len={}",
          _pending_rx_bytes,
          _rxq.size());
    }

    void mark_ready(stream_id sid) override {
        quic_rt_log.debug("default stream updated: {} -> {}", _default_stream, sid);
        _default_stream = sid;
    }

    void mark_transport_closed() override {
        if (_closed) {
            quic_rt_log.debug("mark_transport_closed ignored: runtime already closed");
            return;
        }

        quic_rt_log.info(
          "transport closed: pending_tx_bytes={} pending_rx_bytes={} tx_queue_len={} rx_queue_len={}",
          _pending_tx_bytes,
          _pending_rx_bytes,
          _txq.size(),
          _rxq.size());
        _closed = true;
        _tx_cv.signal();
        _rx_cv.signal();
        _tx_space_cv.signal();
        _rx_space_cv.signal();
    }

    void mark_error(quic_error error, sstring detail) override {
        if (_error != quic_error::none) {
            quic_rt_log.debug(
              "ignoring duplicate runtime error: current_error={} new_error={} new_detail={}",
              to_string(_error),
              to_string(error),
              detail);
            return;
        }

        quic_rt_log.error(
          "runtime error: error={} detail='{}' pending_tx_bytes={} pending_rx_bytes={} tx_queue_len={} rx_queue_len={}",
          to_string(error),
          detail,
          _pending_tx_bytes,
          _pending_rx_bytes,
          _txq.size(),
          _rxq.size());
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
            quic_rt_log.debug("operation '{}' aborted due to error: {}", op, _error_detail);
            throw quic_exception(_error, std::string(op) + ": " + _error_detail);
        }
        if (_closed) {
            quic_rt_log.debug("operation '{}' aborted: session closed", op);
            throw quic_exception(quic_error::closed, std::string(op) + ": session closed");
        }
    }

    connection_options _options;
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

session_runtime_ptr make_session_runtime(connection_options options) {
    quic_rt_log.debug("make_session_runtime called");
    return seastar::make_shared<basic_session_runtime>(std::move(options));
}

} // namespace internal

connection::connection()
    : _runtime(internal::make_session_runtime()) {
    quic_rt_log.debug("connection created with default runtime");
}

connection::connection(internal::session_runtime_ptr runtime)
    : _runtime(std::move(runtime)) {
    if (!_runtime) {
        quic_rt_log.warn("connection created with null runtime, creating fallback runtime");
        _runtime = internal::make_session_runtime();
    }
    quic_rt_log.debug("connection created with runtime={}", static_cast<bool>(_runtime));
}

connection::~connection() = default;
connection::connection(connection&&) noexcept = default;
connection& connection::operator=(connection&&) noexcept = default;

bool connection::is_open() const noexcept {
    return _runtime && _runtime->is_open();
}

stream_id connection::default_stream() const noexcept {
    if (!_runtime) {
        return invalid_stream_id;
    }
    return _runtime->default_stream();
}

future<> connection::send(quic_message msg) {
    if (!_runtime) {
        throw_quic_error(quic_error::invalid_state, "session runtime is null");
    }
    quic_rt_log.trace("connection::send sid={} bytes={} fin={}", msg.stream, msg.payload.size(), msg.fin);
    return _runtime->send(std::move(msg));
}

future<> connection::send(stream_id sid, temporary_buffer<char> payload, bool fin) {
    return send(quic_message(sid, std::move(payload), fin));
}

future<> connection::send(stream_id sid, sstring payload, bool fin) {
    temporary_buffer<char> tb(payload.size());
    std::memcpy(tb.get_write(), payload.data(), payload.size());
    return send(quic_message(sid, std::move(tb), fin));
}

future<quic_message> connection::receive() {
    if (!_runtime) {
        throw_quic_error(quic_error::invalid_state, "session runtime is null");
    }
    quic_rt_log.trace("connection::receive");
    return _runtime->receive();
}

future<> connection::close() {
    if (!_runtime) {
        quic_rt_log.debug("connection::close ignored: runtime is null");
        co_return;
    }
    quic_rt_log.info("connection::close");
    co_await _runtime->close();
}

internal::session_runtime_ptr connection::runtime() const noexcept {
    return _runtime;
}

} // namespace seastar::quic::experimental
