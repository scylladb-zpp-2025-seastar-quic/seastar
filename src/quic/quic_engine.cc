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
#include <cstring>
#include <deque>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>

#include <ngtcp2/ngtcp2.h>

#include <seastar/coroutine/maybe_yield.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/util/later.hh>
#include <seastar/net/stack.hh>

namespace seastar::quic::experimental {

namespace internal {

namespace {

uint64_t transport_now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

future<> flush_transport_batch(connection_transport& transport, bool rearm_timer = true) {
    if (!transport.has_transport_connection()) {
        co_return;
    }

    co_await flush_pending_transport_packets(transport);
    if (transport.has_queued_datagram_packets()) {
        co_await transport.flush_datagram_packets();
    }
    if (rearm_timer) {
        transport.rearm_transport_timer();
    }
}

} // namespace

class receive_budget final : public enable_shared_from_this<receive_budget> {
public:
    explicit receive_budget(size_t limit)
        : _limit(limit) {
    }

    bool try_acquire(size_t size) {
        if (!size) {
            return true;
        }
        if (_limit && _pending_bytes + size > _limit) {
            return false;
        }
        _pending_bytes += size;
        return true;
    }

    void release(size_t size) {
        if (!size) {
            return;
        }
        if (size >= _pending_bytes) {
            _pending_bytes = 0;
            return;
        }
        _pending_bytes -= size;
    }

private:
    size_t _limit = 0;
    size_t _pending_bytes = 0;
};

class stream_state final : public enable_shared_from_this<stream_state> {
    class source_impl;
    class sink_impl;

    public:
        stream_state(
          session_runtime_ptr runtime,
          std::shared_ptr<transport_debug_stats> debug_stats,
          shared_ptr<receive_budget> receive_budget,
          stream_id sid,
          stream_type type,
          bool peer_initiated)
            : _runtime(std::move(runtime))
            , _debug_stats(std::move(debug_stats))
            , _receive_budget(std::move(receive_budget))
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

    bool mark_accepted_for_delivery() noexcept {
        if (_accepted_for_delivery) {
            return false;
        }
        _accepted_for_delivery = true;
        return true;
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
    void on_stop_sending_input(application_error_code app_error_code);
    void on_stop_sending_output(application_error_code app_error_code);
    void on_batch_flush_error() noexcept;
    void on_transport_closed();

private:
    future<> send_one(temporary_buffer<char> payload, bool fin);

    bool push_read_fragment(temporary_buffer<char> payload) {
        const auto payload_size = payload.size();
        if (payload_size && _receive_budget && !_receive_budget->try_acquire(payload_size)) {
            abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::io, "receive queue limit exceeded")));
            if (_runtime) {
                _runtime->mark_error(quic_error::io, "receive queue limit exceeded");
            }
            return false;
        }
        if (_read_queue.push(std::move(payload))) {
            _queued_read_bytes += payload_size;
            return true;
        }
        if (payload_size && _receive_budget) {
            _receive_budget->release(payload_size);
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

    void release_queued_read_bytes() {
        if (_queued_read_bytes && _receive_budget) {
            _receive_budget->release(_queued_read_bytes);
        }
        _queued_read_bytes = 0;
    }

    void release_read_bytes(size_t size) {
        if (!size) {
            return;
        }
        if (_queued_read_bytes >= size) {
            _queued_read_bytes -= size;
        } else {
            _queued_read_bytes = 0;
        }
        if (_receive_budget) {
            _receive_budget->release(size);
        }
    }

    void abort_read_queue(std::exception_ptr ex) {
        release_queued_read_bytes();
        _read_queue.abort(ex);
        notify_input_shutdown();
    }

    session_runtime_ptr _runtime;
    std::shared_ptr<transport_debug_stats> _debug_stats;
    shared_ptr<receive_budget> _receive_budget;
    stream_id _id = invalid_stream_id;
    stream_type _type = stream_type::bidirectional;
    bool _can_read = true;
    bool _can_write = true;

    // Receive backpressure is already enforced by _receive_budget in bytes.
    // A small fixed fragment-count cap overflows single bidi streams when
    // larger UDP payloads are enabled, even though the byte budget still has room.
    queue<temporary_buffer<char>> _read_queue{std::numeric_limits<size_t>::max()};
    shared_promise<> _input_shutdown;
    bool _input_shutdown_notified = false;
    bool _output_closed = false;
    bool _transport_closed = false;
    bool _accepted_for_delivery = false;
    size_t _queued_read_bytes = 0;
};

class connection_engine::impl {
public:
    impl(session_runtime_ptr runtime_arg, connection_options options_arg)
        : runtime(std::move(runtime_arg))
        , options(std::move(options_arg))
        , accepted_streams(1024)
        , receive_window(make_shared<receive_budget>(options.max_pending_receive_bytes)) {
        _timer.set_callback([this] {
            if (transport_closed || tick_pending) {
                return;
            }
            tick_pending = true;
            if (!actor_waiter) {
                return;
            }
            auto waiter = std::move(*actor_waiter);
            actor_waiter.reset();
            waiter.set_value();
        });
    }

    session_runtime_ptr runtime;
    connection_options options;
    std::shared_ptr<transport_debug_stats> debug_stats;
    queue<shared_ptr<stream_state>> accepted_streams;
    std::unordered_map<stream_id, shared_ptr<stream_state>> streams;
    shared_ptr<receive_budget> receive_window;
    bool transport_closed = false;

    std::deque<transport_command> blocked_bidi_open_streams;
    std::deque<transport_command> blocked_uni_open_streams;
    std::optional<promise<>> actor_waiter;
    timer<> _timer;
    bool tick_pending = false;
    bool blocked_bidi_open_stream_retry_pending = false;
    bool blocked_uni_open_stream_retry_pending = false;
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

void stream_state::on_stop_sending_input(application_error_code) {
    if (!_can_read || _input_shutdown_notified) {
        return;
    }
    abort_read_queue(std::make_exception_ptr(quic_exception(quic_error::closed, "stop_sending")));
}

void stream_state::on_stop_sending_output(application_error_code) {
    if (!_can_write || _output_closed) {
        return;
    }
    _output_closed = true;
}

void stream_state::on_batch_flush_error() noexcept {
    _output_closed = true;
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
        auto buf = co_await _state->_read_queue.pop_eventually();
        _state->release_read_bytes(buf.size());
        co_return std::move(buf);
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
        if (bufs.empty()) {
            return make_ready_future<>();
        }
        size_t total = 0;
        for (const auto& buf : bufs) {
            total += buf.size();
        }

        if (bufs.size() > 1 && _state->_debug_stats) {
            _state->_debug_stats->tx_copy_bytes += total;
            ++_state->_debug_stats->tx_copy_events;
        }

        if (bufs.size() == 1) {
            return _state->send_one(std::move(bufs.front()), false);
        }

        temporary_buffer<char> merged(total);
        auto* dst = merged.get_write();
        size_t offset = 0;
        for (auto& buf : bufs) {
            std::memcpy(dst + offset, buf.get(), buf.size());
            offset += buf.size();
        }
        return _state->send_one(std::move(merged), false);
    }

    future<> close() override {
        return _state->close_output();
    }

    size_t buffer_size() const noexcept override {
        return 8192;
    }

    bool can_batch_flushes() const noexcept override {
        return true;
    }

    void on_batch_flush_error() noexcept override {
        _state->on_batch_flush_error();
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
    if (_output_closed) {
        throw_quic_error(quic_error::closed, "stream output is closed");
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
    if (_output_closed) {
        throw_quic_error(quic_error::closed, "stream output is closed");
    }
    return data_sink(std::make_unique<sink_impl>(shared_from_this()));
}

connection_engine::connection_engine(
  session_runtime_ptr runtime,
  connection_options options,
  std::shared_ptr<transport_debug_stats> debug_stats)
    : _impl(std::make_unique<impl>(std::move(runtime), std::move(options))) {
    _impl->debug_stats = std::move(debug_stats);
}

connection_engine::~connection_engine() = default;

bool connection_engine::is_open() const noexcept {
    return _impl->runtime && _impl->runtime->is_open();
}

socket_address connection_engine::local_address() const {
    return _impl->runtime ? _impl->runtime->local_address() : socket_address();
}

socket_address connection_engine::peer_address() const {
    return _impl->runtime ? _impl->runtime->peer_address() : socket_address();
}

sstring connection_engine::selected_alpn() const {
    return _impl->runtime ? _impl->runtime->selected_alpn() : sstring();
}

future<stream> connection_engine::open_stream(stream_open_options options) {
    auto sid = co_await _impl->runtime->open_stream(options.type);
    auto [it, inserted] = _impl->streams.emplace(sid, shared_ptr<stream_state>{});
    if (inserted || !it->second) {
        it->second = seastar::make_shared<stream_state>(
          _impl->runtime,
          _impl->debug_stats,
          _impl->receive_window,
          sid,
          options.type,
          false);
    }
    auto st = it->second;
    co_return stream(std::move(st));
}

future<stream> connection_engine::accept_stream() {
    auto st = co_await _impl->accepted_streams.pop_eventually();
    co_return stream(std::move(st));
}

future<> connection_engine::close() {
    if (!_impl->runtime) {
        co_return;
    }
    co_await _impl->runtime->close();
}

void connection_engine::on_stream_data(stream_id sid, stream_type type, bool peer_initiated, temporary_buffer<char> payload, bool fin) {
    auto [it, inserted] = _impl->streams.emplace(sid, shared_ptr<stream_state>{});
    if (inserted || !it->second) {
        it->second = seastar::make_shared<stream_state>(
          _impl->runtime,
          _impl->debug_stats,
          _impl->receive_window,
          sid,
          type,
          peer_initiated);
    }
    auto st = it->second;
    if (peer_initiated && st->mark_accepted_for_delivery()) {
        if (!_impl->accepted_streams.push(shared_ptr<stream_state>(st)) && _impl->runtime) {
            _impl->runtime->mark_error(quic_error::io, "accepted stream queue is full");
        }
    }
    st->on_data(std::move(payload), fin);
}

void connection_engine::on_stream_reset(
  stream_id sid,
  stream_type type,
  bool peer_initiated,
  application_error_code app_error_code) {
    auto [it, inserted] = _impl->streams.emplace(sid, shared_ptr<stream_state>{});
    if (inserted || !it->second) {
        it->second = seastar::make_shared<stream_state>(
          _impl->runtime,
          _impl->debug_stats,
          _impl->receive_window,
          sid,
          type,
          peer_initiated);
    }
    auto st = it->second;
    if (peer_initiated && st->mark_accepted_for_delivery()) {
        if (!_impl->accepted_streams.push(shared_ptr<stream_state>(st)) && _impl->runtime) {
            _impl->runtime->mark_error(quic_error::io, "accepted stream queue is full");
        }
    }
    st->on_reset(app_error_code);
}

void connection_engine::on_stream_stop_sending(
  stream_id sid,
  stream_type type,
  bool peer_initiated,
  application_error_code app_error_code,
  stream_shutdown_side shutdown_side) {
    auto [it, inserted] = _impl->streams.emplace(sid, shared_ptr<stream_state>{});
    if (inserted || !it->second) {
        it->second = seastar::make_shared<stream_state>(
          _impl->runtime,
          _impl->debug_stats,
          _impl->receive_window,
          sid,
          type,
          peer_initiated);
    }
    auto st = it->second;
    if (peer_initiated && st->mark_accepted_for_delivery()) {
        if (!_impl->accepted_streams.push(shared_ptr<stream_state>(st)) && _impl->runtime) {
            _impl->runtime->mark_error(quic_error::io, "accepted stream queue is full");
        }
    }
    if (shutdown_side == stream_shutdown_side::write) {
        st->on_stop_sending_output(app_error_code);
    } else {
        st->on_stop_sending_input(app_error_code);
    }
}

void connection_engine::on_stream_closed(stream_id sid) {
    _impl->streams.erase(sid);
}

void connection_engine::on_transport_closed(std::exception_ptr ex) {
    if (_impl->transport_closed) {
        return;
    }
    _impl->transport_closed = true;
    _impl->_timer.cancel();
    if (!ex) {
        ex = std::make_exception_ptr(quic_exception(quic_error::closed, "transport closed"));
    }
    _impl->accepted_streams.abort(ex);
    for (auto& [_, st] : _impl->streams) {
        st->on_transport_closed();
    }
    _impl->streams.clear();
}

future<> connection_engine::wait_for_actor_wakeup(bool has_pending_work, bool closing) {
    if (has_pending_work || closing) {
        co_return;
    }
    _impl->actor_waiter.emplace();
    try {
        co_await _impl->actor_waiter->get_future();
    } catch (...) {
    }
    co_return;
}

void connection_engine::wake_actor() {
    if (!_impl->actor_waiter) {
        return;
    }
    auto waiter = std::move(*_impl->actor_waiter);
    _impl->actor_waiter.reset();
    waiter.set_value();
}

void connection_engine::arm_timer(std::chrono::nanoseconds delay, bool closing) {
    if (closing || _impl->transport_closed) {
        _impl->_timer.cancel();
        return;
    }
    if (delay <= std::chrono::nanoseconds::zero()) {
        _impl->_timer.cancel();
        if (_impl->tick_pending) {
            return;
        }
        _impl->tick_pending = true;
        wake_actor();
        return;
    }
    _impl->_timer.cancel();
    _impl->_timer.arm(delay);
}

void connection_engine::rearm_timer_from_expiry(uint64_t expiry_ns, uint64_t now_ns, bool closing) {
    constexpr auto max_timer_sleep = std::chrono::hours(24);
    if (expiry_ns <= now_ns) {
        arm_timer(std::chrono::nanoseconds(0), closing);
        return;
    }
    auto wait_ns = expiry_ns - now_ns;
    auto max_wait_ns = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(max_timer_sleep).count());
    auto sleep_ns = wait_ns > max_wait_ns ? max_wait_ns : wait_ns;
    arm_timer(std::chrono::nanoseconds(sleep_ns), closing);
}

bool connection_engine::tick_pending() const noexcept {
    return _impl->tick_pending;
}

void connection_engine::clear_tick() noexcept {
    _impl->tick_pending = false;
}

void connection_engine::cancel_timer() noexcept {
    _impl->_timer.cancel();
}

void connection_engine::defer_blocked_open_stream(transport_command cmd) {
    auto& q = cmd.type == stream_type::bidirectional
                ? _impl->blocked_bidi_open_streams
                : _impl->blocked_uni_open_streams;
    q.push_back(std::move(cmd));
}

std::optional<transport_command> connection_engine::pop_blocked_open_stream(stream_type type) {
    auto& q = type == stream_type::bidirectional
                ? _impl->blocked_bidi_open_streams
                : _impl->blocked_uni_open_streams;
    if (q.empty()) {
        return std::nullopt;
    }
    auto cmd = std::move(q.front());
    q.pop_front();
    return cmd;
}

void connection_engine::request_blocked_open_stream_retry(stream_type type) {
    auto& pending = type == stream_type::bidirectional
                      ? _impl->blocked_bidi_open_stream_retry_pending
                      : _impl->blocked_uni_open_stream_retry_pending;
    pending = true;
    wake_actor();
}

bool connection_engine::blocked_open_stream_retry_pending(stream_type type) const noexcept {
    return type == stream_type::bidirectional
             ? _impl->blocked_bidi_open_stream_retry_pending
             : _impl->blocked_uni_open_stream_retry_pending;
}

void connection_engine::clear_blocked_open_stream_retry(stream_type type) noexcept {
    auto& pending = type == stream_type::bidirectional
                      ? _impl->blocked_bidi_open_stream_retry_pending
                      : _impl->blocked_uni_open_stream_retry_pending;
    pending = false;
}

bool connection_engine::has_blocked_open_stream_retry_work() const noexcept {
    return (_impl->blocked_bidi_open_stream_retry_pending && !_impl->blocked_bidi_open_streams.empty())
           || (_impl->blocked_uni_open_stream_retry_pending && !_impl->blocked_uni_open_streams.empty());
}

void connection_engine::fail_blocked_open_streams(quic_error error, std::string_view detail) {
    if (!_impl->runtime) {
        _impl->blocked_bidi_open_streams.clear();
        _impl->blocked_uni_open_streams.clear();
        _impl->blocked_bidi_open_stream_retry_pending = false;
        _impl->blocked_uni_open_stream_retry_pending = false;
        return;
    }

    auto fail_queue = [this, error, detail] (auto& q) {
        for (auto& cmd : q) {
            _impl->runtime->fail_open_stream(cmd.open_result, error, sstring(detail));
        }
        q.clear();
    };

    fail_queue(_impl->blocked_bidi_open_streams);
    fail_queue(_impl->blocked_uni_open_streams);
    _impl->blocked_bidi_open_stream_retry_pending = false;
    _impl->blocked_uni_open_stream_retry_pending = false;
}

future<> flush_pending_transport_packets(connection_transport& transport) {
    if (!transport.has_transport_connection()) {
        co_return;
    }

    temporary_buffer<char> outbuf;
    while (transport.transport_active()) {
        if (!outbuf) {
            outbuf = transport.acquire_tx_packet_buffer();
        }
        auto nwrite = transport.write_pending_packet(
          reinterpret_cast<uint8_t*>(outbuf.get_write()),
          outbuf.size());
        if (nwrite == 0) {
            co_return;
        }
        if (nwrite < 0) {
            if (ngtcp2_is_write_more(static_cast<int>(nwrite))) {
                continue;
            }
            if (ngtcp2_is_draining(static_cast<int>(nwrite))) {
                transport.stop_transport();
                co_return;
            }
            transport.fail_transport(
              classify_ngtcp2_error(static_cast<int>(nwrite)),
              ngtcp2_error_message(static_cast<int>(nwrite)));
            co_return;
        }
        co_await transport.send_datagram_packet(std::move(outbuf), static_cast<size_t>(nwrite));
    }
}

future<> send_stream_message(connection_transport& transport, connection_actor& actor, blocked_send_state state) {
    if (!transport.has_transport_connection() || state.msg.stream == invalid_stream_id) {
        co_return;
    }

    if (state.offset == 0 && state.msg.fin && !state.send_fin) {
        state.send_fin = true;
    }

    temporary_buffer<char> outbuf;
    while (transport.transport_active()) {
        if (!outbuf) {
            outbuf = transport.acquire_tx_packet_buffer();
        }
        const bool remaining = state.offset < state.msg.payload.size();
        if (!remaining && !state.send_fin) {
            break;
        }

        auto* ptr = remaining ? (state.msg.payload.get() + state.offset) : nullptr;
        auto len = remaining ? (state.msg.payload.size() - state.offset) : 0;
        auto result = transport.write_stream_packet(
          state.msg.stream,
          ptr,
          len,
          state.send_fin,
          reinterpret_cast<uint8_t*>(outbuf.get_write()),
          outbuf.size());

        if (result.nwrite < 0) {
            if (ngtcp2_is_write_more(static_cast<int>(result.nwrite))) {
                state.offset += result.consumed;
                co_await flush_pending_transport_packets(transport);
                continue;
            }
            if (ngtcp2_is_draining(static_cast<int>(result.nwrite))) {
                transport.stop_transport();
                co_return;
            }
            if (result.nwrite == NGTCP2_ERR_STREAM_SHUT_WR || result.nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
                transport.on_stream_write_closed(state.msg.stream);
                co_return;
            }
            if (result.nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                ++transport.debug_stats().tx_blocked_events;
                co_await flush_transport_batch(transport);
                actor.actor_defer_blocked_send(std::move(state));
                co_return;
            }
            transport.fail_transport(
              classify_ngtcp2_error(static_cast<int>(result.nwrite)),
              ngtcp2_error_message(static_cast<int>(result.nwrite)));
            co_return;
        }
        if (result.nwrite == 0) {
            ++transport.debug_stats().tx_zero_write_events;
            co_await flush_transport_batch(transport);
            actor.actor_defer_blocked_send(std::move(state));
            co_return;
        }

        state.offset += result.consumed;
        if (!remaining && state.send_fin) {
            state.send_fin = false;
        }
        co_await transport.send_datagram_packet(std::move(outbuf), static_cast<size_t>(result.nwrite));

        if (state.offset >= state.msg.payload.size() && !state.send_fin) {
            break;
        }
    }
}

future<bool> open_stream(connection_transport& transport, transport_command cmd) {
    if (!transport.has_transport_connection() || !cmd.open_result) {
        co_return false;
    }

    auto result = transport.try_open_stream(cmd.type);
    if (result.rv == 0) {
        transport.complete_open_stream(cmd.open_result, result.sid);
        co_return false;
    }

    if (result.rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
        transport.defer_blocked_open_stream(std::move(cmd));
        co_return true;
    }

    auto error = classify_ngtcp2_error(result.rv);
    auto detail = ngtcp2_error_message(result.rv);
    transport.fail_open_stream(cmd.open_result, error, detail);
    transport.fail_transport(error, detail);
    co_return false;
}

future<> reset_stream(connection_transport& transport, stream_id sid, application_error_code app_error_code) {
    if (!transport.has_transport_connection()) {
        co_return;
    }
    auto rv = transport.shutdown_stream_write(sid, app_error_code);
    if (rv < 0) {
        transport.fail_transport(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }
}

future<> stop_sending(connection_transport& transport, stream_id sid, application_error_code app_error_code) {
    if (!transport.has_transport_connection()) {
        co_return;
    }
    auto rv = transport.shutdown_stream_read(sid, app_error_code);
    if (rv < 0) {
        transport.fail_transport(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }
}

future<> retry_blocked_open_streams(connection_transport& transport, stream_type type) {
    if (!transport.can_retry_blocked_open_streams() || !transport.blocked_open_stream_retry_pending(type)) {
        co_return;
    }

    transport.clear_blocked_open_stream_retry(type);
    while (transport.can_retry_blocked_open_streams()) {
        auto cmd = transport.pop_blocked_open_stream(type);
        if (!cmd) {
            co_return;
        }
        auto blocked = co_await open_stream(transport, std::move(*cmd));
        if (blocked) {
            co_return;
        }
    }
}

future<> handle_transport_command(connection_transport& transport, connection_actor& actor, transport_command cmd) {
    switch (cmd.op) {
    case transport_command::kind::send: {
        blocked_send_state state;
        state.send_fin = cmd.msg.fin;
        state.msg = std::move(cmd.msg);
        co_await send_stream_message(transport, actor, std::move(state));
        break;
    }
    case transport_command::kind::open_stream:
        (void)co_await open_stream(transport, std::move(cmd));
        break;
    case transport_command::kind::reset_stream:
        co_await reset_stream(transport, cmd.msg.stream, cmd.app_error_code);
        break;
    case transport_command::kind::stop_sending:
        co_await stop_sending(transport, cmd.msg.stream, cmd.app_error_code);
        break;
    case transport_command::kind::close_connection:
        transport.request_close();
        break;
    }
}

future<> recv_transport_datagram(connection_transport& transport, const socket_address& src, temporary_buffer<char> pkt) {
    if (!transport.transport_active() || !transport.has_transport_connection()) {
        co_return;
    }

    auto rv = transport.read_transport_datagram(src, pkt.get(), pkt.size());
    if (rv < 0) {
        if (ngtcp2_is_draining(rv)) {
            transport.stop_transport();
            co_return;
        }
        transport.fail_transport(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }

    transport.sync_transport_path();
}

future<> handle_transport_timer(connection_transport& transport) {
    if (!transport.transport_active() || !transport.has_transport_connection()) {
        co_return;
    }

    auto now_local = transport_now_ns();
    if (transport.transport_expiry_ns() <= now_local) {
        auto rv = transport.handle_transport_expiry(now_local);
        if (rv < 0) {
            if (ngtcp2_is_idle_close(rv) || ngtcp2_is_draining(rv)) {
                transport.stop_transport();
                co_return;
            }
            transport.fail_transport(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
            co_return;
        }
    }
}

future<> send_connection_close(connection_transport& transport) {
    if (!transport.can_send_connection_close()) {
        co_return;
    }

    auto outbuf = transport.acquire_tx_packet_buffer();
    auto nwrite = transport.write_connection_close_packet(
      reinterpret_cast<uint8_t*>(outbuf.get_write()),
      outbuf.size());
    if (nwrite <= 0) {
        co_return;
    }

    co_await transport.send_datagram_packet(std::move(outbuf), static_cast<size_t>(nwrite));
    co_await transport.flush_datagram_packets();
}

future<> run_connection_actor(connection_transport& transport, connection_actor& actor) {
    constexpr size_t actor_batch_limit = 64;

    while (actor.actor_active()) {
        if (!actor.actor_has_pending_work()) {
            co_await actor.actor_wait_for_wakeup();
            if (!actor.actor_active()) {
                co_return;
            }
        }

        if (actor.actor_stop_requested()) {
            co_await actor.actor_handle_stop_request();
            co_return;
        }

        size_t rx_processed = 0;
        while (actor.actor_active()
               && !actor.actor_stop_requested()
               && actor.actor_has_rx_event()
               && rx_processed < actor_batch_limit) {
            co_await actor.actor_handle_next_rx_event();
            ++rx_processed;
        }

        if (actor.actor_active() && !actor.actor_stop_requested() && actor.actor_tick_pending()) {
            actor.actor_clear_tick();
            co_await actor.actor_handle_timer_tick();
        }

        if (actor.actor_active() && !actor.actor_stop_requested() && actor.actor_has_blocked_send()) {
            co_await actor.actor_handle_blocked_send();
        }

        size_t commands_processed = 0;
        while (actor.actor_active()
               && !actor.actor_stop_requested()
               && !actor.actor_has_blocked_send()
               && actor.actor_has_transport_command()
               && commands_processed < actor_batch_limit) {
            co_await actor.actor_handle_next_transport_command();
            ++commands_processed;
        }

        if (actor.actor_active() && !actor.actor_stop_requested()) {
            co_await actor.actor_retry_blocked_open_streams();
        }

        if (actor.actor_active() && !actor.actor_stop_requested()) {
            co_await flush_transport_batch(transport);
        }

        if (actor.actor_active()
            && !actor.actor_stop_requested()
            && actor.actor_has_pending_work()
            && (rx_processed == actor_batch_limit || commands_processed == actor_batch_limit)) {
            co_await seastar::coroutine::maybe_yield();
        }
    }
}

connection_engine_ptr make_connection_engine(
  session_runtime_ptr runtime,
  connection_options options,
  std::shared_ptr<transport_debug_stats> debug_stats) {
    return seastar::make_shared<connection_engine>(
      std::move(runtime),
      std::move(options),
      std::move(debug_stats));
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
connection::~connection() = default;
connection::connection(connection&&) noexcept = default;
connection& connection::operator=(connection&&) noexcept = default;

connection::connection(internal::connection_engine_ptr state)
    : _state(std::move(state)) {
}

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
