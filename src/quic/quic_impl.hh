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

#pragma once

#include "quic_error_impl.hh"

#include <seastar/quic/quic.hh>

namespace seastar::quic::experimental {

namespace internal {
class stream_state;
class connection_engine;

using stream_state_ptr = shared_ptr<stream_state>;
using connection_engine_ptr = shared_ptr<connection_engine>;
}

class stream::impl {
public:
    explicit impl(internal::stream_state_ptr state)
        : state(std::move(state)) {
    }

    internal::stream_state_ptr state;
};

class connection::impl {
public:
    explicit impl(internal::connection_engine_ptr state)
        : state(std::move(state)) {
    }

    internal::connection_engine_ptr state;
};

} // namespace seastar::quic::experimental

namespace seastar::quic::experimental::internal {

class session_runtime;
class stream_state;
class connection_engine;

using session_runtime_ptr = shared_ptr<session_runtime>;
using stream_state_ptr = shared_ptr<stream_state>;
using connection_engine_ptr = shared_ptr<connection_engine>;

struct quic_message {
    stream_id stream = invalid_stream_id;
    temporary_buffer<char> payload;
    bool fin = false;
};

enum class stream_shutdown_side : uint8_t {
    read,
    write,
};

struct transport_command {
    enum class kind : uint8_t {
        send,
        open_stream,
        consume_stream_data,
        reset_stream,
        stop_sending,
        close_connection,
    };

    kind op = kind::send;
    quic_message msg;
    stream_type type = stream_type::bidirectional;
    size_t consumed_bytes = 0;
    application_error_code app_error_code = 0;
    std::shared_ptr<promise<stream_id>> open_result;
};

class session_runtime {
public:
    virtual ~session_runtime() = default;

    virtual bool is_open() const noexcept = 0;
    virtual socket_address local_address() const = 0;
    virtual socket_address peer_address() const = 0;
    virtual sstring selected_alpn() const = 0;

    virtual future<> send(quic_message msg) = 0;
    virtual future<stream_id> open_stream(stream_type type) = 0;
    virtual void complete_send_bytes(size_t len) = 0;
    virtual void consume_stream_data(stream_id sid, size_t len) = 0;
    virtual future<> reset_stream(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<> stop_sending(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<> close() = 0;

    virtual bool has_pending_commands() const noexcept = 0;
    virtual std::optional<transport_command> poll_command() = 0;
    virtual void set_command_notifier(std::function<void()> notifier) = 0;
    virtual void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) = 0;
    virtual void fail_open_stream(std::shared_ptr<promise<stream_id>> result, quic_error_code error, sstring detail) = 0;
    virtual void mark_transport_ready(socket_address local, socket_address peer, sstring selected_alpn) = 0;
    virtual void mark_transport_closed() = 0;
    virtual void mark_error(quic_error_code error, sstring detail) = 0;
    virtual bool transport_terminal() const noexcept = 0;
    virtual bool transport_failed() const noexcept = 0;
    virtual quic_error_code transport_error() const noexcept = 0;
    virtual sstring transport_error_detail() const = 0;
};

struct transport_stream_write_result {
    int64_t nwrite = 0;
    size_t consumed = 0;
};

struct transport_open_stream_result {
    int rv = 0;
    stream_id sid = invalid_stream_id;
};

class connection_transport {
public:
    virtual ~connection_transport() = default;

    virtual bool transport_active() const noexcept = 0;
    virtual bool has_transport_connection() const noexcept = 0;
    virtual bool can_retry_blocked_open_streams() const noexcept = 0;
    virtual size_t tx_payload_limit_bytes() const noexcept = 0;

    virtual int64_t write_pending_packet(uint8_t* outbuf, size_t outbuf_size) = 0;
    virtual transport_stream_write_result write_stream_packet(
      stream_id sid,
      const char* data,
      size_t len,
      bool fin,
      uint8_t* outbuf,
      size_t outbuf_size) = 0;
    virtual transport_open_stream_result try_open_stream(stream_type type) = 0;
    virtual void complete_send_bytes(size_t len) = 0;
    virtual int consume_stream_data(stream_id sid, size_t len) = 0;
    virtual int shutdown_stream_write(stream_id sid, application_error_code app_error_code) = 0;
    virtual int shutdown_stream_read(stream_id sid, application_error_code app_error_code) = 0;
    virtual int read_transport_datagram(const socket_address& src, const char* data, size_t len) = 0;
    virtual void sync_transport_path() = 0;
    virtual uint64_t transport_expiry_ns() const noexcept = 0;
    virtual int handle_transport_expiry(uint64_t now_ns) = 0;
    virtual temporary_buffer<char>& tx_packet_buffer() = 0;

    virtual future<> send_datagram_packet(temporary_buffer<char> packet) = 0;
    virtual bool can_send_connection_close() const noexcept = 0;
    virtual int64_t write_connection_close_packet(uint8_t* outbuf, size_t outbuf_size) = 0;
    virtual void on_stream_write_closed(stream_id sid) = 0;
    virtual void rearm_transport_timer() = 0;
    virtual void request_close() = 0;
    virtual void stop_transport() = 0;
    virtual void fail_transport(quic_error_code error, sstring detail) = 0;

    virtual void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) = 0;
    virtual void fail_open_stream(
      std::shared_ptr<promise<stream_id>> result,
      quic_error_code error,
      sstring detail) = 0;
    virtual void defer_blocked_open_stream(transport_command cmd) = 0;
    virtual std::optional<transport_command> pop_blocked_open_stream(stream_type type) = 0;
    virtual bool blocked_open_stream_retry_pending(stream_type type) const noexcept = 0;
    virtual void clear_blocked_open_stream_retry(stream_type type) noexcept = 0;
};

class connection_actor {
public:
    virtual ~connection_actor() = default;

    virtual bool actor_active() const noexcept = 0;
    virtual bool actor_has_pending_work() const noexcept = 0;
    virtual future<> actor_wait_for_wakeup() = 0;
    virtual bool actor_stop_requested() const noexcept = 0;
    virtual future<> actor_handle_stop_request() = 0;
    virtual bool actor_transport_terminal() const noexcept = 0;
    virtual future<> actor_handle_transport_terminal() = 0;
    virtual bool actor_has_rx_event() const noexcept = 0;
    virtual future<> actor_handle_next_rx_event() = 0;
    virtual bool actor_has_transport_command() const noexcept = 0;
    virtual future<> actor_handle_next_transport_command() = 0;
    virtual future<> actor_retry_blocked_open_streams() = 0;
    virtual bool actor_tick_pending() const noexcept = 0;
    virtual void actor_clear_tick() noexcept = 0;
    virtual future<> actor_handle_timer_tick() = 0;
};

class connection_engine {
public:
    explicit connection_engine(session_runtime_ptr runtime, connection_options options = {});
    ~connection_engine();

    connection_engine(const connection_engine&) = delete;
    connection_engine& operator=(const connection_engine&) = delete;

    bool is_open() const noexcept;
    socket_address local_address() const;
    socket_address peer_address() const;
    sstring selected_alpn() const;

    future<stream> open_stream(stream_open_options options = {});
    future<stream> accept_stream();
    future<> close();

    void on_stream_data(stream_id sid, stream_type type, bool peer_initiated, temporary_buffer<char> payload, bool fin);
    void on_stream_reset(stream_id sid, stream_type type, bool peer_initiated, application_error_code app_error_code);
    void on_stream_stop_sending(
      stream_id sid,
      stream_type type,
      bool peer_initiated,
      application_error_code app_error_code,
      stream_shutdown_side shutdown_side);
    void on_stream_closed(stream_id sid);
    void on_transport_closed(std::exception_ptr ex);

    future<> wait_for_actor_wakeup(bool has_pending_work, bool closing);
    void wake_actor();

    bool tick_pending() const noexcept;
    void clear_tick() noexcept;

    void arm_timer(std::chrono::nanoseconds delay, bool closing);
    void rearm_timer_from_expiry(uint64_t expiry_ns, uint64_t now_ns, bool closing);
    void cancel_timer() noexcept;

    void defer_blocked_open_stream(transport_command cmd);
    std::optional<transport_command> pop_blocked_open_stream(stream_type type);
    void request_blocked_open_stream_retry(stream_type type);
    bool blocked_open_stream_retry_pending(stream_type type) const noexcept;
    void clear_blocked_open_stream_retry(stream_type type) noexcept;
    bool has_blocked_open_stream_retry_work() const noexcept;
    void fail_blocked_open_streams(quic_error_code error, std::string_view detail);

private:
    class impl;
    std::unique_ptr<impl> _impl;
};

connection_engine_ptr make_connection_engine(session_runtime_ptr runtime, connection_options options = {});

future<> flush_pending_transport_packets(connection_transport& transport);
future<std::optional<quic_message>> send_stream_message(connection_transport& transport, quic_message msg);
future<bool> open_stream(connection_transport& transport, transport_command cmd);
future<> consume_stream_data(connection_transport& transport, stream_id sid, size_t len);
future<> reset_stream(connection_transport& transport, stream_id sid, application_error_code app_error_code);
future<> stop_sending(connection_transport& transport, stream_id sid, application_error_code app_error_code);
future<> retry_blocked_open_streams(connection_transport& transport, stream_type type);
future<std::optional<transport_command>> handle_transport_command(connection_transport& transport, transport_command cmd);
future<> recv_transport_datagram(connection_transport& transport, const socket_address& src, temporary_buffer<char> pkt);
future<> handle_transport_timer(connection_transport& transport);
future<> send_connection_close(connection_transport& transport);
future<> run_connection_actor(connection_actor& actor);

session_runtime_ptr make_session_runtime(connection_options options = {});

} // namespace seastar::quic::experimental::internal
