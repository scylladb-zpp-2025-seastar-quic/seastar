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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <seastar/core/future.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/quic/quic_error.hh>

namespace seastar::quic::experimental {

using stream_id = int64_t;
using application_error_code = uint64_t;
inline constexpr stream_id invalid_stream_id = -1;

enum class stream_type : uint8_t {
    bidirectional,
    unidirectional,
};

struct transport_config {
    uint64_t max_idle_timeout_ns = 60ULL * 1000 * 1000 * 1000;
    uint64_t initial_max_stream_data_bidi_local = 256 * 1024;
    uint64_t initial_max_stream_data_bidi_remote = 256 * 1024;
    uint64_t initial_max_data = 4 * 1024 * 1024;
    uint64_t initial_max_streams_bidi = 128;
};

struct connection_options {
    size_t max_pending_send_bytes = 4 * 1024 * 1024;
    size_t max_pending_receive_bytes = 4 * 1024 * 1024;
    transport_config transport{};
};

struct stream_open_options {
    stream_type type = stream_type::bidirectional;
};

namespace internal {
class session_runtime;
class stream_state;
class connection_state;
using session_runtime_ptr = shared_ptr<session_runtime>;
using stream_state_ptr = shared_ptr<stream_state>;
using connection_state_ptr = shared_ptr<connection_state>;
}

class stream final {
public:
    stream();
    ~stream();

    stream(stream&&) noexcept;
    stream& operator=(stream&&) noexcept;

    stream(const stream&) = delete;
    stream& operator=(const stream&) = delete;

    bool is_open() const noexcept;
    stream_id id() const noexcept;
    stream_type type() const noexcept;

    input_stream<char> input(connected_socket_input_stream_config cfg = {});
    output_stream<char> output(size_t buffer_size = 8192);

    future<> close_output();
    future<> reset(application_error_code app_error_code = 0);
    future<> stop_sending(application_error_code app_error_code = 0);
    future<> wait_input_shutdown();

private:
    explicit stream(internal::stream_state_ptr state);

    internal::stream_state_ptr _state;

    friend class connection;
    friend class internal::connection_state;
    friend connected_socket to_connected_socket(stream&& s);
};

class connection final {
public:
    connection();
    ~connection();

    connection(connection&&) noexcept;
    connection& operator=(connection&&) noexcept;

    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    bool is_open() const noexcept;
    socket_address local_address() const;
    socket_address peer_address() const;
    sstring selected_alpn() const;

    future<stream> open_stream(stream_open_options options = {});
    future<stream> accept_stream();
    future<> close();

private:
    explicit connection(internal::session_runtime_ptr runtime);
    explicit connection(internal::connection_state_ptr state);

    internal::connection_state_ptr _state;

    friend class quic_client;
    friend class quic_server;
};

connected_socket to_connected_socket(stream&& s);

namespace internal {

struct quic_message {
    stream_id stream = invalid_stream_id;
    temporary_buffer<char> payload;
    bool fin = false;
};

struct stream_event {
    enum class kind : uint8_t {
        opened,
        data,
        reset,
        stop_sending,
        transport_closed,
    };

    kind op = kind::data;
    stream_id stream = invalid_stream_id;
    stream_type type = stream_type::bidirectional;
    bool peer_initiated = false;
    temporary_buffer<char> payload;
    bool fin = false;
    application_error_code app_error_code = 0;
};

struct transport_command {
    enum class kind : uint8_t {
        send,
        open_stream,
        reset_stream,
        stop_sending,
        close_connection,
    };

    kind op = kind::send;
    quic_message msg;
    stream_type type = stream_type::bidirectional;
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
    virtual future<> reset_stream(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<> stop_sending(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<stream_event> receive_event() = 0;
    virtual future<> close() = 0;

    virtual future<transport_command> pop_command() = 0;
    virtual void push_event(stream_event evt) = 0;
    virtual void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) = 0;
    virtual void fail_open_stream(std::shared_ptr<promise<stream_id>> result, quic_error error, sstring detail) = 0;
    virtual void mark_transport_ready(socket_address local, socket_address peer, sstring selected_alpn) = 0;
    virtual void mark_transport_closed() = 0;
    virtual void mark_error(quic_error error, sstring detail) = 0;
};

session_runtime_ptr make_session_runtime(connection_options options = {});

} // namespace internal

} // namespace seastar::quic::experimental
