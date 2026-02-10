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
#include <utility>

#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/quic/quic_error.hh>

namespace seastar::quic::experimental {

using stream_id = int64_t;
inline constexpr stream_id invalid_stream_id = -1;

struct quic_message {
    stream_id stream = invalid_stream_id;
    temporary_buffer<char> payload;
    bool fin = false;

    quic_message() = default;
    quic_message(stream_id sid, temporary_buffer<char> data, bool end_stream = false)
        : stream(sid)
        , payload(std::move(data))
        , fin(end_stream) {
    }
};

struct transport_config {
    uint64_t max_idle_timeout_ns = 60ULL * 1000 * 1000 * 1000;
    uint64_t initial_max_stream_data_bidi_local = 256 * 1024;
    uint64_t initial_max_stream_data_bidi_remote = 256 * 1024;
    uint64_t initial_max_data = 4 * 1024 * 1024;
    uint64_t initial_max_streams_bidi = 128;
};

struct connection_options {
    stream_id initial_stream_id = 0;
    size_t max_pending_send_bytes = 4 * 1024 * 1024;
    size_t max_pending_receive_bytes = 4 * 1024 * 1024;
    transport_config transport{};
};

namespace internal {
class session_runtime;
using session_runtime_ptr = shared_ptr<session_runtime>;
session_runtime_ptr make_session_runtime(connection_options options = {});
}

class connection final {
public:
    connection();
    ~connection();

    connection(connection&&) noexcept;
    connection& operator=(connection&&) noexcept;

    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    bool is_open() const noexcept;
    stream_id default_stream() const noexcept;

    future<> send(quic_message msg);
    future<> send(stream_id sid, temporary_buffer<char> payload, bool fin = false);
    future<> send(stream_id sid, sstring payload, bool fin = false);

    future<quic_message> receive();
    future<> close();

    // Backend adapter hook used by transport implementations in .cc files.
    internal::session_runtime_ptr runtime() const noexcept;

private:
    explicit connection(internal::session_runtime_ptr runtime);

    internal::session_runtime_ptr _runtime;

    friend class quic_client;
    friend class quic_server;
};

namespace internal {

class session_runtime {
public:
    virtual ~session_runtime() = default;

    virtual bool is_open() const noexcept = 0;
    virtual stream_id default_stream() const noexcept = 0;
    virtual future<> send(quic_message msg) = 0;
    virtual future<quic_message> receive() = 0;
    virtual future<> close() = 0;

    virtual future<quic_message> pop_outgoing() = 0;
    virtual void push_incoming(quic_message msg) = 0;
    virtual void mark_ready(stream_id sid) = 0;
    virtual void mark_transport_closed() = 0;
    virtual void mark_error(quic_error error, sstring detail) = 0;
};

} // namespace internal

} // namespace seastar::quic::experimental
