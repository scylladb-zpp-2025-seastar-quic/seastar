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

#include <deque>
#include <optional>
#include <string_view>
#include <utility>

#include <ngtcp2/ngtcp2.h>

#include <seastar/core/future.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/thread.hh>
#include <seastar/net/api.hh>
#include <seastar/quic/quic.hh>
#include <seastar/testing/test_case.hh>

#include "quic/quic_impl.hh"

using namespace seastar;
using namespace seastar::quic::experimental;
namespace quic_internal = seastar::quic::experimental::internal;

namespace {

constexpr int ngtcp2_err_write_more = NGTCP2_ERR_WRITE_MORE;
constexpr int ngtcp2_err_stream_data_blocked = NGTCP2_ERR_STREAM_DATA_BLOCKED;

struct fake_connection_transport {
    bool active = true;
    bool has_connection = true;
    size_t consume_calls = 0;
    size_t completed_send_bytes = 0;
    size_t stream_write_calls = 0;
    size_t write_pending_calls = 0;
    size_t send_datagram_calls = 0;
    size_t rearm_calls = 0;
    size_t open_stream_calls = 0;
    size_t complete_open_stream_calls = 0;
    size_t fail_open_stream_calls = 0;
    size_t deferred_open_stream_calls = 0;
    stream_id consumed_sid = invalid_stream_id;
    size_t consumed_len = 0;
    stream_id completed_open_sid = invalid_stream_id;
    temporary_buffer<char> tx_buffer = temporary_buffer<char>(128);
    std::deque<quic_internal::transport_stream_write_result> stream_write_results;
    std::deque<quic_internal::transport_open_stream_result> open_stream_results;
    std::deque<int64_t> pending_packet_results;
    std::optional<quic_internal::transport_command> deferred_open_stream_cmd;

    bool transport_active() const noexcept {
        return active;
    }

    bool has_transport_connection() const noexcept {
        return has_connection;
    }

    bool can_retry_blocked_open_streams() const noexcept {
        return false;
    }

    size_t tx_payload_limit_bytes() const noexcept {
        return 1200;
    }

    int64_t write_pending_packet(uint8_t*, size_t) {
        ++write_pending_calls;
        if (!pending_packet_results.empty()) {
            auto result = pending_packet_results.front();
            pending_packet_results.pop_front();
            return result;
        }
        return 0;
    }

    quic_internal::transport_stream_write_result write_stream_packet(
      stream_id,
      const char*,
      size_t,
      bool,
      uint8_t*,
      size_t) {
        ++stream_write_calls;
        if (!stream_write_results.empty()) {
            auto result = stream_write_results.front();
            stream_write_results.pop_front();
            return result;
        }
        return {};
    }

    quic_internal::transport_open_stream_result try_open_stream(stream_type) {
        ++open_stream_calls;
        if (!open_stream_results.empty()) {
            auto result = open_stream_results.front();
            open_stream_results.pop_front();
            return result;
        }
        return {};
    }

    void complete_send_bytes(size_t len) {
        completed_send_bytes += len;
    }

    int consume_stream_data(stream_id sid, size_t len) {
        ++consume_calls;
        consumed_sid = sid;
        consumed_len = len;
        return 0;
    }

    int shutdown_stream_write(stream_id, application_error_code) {
        return 0;
    }

    int shutdown_stream_read(stream_id, application_error_code) {
        return 0;
    }

    int read_transport_datagram(const socket_address&, const char*, size_t) {
        return 0;
    }

    void sync_transport_path() {
    }

    uint64_t transport_expiry_ns() const noexcept {
        return 0;
    }

    int handle_transport_expiry(uint64_t) {
        return 0;
    }

    temporary_buffer<char>& tx_packet_buffer() {
        return tx_buffer;
    }

    future<> send_datagram_packet(temporary_buffer<char>) {
        ++send_datagram_calls;
        return make_ready_future<>();
    }

    bool can_send_connection_close() const noexcept {
        return false;
    }

    int64_t write_connection_close_packet(uint8_t*, size_t) {
        return 0;
    }

    void on_stream_write_closed(stream_id) {
    }

    void rearm_transport_timer() {
        ++rearm_calls;
    }

    void request_close() {
    }

    void stop_transport() {
        active = false;
    }

    void fail_transport(quic_error_code error, sstring detail) {
        last_error = error;
        last_error_detail = std::move(detail);
    }

    void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) {
        ++complete_open_stream_calls;
        completed_open_sid = sid;
        if (result) {
            result->set_value(sid);
        }
    }

    void fail_open_stream(std::shared_ptr<promise<stream_id>> result, quic_error_code error, sstring detail) {
        ++fail_open_stream_calls;
        open_stream_error = error;
        open_stream_error_detail = detail;
        if (result) {
            result->set_exception(std::make_exception_ptr(quic_error(error, std::string(detail))));
        }
    }

    void defer_blocked_open_stream(quic_internal::transport_command cmd) {
        ++deferred_open_stream_calls;
        deferred_open_stream_cmd = std::move(cmd);
    }

    std::optional<quic_internal::transport_command> pop_blocked_open_stream(stream_type) {
        return std::nullopt;
    }

    bool blocked_open_stream_retry_pending(stream_type) const noexcept {
        return false;
    }

    void clear_blocked_open_stream_retry(stream_type) noexcept {
    }

    std::optional<quic_error_code> last_error;
    sstring last_error_detail;
    std::optional<quic_error_code> open_stream_error;
    sstring open_stream_error_detail;
};

quic_internal::quic_message make_message(stream_id sid, std::string_view payload, bool fin = false) {
    return quic_internal::quic_message{
      .stream = sid,
      .payload = temporary_buffer<char>::copy_of(payload),
      .fin = fin,
    };
}

} // namespace

SEASTAR_TEST_CASE(test_quic_reading_stream_queues_consumed_credit) {
    return seastar::async([] {
        auto runtime = quic_internal::make_session_runtime();
        auto engine = quic_internal::make_connection_engine(runtime);

        engine->on_stream_data(
          0,
          stream_type::bidirectional,
          true,
          temporary_buffer<char>("ping", 4),
          false);

        auto accepted = engine->accept_stream().get();
        auto input = accepted.input();
        auto chunk = input.read().get();

        BOOST_REQUIRE_EQUAL(to_sstring(std::move(chunk)), "ping");

        auto cmd = runtime->poll_command();
        BOOST_REQUIRE(cmd.has_value());
        BOOST_REQUIRE(cmd->op == quic_internal::transport_command::kind::consume_stream_data);
        BOOST_REQUIRE_EQUAL(cmd->msg.stream, 0);
        BOOST_REQUIRE_EQUAL(cmd->consumed_bytes, 4);
    });
}

SEASTAR_TEST_CASE(test_quic_consume_stream_command_updates_transport_credit) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        quic_internal::transport_command cmd;
        cmd.op = quic_internal::transport_command::kind::consume_stream_data;
        cmd.msg.stream = 7;
        cmd.consumed_bytes = 64;

        quic_internal::handle_transport_command(transport_handle, std::move(cmd)).get();

        BOOST_REQUIRE_EQUAL(transport.consume_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.consumed_sid, 7);
        BOOST_REQUIRE_EQUAL(transport.consumed_len, 64);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.send_datagram_calls, 0);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 1);
        BOOST_REQUIRE(!transport.last_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_send_backpressure_waits_for_transport_consumption) {
    return seastar::async([] {
        connection_options options;
        options.max_pending_send_bytes = 4;

        auto runtime = quic_internal::make_session_runtime(options);
        runtime->send(make_message(0, "ping")).get();

        auto second_send = runtime->send(make_message(0, "x"));
        BOOST_REQUIRE(!second_send.available());

        auto first = runtime->poll_command();
        BOOST_REQUIRE(first.has_value());
        BOOST_REQUIRE(first->op == quic_internal::transport_command::kind::send);
        BOOST_REQUIRE(!second_send.available());

        runtime->complete_send_bytes(first->msg.payload.size());
        second_send.get();
    });
}

SEASTAR_TEST_CASE(test_quic_send_command_defers_remaining_payload_when_blocked) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = ngtcp2_err_write_more,
          .consumed = 3,
        });
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = 0,
          .consumed = 0,
        });

        quic_internal::transport_command cmd;
        cmd.op = quic_internal::transport_command::kind::send;
        cmd.msg = make_message(9, "hello");

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(cmd)).get();

        BOOST_REQUIRE(blocked.has_value());
        BOOST_REQUIRE(blocked->op == quic_internal::transport_command::kind::send);
        BOOST_REQUIRE_EQUAL(blocked->msg.stream, 9);
        BOOST_REQUIRE_EQUAL(to_sstring(blocked->msg.payload.share()), "lo");
        BOOST_REQUIRE_EQUAL(transport.completed_send_bytes, 3);
        BOOST_REQUIRE_EQUAL(transport.stream_write_calls, 2);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 2);
        BOOST_REQUIRE_EQUAL(transport.send_datagram_calls, 0);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 1);
        BOOST_REQUIRE(!transport.last_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_send_command_retry_completes_deferred_payload) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = ngtcp2_err_write_more,
          .consumed = 3,
        });
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = 0,
          .consumed = 0,
        });

        quic_internal::transport_command first_cmd;
        first_cmd.op = quic_internal::transport_command::kind::send;
        first_cmd.msg = make_message(11, "hello");

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(first_cmd)).get();
        BOOST_REQUIRE(blocked.has_value());

        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = 17,
          .consumed = 2,
        });

        auto resumed = quic_internal::handle_transport_command(transport_handle, std::move(*blocked)).get();

        BOOST_REQUIRE(!resumed.has_value());
        BOOST_REQUIRE_EQUAL(transport.completed_send_bytes, 5);
        BOOST_REQUIRE_EQUAL(transport.stream_write_calls, 3);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 3);
        BOOST_REQUIRE_EQUAL(transport.send_datagram_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 2);
        BOOST_REQUIRE(!transport.last_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_send_command_defers_payload_when_stream_flow_control_blocks) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = ngtcp2_err_stream_data_blocked,
          .consumed = 0,
        });

        quic_internal::transport_command cmd;
        cmd.op = quic_internal::transport_command::kind::send;
        cmd.msg = make_message(13, "hello");

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(cmd)).get();

        BOOST_REQUIRE(blocked.has_value());
        BOOST_REQUIRE(blocked->op == quic_internal::transport_command::kind::send);
        BOOST_REQUIRE_EQUAL(blocked->msg.stream, 13);
        BOOST_REQUIRE_EQUAL(to_sstring(blocked->msg.payload.share()), "hello");
        BOOST_REQUIRE(!blocked->msg.fin);
        BOOST_REQUIRE_EQUAL(transport.completed_send_bytes, 0);
        BOOST_REQUIRE_EQUAL(transport.stream_write_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.send_datagram_calls, 0);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 1);
        BOOST_REQUIRE(!transport.last_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_send_command_retry_fin_completes_without_duplicate_write) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = ngtcp2_err_stream_data_blocked,
          .consumed = 0,
        });

        quic_internal::transport_command first_cmd;
        first_cmd.op = quic_internal::transport_command::kind::send;
        first_cmd.msg = make_message(17, "hello", true);

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(first_cmd)).get();
        BOOST_REQUIRE(blocked.has_value());
        BOOST_REQUIRE(blocked->msg.fin);
        BOOST_REQUIRE_EQUAL(to_sstring(blocked->msg.payload.share()), "hello");

        transport.stream_write_results.push_back(quic_internal::transport_stream_write_result{
          .nwrite = 19,
          .consumed = 5,
        });

        auto resumed = quic_internal::handle_transport_command(transport_handle, std::move(*blocked)).get();

        BOOST_REQUIRE(!resumed.has_value());
        BOOST_REQUIRE_EQUAL(transport.completed_send_bytes, 5);
        BOOST_REQUIRE_EQUAL(transport.stream_write_calls, 2);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 2);
        BOOST_REQUIRE_EQUAL(transport.send_datagram_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 2);
        BOOST_REQUIRE(!transport.last_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_open_stream_command_completes_result) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.open_stream_results.push_back(quic_internal::transport_open_stream_result{
          .rv = 0,
          .sid = 21,
        });

        auto result = std::make_shared<promise<stream_id>>();
        auto result_future = result->get_future();

        quic_internal::transport_command cmd;
        cmd.op = quic_internal::transport_command::kind::open_stream;
        cmd.type = stream_type::bidirectional;
        cmd.open_result = result;

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(cmd)).get();

        BOOST_REQUIRE(!blocked.has_value());
        BOOST_REQUIRE_EQUAL(result_future.get(), 21);
        BOOST_REQUIRE_EQUAL(transport.open_stream_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.complete_open_stream_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.completed_open_sid, 21);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 1);
        BOOST_REQUIRE(!transport.last_error.has_value());
        BOOST_REQUIRE(!transport.open_stream_error.has_value());
    });
}

SEASTAR_TEST_CASE(test_quic_open_stream_command_failure_propagates_error) {
    return seastar::async([] {
        fake_connection_transport transport;
        auto transport_handle = quic_internal::make_connection_transport(transport);
        transport.open_stream_results.push_back(quic_internal::transport_open_stream_result{
          .rv = NGTCP2_ERR_PROTO,
          .sid = invalid_stream_id,
        });

        auto result = std::make_shared<promise<stream_id>>();
        auto result_future = result->get_future();

        quic_internal::transport_command cmd;
        cmd.op = quic_internal::transport_command::kind::open_stream;
        cmd.type = stream_type::bidirectional;
        cmd.open_result = result;

        auto blocked = quic_internal::handle_transport_command(transport_handle, std::move(cmd)).get();

        BOOST_REQUIRE(!blocked.has_value());
        BOOST_REQUIRE_EQUAL(transport.open_stream_calls, 1);
        BOOST_REQUIRE_EQUAL(transport.fail_open_stream_calls, 1);
        BOOST_REQUIRE(transport.open_stream_error.has_value());
        BOOST_REQUIRE(*transport.open_stream_error == quic_error_code::protocol);
        BOOST_REQUIRE(!transport.open_stream_error_detail.empty());
        BOOST_REQUIRE(transport.last_error.has_value());
        BOOST_REQUIRE(*transport.last_error == quic_error_code::protocol);
        BOOST_REQUIRE_EQUAL(transport.write_pending_calls, 0);
        BOOST_REQUIRE_EQUAL(transport.rearm_calls, 0);

        try {
            (void)result_future.get();
            BOOST_FAIL("expected open_stream to fail");
        } catch (const quic_error& e) {
            BOOST_REQUIRE(e.code() == quic_error_code::protocol);
        }
    });
}
