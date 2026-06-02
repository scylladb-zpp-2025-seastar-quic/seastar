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

// QUIC benchmark server.
//
// For bidirectional streams: echoes all received data back to the client.
// For unidirectional streams (client->server): reads and discards all data.
//
// Prints throughput statistics every --stats-interval seconds.
// Use alongside quic_bench_client to measure QUIC throughput and latency.

#include <arpa/inet.h>

#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

#include <fmt/core.h>

#include <seastar/core/abort_source.hh>
#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/when_all.hh>
#include <seastar/quic/quic_server.hh>

#include "../../apps/lib/stop_signal.hh"

using namespace seastar;
using namespace seastar::quic::experimental;
namespace bpo = boost::program_options;

static constexpr size_t throughput_buffer_size = 256 * 1024;
static constexpr uint64_t throughput_stream_window = 8 * 1024 * 1024;
static constexpr uint64_t throughput_connection_window = 64 * 1024 * 1024;
static constexpr uint64_t throughput_stream_limit = 1024;
static size_t g_throughput_flush_bytes = throughput_buffer_size;

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

// Server-side counters (single-shard, no atomics needed).
struct server_stats {
    uint64_t bytes_received = 0;  // total bytes read from all streams
    uint64_t bytes_echoed = 0;    // total bytes written back (bidi streams only)
    uint64_t streams_completed = 0;
    uint64_t connections_accepted = 0;
};

static server_stats g_stats;

// Echo all data on a bidirectional stream.
static future<> handle_bidi_stream(seastar::quic::experimental::stream s) {
    auto input = s.input();
    // Match the TLS/TCP benchmark buffering in throughput mode.
    auto output = s.output(throughput_buffer_size);
    size_t buffered_echo_bytes = 0;
    try {
        while (true) {
            auto buf = co_await input.read();
            if (buf.empty()) {
                break;
            }
            g_stats.bytes_received += buf.size();
            co_await output.write(buf.get(), buf.size());
            buffered_echo_bytes += buf.size();
            if (buffered_echo_bytes >= g_throughput_flush_bytes) {
                co_await output.flush();
                buffered_echo_bytes = 0;
            }
            g_stats.bytes_echoed += buf.size();
        }
        if (buffered_echo_bytes > 0) {
            co_await output.flush();
        }
    } catch (const quic_error& e) {
        if (e.code() != quic_error::closed) {
            std::cerr << "[server] bidi stream error: " << e.what() << "\n";
        }
    }
    try { co_await output.close(); } catch (...) {}
    try { co_await input.close(); } catch (...) {}
    ++g_stats.streams_completed;
}

// Drain all data on a unidirectional stream (client->server direction).
static future<> handle_uni_stream(seastar::quic::experimental::stream s) {
    auto input = s.input();
    try {
        while (true) {
            auto buf = co_await input.read();
            if (buf.empty()) {
                break;
            }
            g_stats.bytes_received += buf.size();
        }
    } catch (const quic_error& e) {
        if (e.code() != quic_error::closed) {
            std::cerr << "[server] uni stream error: " << e.what() << "\n";
        }
    }
    try { co_await input.close(); } catch (...) {}
    ++g_stats.streams_completed;
}

static future<> handle_bench_stream(seastar::quic::experimental::stream s) {
    if (s.type() == stream_type::bidirectional) {
        return handle_bidi_stream(std::move(s));
    } else {
        return handle_uni_stream(std::move(s));
    }
}

static future<> handle_bench_session(connection session) {
    gate streams;
    ++g_stats.connections_accepted;
    try {
        while (session.is_open()) {
            auto s = co_await session.accept_stream();
            (void)with_gate(streams, [s = std::move(s)]() mutable {
                return handle_bench_stream(std::move(s));
            }).handle_exception([](std::exception_ptr ep) {
                try {
                    std::rethrow_exception(ep);
                } catch (const std::exception& e) {
                    std::cerr << "[server] stream task failed: " << e.what() << "\n";
                }
            }).or_terminate();
        }
    } catch (const quic_error& e) {
        if (e.code() != quic_error::closed) {
            std::cerr << "[server] connection error: " << e.what() << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] connection exception: " << e.what() << "\n";
    }
    try { co_await session.close(); } catch (...) {}
    try { co_await streams.close(); } catch (...) {}
}

static future<> accept_loop(quic_server& server, gate& sessions) {
    while (true) {
        connection session;
        try {
            session = co_await server.accept();
        } catch (const quic_error& e) {
            if (e.code() == quic_error::closed) {
                co_return;
            }
            throw;
        }
        (void)with_gate(sessions, [session = std::move(session)]() mutable {
            return handle_bench_session(std::move(session));
        }).handle_exception([](std::exception_ptr ep) {
            try {
                std::rethrow_exception(ep);
            } catch (const std::exception& e) {
                std::cerr << "[server] connection task failed: " << e.what() << "\n";
            }
        }).or_terminate();
    }
}

// Prints a one-line stats summary every `interval_s` seconds until aborted.
static future<> print_stats_loop(unsigned interval_s, abort_source& as) {
    uint64_t prev_rx = 0;
    uint64_t prev_tx = 0;
    try {
        while (true) {
            co_await sleep_abortable(std::chrono::seconds(interval_s), as);
            uint64_t rx = g_stats.bytes_received;
            uint64_t tx = g_stats.bytes_echoed;
            double rx_mb_s = static_cast<double>(rx - prev_rx) / 1e6 / interval_s;
            double tx_mb_s = static_cast<double>(tx - prev_tx) / 1e6 / interval_s;
            prev_rx = rx;
            prev_tx = tx;
            fmt::print(
                "[server] conns={} streams_done={} rx={:.1f} MB/s tx={:.1f} MB/s\n",
                g_stats.connections_accepted,
                g_stats.streams_completed,
                rx_mb_s,
                tx_mb_s);
            std::cout.flush();
        }
    } catch (const sleep_aborted&) {
        // Normal shutdown path.
    }
}

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
        ("address", bpo::value<std::string>()->default_value("::1"),
         "Server IPv6 address")
        ("port", bpo::value<uint16_t>()->default_value(4444),
         "Server UDP port")
        ("crt", bpo::value<std::string>()->default_value("server.crt"),
         "PEM certificate file")
        ("key,k", bpo::value<std::string>()->default_value("server.key"),
         "PEM private-key file")
        ("throughput-flush-bytes", bpo::value<size_t>()->default_value(0),
         "Flush echoed throughput data every N bytes (0 = auto, one output buffer)")
        ("stats-interval", bpo::value<unsigned>()->default_value(1),
         "Throughput stats printing interval in seconds (0 to disable)");

    return app.run(argc, argv, [&app]() -> future<int> {
        quic_server server;
        gate sessions;
        abort_source stats_as;
        std::optional<future<>> accept_task;
        std::optional<future<>> stats_task;
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address       = cfg["address"].as<std::string>();
            auto port          = cfg["port"].as<uint16_t>();
            auto crt           = cfg["crt"].as<std::string>();
            auto key           = cfg["key"].as<std::string>();
            auto flush_bytes   = cfg["throughput-flush-bytes"].as<size_t>();
            auto stats_intv    = cfg["stats-interval"].as<unsigned>();
            g_throughput_flush_bytes = flush_bytes > 0 ? flush_bytes : throughput_buffer_size;

            quic_server_config server_cfg;
            server_cfg.listen_address = parse_ipv6_address(address, port);
            server_cfg.crt_file = crt;
            server_cfg.key_file = key;
            // Increase transport limits for high-throughput benchmarking.
            server_cfg.session_options.max_pending_send_bytes    = 4 * 1024 * 1024;
            server_cfg.session_options.max_pending_receive_bytes = 64 * 1024 * 1024;
            server_cfg.session_options.transport.initial_max_stream_data_bidi_local  = throughput_stream_window;
            server_cfg.session_options.transport.initial_max_stream_data_bidi_remote = throughput_stream_window;
            server_cfg.session_options.transport.initial_max_stream_data_uni         = throughput_stream_window;
            server_cfg.session_options.transport.initial_max_data          = throughput_connection_window;
            server_cfg.session_options.transport.initial_max_streams_bidi  = throughput_stream_limit;
            server_cfg.session_options.transport.initial_max_streams_uni   = throughput_stream_limit;
            server_cfg.session_options.transport.max_window = throughput_connection_window;
            server_cfg.session_options.transport.max_stream_window = 16 * 1024 * 1024;
            server_cfg.session_options.transport.ack_thresh = 8;
            server_cfg.session_options.transport.initial_rtt_ns = 0;
            server_cfg.session_options.transport.congestion_control = congestion_control_algorithm::bbr;
            server_cfg.session_options.transport.max_udp_payload_size = 65527;
            server_cfg.session_options.transport.max_tx_udp_payload_size = 4096;
            server_cfg.session_options.transport.disable_tx_udp_payload_size_shaping = true;

            co_await server.start(std::move(server_cfg));
            accept_task.emplace(accept_loop(server, sessions));
            if (stats_intv > 0) {
                stats_task.emplace(print_stats_loop(stats_intv, stats_as));
            }

            fmt::print("[server] QUIC bench server listening on [{}]:{}\n", address, port);
            fmt::print("[server] throughput flush-bytes={}\n", g_throughput_flush_bytes);
            fmt::print("[server] Ctrl-C to stop.\n");
            std::cout.flush();

            seastar_apps_lib::stop_signal stop_signal;
            co_await stop_signal.wait();
            fmt::print("[server] shutting down...\n");
            std::cout.flush();
        } catch (...) {
            error = std::current_exception();
        }

        stats_as.request_abort();
        if (stats_task) {
            try { co_await std::move(*stats_task); } catch (...) {}
        }
        try { co_await server.stop(); } catch (...) {}
        if (accept_task) {
            try {
                co_await std::move(*accept_task);
            } catch (...) {
                if (!error) { error = std::current_exception(); }
            }
        }
        try { co_await sessions.close(); } catch (...) {
            if (!error) { error = std::current_exception(); }
        }

        if (error) {
            try {
                std::rethrow_exception(error);
            } catch (const std::exception& e) {
                std::cerr << "[server] fatal: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[server] fatal: unknown exception\n";
            }
            co_return 1;
        }
        co_return 0;
    });
}
