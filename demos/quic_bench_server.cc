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

#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/core.h>

#include <seastar/core/abort_source.hh>
#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/smp.hh>
#include <seastar/core/when_all.hh>
#include <seastar/quic/sharded_quic_server.hh>

#include "../apps/lib/stop_signal.hh"

using namespace seastar;
using namespace seastar::quic::experimental;
namespace bpo = boost::program_options;

static constexpr size_t throughput_buffer_size = 256 * 1024;
static constexpr uint64_t throughput_stream_window = 8 * 1024 * 1024;
static constexpr uint64_t throughput_connection_window = 64 * 1024 * 1024;
static constexpr uint64_t throughput_stream_limit = 1024;
// Loopback benchmark default: large enough to reduce packet churn, while
// still staying below the unstable jumbo-datagram range.
static constexpr uint64_t benchmark_udp_payload_size = 32 * 1024;
static size_t g_throughput_flush_bytes = throughput_buffer_size;

enum class wire_mode : char {
    bidirectional = 'B',
    unidirectional = 'U',
    latency = 'L',
};

static wire_mode parse_mode_header(char header) {
    switch (header) {
    case static_cast<char>(wire_mode::bidirectional):
        return wire_mode::bidirectional;
    case static_cast<char>(wire_mode::unidirectional):
        return wire_mode::unidirectional;
    case static_cast<char>(wire_mode::latency):
        return wire_mode::latency;
    default:
        throw std::runtime_error(fmt::format("Unknown QUIC benchmark stream mode '{}'", header));
    }
}

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

// Server-side counters local to each shard (no atomics needed).
struct server_stats {
    uint64_t bytes_received = 0;  // total bytes read from all streams
    uint64_t bytes_echoed = 0;    // total bytes written back (bidi streams only)
    uint64_t streams_completed = 0;
    uint64_t connections_accepted = 0;

    server_stats& operator+=(const server_stats& other) {
        bytes_received += other.bytes_received;
        bytes_echoed += other.bytes_echoed;
        streams_completed += other.streams_completed;
        connections_accepted += other.connections_accepted;
        return *this;
    }
};

static thread_local server_stats g_stats;

// Echo all data on a bidirectional stream.
static future<> handle_bidi_stream(seastar::quic::experimental::stream s) {
    auto input = s.input();
    // Match the TLS/TCP benchmark buffering in throughput mode.
    auto output = s.output(throughput_buffer_size);
    size_t buffered_echo_bytes = 0;
    try {
        auto mode_buffer = co_await input.read_exactly(1);
        if (mode_buffer.empty()) {
            co_return;
        }
        auto mode = parse_mode_header(mode_buffer.get()[0]);
        if (mode == wire_mode::unidirectional) {
            throw std::runtime_error("Unidirectional mode header received on bidirectional stream");
        }
        while (true) {
            auto buf = co_await input.read();
            if (buf.empty()) {
                break;
            }
            g_stats.bytes_received += buf.size();
            co_await output.write(buf.get(), buf.size());
            buffered_echo_bytes += buf.size();
            if (mode == wire_mode::latency
                    || buffered_echo_bytes >= g_throughput_flush_bytes) {
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
        auto mode_buffer = co_await input.read_exactly(1);
        if (mode_buffer.empty()) {
            co_return;
        }
        auto mode = parse_mode_header(mode_buffer.get()[0]);
        if (mode != wire_mode::unidirectional) {
            throw std::runtime_error("Non-unidirectional mode header received on unidirectional stream");
        }
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
                } catch (const quic_error& e) {
                    if (e.code() != quic_error::closed) {
                        std::cerr << "[server] stream task failed: " << e.what() << "\n";
                    }
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


static future<std::vector<server_stats>> collect_server_stats() {
    std::vector<future<server_stats>> pending;
    pending.reserve(this_smp_shard_count());
    for (unsigned shard = 0; shard < this_smp_shard_count(); ++shard) {
        pending.push_back(smp::submit_to(shard, [] {
            return g_stats;
        }));
    }
    co_return co_await when_all_succeed(pending.begin(), pending.end());
}

static void print_interval_stats(
        const std::vector<server_stats>& current,
        const std::vector<server_stats>& previous,
        double elapsed_s) {
    server_stats total;
    server_stats previous_total;
    for (unsigned shard = 0; shard < current.size(); ++shard) {
        total += current[shard];
        previous_total += previous[shard];
        fmt::print(
            "[server shard={}] conns={} streams={} rx={:.1f} MB/s tx={:.1f} MB/s\n",
            shard,
            current[shard].connections_accepted,
            current[shard].streams_completed,
            static_cast<double>(current[shard].bytes_received - previous[shard].bytes_received) / 1e6 / elapsed_s,
            static_cast<double>(current[shard].bytes_echoed - previous[shard].bytes_echoed) / 1e6 / elapsed_s);
    }
    fmt::print(
        "[server total] conns={} streams={} rx={:.1f} MB/s tx={:.1f} MB/s\n",
        total.connections_accepted,
        total.streams_completed,
        static_cast<double>(total.bytes_received - previous_total.bytes_received) / 1e6 / elapsed_s,
        static_cast<double>(total.bytes_echoed - previous_total.bytes_echoed) / 1e6 / elapsed_s);
    std::cout.flush();
}

static future<> print_final_stats() {
    auto current = co_await collect_server_stats();
    server_stats total;
    fmt::print("\n=== QUIC server shard distribution ===\n");
    for (unsigned shard = 0; shard < current.size(); ++shard) {
        total += current[shard];
        fmt::print(
            "  shard {:2d}: conns={:6d} streams={:8d} rx={:12.2f} MB tx={:12.2f} MB\n",
            shard,
            current[shard].connections_accepted,
            current[shard].streams_completed,
            static_cast<double>(current[shard].bytes_received) / 1e6,
            static_cast<double>(current[shard].bytes_echoed) / 1e6);
    }
    fmt::print(
        "  total:    conns={:6d} streams={:8d} rx={:12.2f} MB tx={:12.2f} MB\n\n",
        total.connections_accepted,
        total.streams_completed,
        static_cast<double>(total.bytes_received) / 1e6,
        static_cast<double>(total.bytes_echoed) / 1e6);
    std::cout.flush();
}

// Collects and prints all shard-local counters every `interval_s` seconds.
static future<> print_stats_loop(unsigned interval_s, abort_source& as) {
    std::vector<server_stats> previous(this_smp_shard_count());
    auto previous_at = std::chrono::steady_clock::now();
    try {
        while (true) {
            co_await sleep_abortable(std::chrono::seconds(interval_s), as);
            auto now = std::chrono::steady_clock::now();
            auto current = co_await collect_server_stats();
            auto elapsed_s = std::chrono::duration<double>(now - previous_at).count();
            print_interval_stats(current, previous, elapsed_s);
            previous = std::move(current);
            previous_at = now;
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
        ("max-udp-payload-size", bpo::value<uint64_t>()->default_value(benchmark_udp_payload_size),
         "Advertised QUIC max UDP payload size for this endpoint")
        ("max-tx-udp-payload-size", bpo::value<uint64_t>()->default_value(benchmark_udp_payload_size),
         "Maximum UDP payload size used for transmitted QUIC packets")
        ("stats-interval", bpo::value<unsigned>()->default_value(0),
         "Throughput stats printing interval in seconds (0 to disable)");

    return app.run(argc, argv, [&app]() -> future<int> {
        sharded_quic_server server;
        abort_source stats_as;
        std::optional<future<>> stats_task;
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address       = cfg["address"].as<std::string>();
            auto port          = cfg["port"].as<uint16_t>();
            auto crt           = cfg["crt"].as<std::string>();
            auto key           = cfg["key"].as<std::string>();
            auto flush_bytes   = cfg["throughput-flush-bytes"].as<size_t>();
            auto max_udp_payload_size = cfg["max-udp-payload-size"].as<uint64_t>();
            auto max_tx_udp_payload_size = cfg["max-tx-udp-payload-size"].as<uint64_t>();
            auto stats_intv    = cfg["stats-interval"].as<unsigned>();
            g_throughput_flush_bytes = flush_bytes > 0 ? flush_bytes : throughput_buffer_size;
            if (max_udp_payload_size < 1200 || max_tx_udp_payload_size < 1200) {
                throw std::runtime_error("--max-udp-payload-size and --max-tx-udp-payload-size must be >= 1200");
            }
            if (max_tx_udp_payload_size > max_udp_payload_size) {
                throw std::runtime_error("--max-tx-udp-payload-size must be <= --max-udp-payload-size");
            }

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
            server_cfg.session_options.transport.congestion_control = congestion_control_algorithm::cubic;
            server_cfg.session_options.transport.max_udp_payload_size = max_udp_payload_size;
            server_cfg.session_options.transport.max_tx_udp_payload_size = max_tx_udp_payload_size;
            server_cfg.session_options.transport.disable_tx_udp_payload_size_shaping = true;

            co_await server.start(std::move(server_cfg));
            co_await server.serve([] {
                return [] (connection session) {
                    return handle_bench_session(std::move(session));
                };
            });
            if (stats_intv > 0) {
                stats_task.emplace(print_stats_loop(stats_intv, stats_as));
            }

            fmt::print("[server] QUIC bench server listening on [{}]:{} with {} shards\n",
                address, port, this_smp_shard_count());
            fmt::print("[server] throughput flush-bytes={}\n", g_throughput_flush_bytes);
            fmt::print("[server] udp-payload={}B tx-udp-payload={}B\n", max_udp_payload_size, max_tx_udp_payload_size);
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
        try { co_await print_final_stats(); } catch (...) {}
        try { co_await server.stop(); } catch (...) {}

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
