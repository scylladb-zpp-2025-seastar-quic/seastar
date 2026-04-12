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

// QUIC benchmark client.
//
// Two benchmark modes (--mode):
//
//   throughput  Opens --connections connections, each with --streams-per-conn
//               streams.  Each stream sends --message-size byte messages as
//               fast as possible for --duration seconds, then closes.
//               Supports both --stream-type bidi (server echoes, RX measured)
//               and --stream-type uni (server discards, TX only measured).
//
//   latency     Opens --connections connections, each with --streams-per-conn
//               bidirectional streams.  Each stream performs sequential
//               ping-pong: send --message-size bytes, await echo, record RTT.
//               Reports p50/p95/p99/p99.9/max/mean RTT at the end.
//               Only --stream-type bidi is supported in this mode.
//
// Run quic_bench_server on the other end before starting this client.

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/core.h>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/when_all.hh>
#include <seastar/quic/quic_client.hh>

using namespace seastar;
using namespace seastar::quic::experimental;
namespace bpo = boost::program_options;

using bm_clock   = std::chrono::steady_clock;
using time_point = bm_clock::time_point;
using us_t       = std::chrono::microseconds;

static constexpr size_t throughput_buffer_size = 256 * 1024;
static constexpr uint64_t throughput_stream_window = 8 * 1024 * 1024;
static constexpr uint64_t throughput_connection_window = 64 * 1024 * 1024;
static constexpr uint64_t throughput_max_stream_window = 16 * 1024 * 1024;
static constexpr uint64_t throughput_stream_limit = 1024;
static constexpr size_t throughput_ack_thresh = 8;
static constexpr size_t throughput_udp_payload_size = 65527;
static constexpr size_t throughput_tx_udp_payload_size = 4096;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

static stream_type parse_stream_type(const std::string& s) {
    if (s == "bidi") { return stream_type::bidirectional; }
    if (s == "uni")  { return stream_type::unidirectional; }
    throw std::runtime_error("Unknown stream-type '" + s + "': expected bidi or uni");
}

static size_t resolve_throughput_flush_messages(size_t configured, size_t msg_size) {
    if (configured > 0) {
        return configured;
    }
    return std::max<size_t>(1, throughput_buffer_size / std::max<size_t>(msg_size, 1));
}

// ---------------------------------------------------------------------------
// Shared result accumulators (single-shard: no atomics needed)
// ---------------------------------------------------------------------------

struct throughput_result {
    uint64_t bytes_sent     = 0;
    uint64_t bytes_received = 0;  // meaningful only for bidi
    uint64_t messages_sent  = 0;
};

// All latency samples in microseconds, collected across all streams.
using latency_samples = std::vector<int64_t>;

// ---------------------------------------------------------------------------
// Per-stream benchmark coroutines
// ---------------------------------------------------------------------------

// Throughput: bidirectional stream.
// Sends as fast as possible until `deadline`; drains the echo concurrently.
static future<> run_bidi_throughput_stream(
        lw_shared_ptr<connection> conn,
        const std::vector<char>&  msg,
        time_point                deadline,
        size_t                    flush_messages,
        throughput_result&        result) {

    auto s   = co_await conn->open_stream({.type = stream_type::bidirectional});
    auto inp = make_lw_shared<input_stream<char>>(s.input());
    // Match the TLS/TCP benchmark buffering in throughput mode.
    auto out = make_lw_shared<output_stream<char>>(s.output(throughput_buffer_size));
    auto bytes_rx = make_lw_shared<uint64_t>(0);
    auto bytes_tx = make_lw_shared<uint64_t>(0);
    auto msgs_tx  = make_lw_shared<uint64_t>(0);

    // Sender: write until deadline, then close the output half.
    auto sender = [out, bytes_tx, msgs_tx, deadline,
                   data = msg.data(), sz = msg.size(), flush_messages]() -> future<> {
        size_t pending_messages = 0;
        while (bm_clock::now() < deadline) {
            co_await out->write(data, sz);
            *bytes_tx += sz;
            ++(*msgs_tx);
            ++pending_messages;
            if (pending_messages >= flush_messages) {
                co_await out->flush();
                pending_messages = 0;
            }
        }
        if (pending_messages > 0) {
            co_await out->flush();
        }
        co_await out->close();
    };

    // Receiver: drain until server closes its end (after echoing everything).
    auto receiver = [inp, bytes_rx]() -> future<> {
        while (true) {
            auto buf = co_await inp->read();
            if (buf.empty()) { co_return; }
            *bytes_rx += buf.size();
        }
    };

    try {
        co_await when_all_succeed(sender(), receiver()).discard_result();
    } catch (const quic_exception& e) {
        if (e.code() != quic_error::closed) { throw; }
    }

    result.bytes_sent     += *bytes_tx;
    result.bytes_received += *bytes_rx;
    result.messages_sent  += *msgs_tx;
}

// Throughput: unidirectional stream (client→server only).
// The server discards data; only TX throughput is measured.
static future<> run_uni_throughput_stream(
        lw_shared_ptr<connection> conn,
        const std::vector<char>&  msg,
        time_point                deadline,
        size_t                    flush_messages,
        throughput_result&        result) {

    auto s   = co_await conn->open_stream({.type = stream_type::unidirectional});
    auto out = s.output(throughput_buffer_size);
    try {
        size_t pending_messages = 0;
        while (bm_clock::now() < deadline) {
            co_await out.write(msg.data(), msg.size());
            result.bytes_sent += msg.size();
            ++result.messages_sent;
            ++pending_messages;
            if (pending_messages >= flush_messages) {
                co_await out.flush();
                pending_messages = 0;
            }
        }
        if (pending_messages > 0) {
            co_await out.flush();
        }
        co_await out.close();
    } catch (const quic_exception& e) {
        if (e.code() != quic_error::closed) { throw; }
    }
}

// Latency: bidirectional ping-pong on a single stream.
// Sends one message, waits for the full echo, records RTT.  Repeats until
// `deadline`.  Appends microsecond RTT values to `samples`.
static future<> run_latency_stream(
        lw_shared_ptr<connection> conn,
        const std::vector<char>&  msg,
        time_point                deadline,
        latency_samples&          samples) {

    auto s        = co_await conn->open_stream({.type = stream_type::bidirectional});
    auto inp      = s.input();
    auto out      = s.output();
    const size_t msg_size = msg.size();

    try {
        while (bm_clock::now() < deadline) {
            auto t0 = bm_clock::now();

            co_await out.write(msg.data(), msg_size);
            co_await out.flush();

            // Receive exactly msg_size bytes (echo may arrive in fragments).
            size_t received = 0;
            bool eof        = false;
            while (received < msg_size && !eof) {
                auto buf = co_await inp.read();
                if (buf.empty()) {
                    eof = true;
                    break;
                }
                received += buf.size();
            }
            if (eof) { break; }

            auto rtt_us = std::chrono::duration_cast<us_t>(bm_clock::now() - t0).count();
            samples.push_back(rtt_us);
        }
        co_await out.close();
        co_await inp.close();
    } catch (const quic_exception& e) {
        if (e.code() != quic_error::closed) { throw; }
    }
}

// ---------------------------------------------------------------------------
// Per-connection runners
// ---------------------------------------------------------------------------

static future<> run_connection_throughput(
        quic_client_config       cfg,
        int                      n_streams,
        stream_type              stype,
        const std::vector<char>& msg,
        time_point               deadline,
        size_t                   flush_messages,
        throughput_result&       result) {

    quic_client client;
    std::exception_ptr err;
    try {
        auto conn = make_lw_shared<connection>(co_await client.connect(cfg));

        std::vector<future<>> futs;
        futs.reserve(n_streams);
        for (int i = 0; i < n_streams; ++i) {
            if (stype == stream_type::bidirectional) {
                futs.push_back(run_bidi_throughput_stream(conn, msg, deadline, flush_messages, result));
            } else {
                futs.push_back(run_uni_throughput_stream(conn, msg, deadline, flush_messages, result));
            }
        }

        auto stream_results = co_await when_all(futs.begin(), futs.end());
        for (auto& f : stream_results) {
            try { f.get(); }
            catch (const std::exception& e) {
                std::cerr << "[client] stream error: " << e.what() << "\n";
            }
        }

        try { co_await conn->close(); } catch (...) {}
    } catch (...) {
        err = std::current_exception();
    }
    try { co_await client.stop(); } catch (...) {}
    if (err) { std::rethrow_exception(err); }
}

static future<> run_connection_latency(
        quic_client_config       cfg,
        int                      n_streams,
        const std::vector<char>& msg,
        time_point               deadline,
        latency_samples&         samples) {

    quic_client client;
    std::exception_ptr err;
    try {
        auto conn = make_lw_shared<connection>(co_await client.connect(cfg));

        std::vector<future<>> futs;
        futs.reserve(n_streams);
        for (int i = 0; i < n_streams; ++i) {
            futs.push_back(run_latency_stream(conn, msg, deadline, samples));
        }

        auto stream_results = co_await when_all(futs.begin(), futs.end());
        for (auto& f : stream_results) {
            try { f.get(); }
            catch (const std::exception& e) {
                std::cerr << "[client] stream error: " << e.what() << "\n";
            }
        }

        try { co_await conn->close(); } catch (...) {}
    } catch (...) {
        err = std::current_exception();
    }
    try { co_await client.stop(); } catch (...) {}
    if (err) { std::rethrow_exception(err); }
}

// ---------------------------------------------------------------------------
// Statistics printers
// ---------------------------------------------------------------------------

static void print_throughput(
        const throughput_result& r,
        double                   elapsed_s,
        stream_type              stype,
        int                      n_conns,
        int                      n_streams_per_conn,
        size_t                   msg_size) {

    fmt::print("\n=== QUIC Throughput Benchmark: {} streams ===\n",
        stype == stream_type::bidirectional ? "bidirectional" : "unidirectional");
    fmt::print("  Connections: {}  Streams/conn: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        n_conns, n_streams_per_conn, msg_size, elapsed_s);
    fmt::print("  TX: {} bytes  ({:.2f} MB/s,  {:.0f} msg/s)\n",
        r.bytes_sent,
        r.bytes_sent  / 1e6 / elapsed_s,
        r.messages_sent / elapsed_s);
    if (stype == stream_type::bidirectional) {
        fmt::print("  RX: {} bytes  ({:.2f} MB/s)\n",
            r.bytes_received,
            r.bytes_received / 1e6 / elapsed_s);
    }
    fmt::print("\n");
    std::cout.flush();
}

static void print_latency(
        const latency_samples& raw_samples,
        double                 elapsed_s,
        stream_type            stype,
        int                    n_conns,
        int                    n_streams_per_conn,
        size_t                 msg_size) {

    fmt::print("\n=== QUIC Latency Benchmark: {} streams ===\n",
        stype == stream_type::bidirectional ? "bidirectional" : "unidirectional");
    fmt::print("  Connections: {}  Streams/conn: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        n_conns, n_streams_per_conn, msg_size, elapsed_s);

    if (raw_samples.empty()) {
        fmt::print("  No samples collected.\n\n");
        std::cout.flush();
        return;
    }

    auto samples = raw_samples;
    std::sort(samples.begin(), samples.end());
    const size_t count = samples.size();

    auto percentile_ms = [&](double p) -> double {
        size_t idx = static_cast<size_t>(p / 100.0 * static_cast<double>(count));
        if (idx >= count) { idx = count - 1; }
        return static_cast<double>(samples[idx]) / 1000.0;  // µs → ms
    };

    double mean_ms = static_cast<double>(
        std::accumulate(samples.begin(), samples.end(), int64_t{0}))
        / static_cast<double>(count) / 1000.0;

    fmt::print("  Samples:  {}\n",   count);
    fmt::print("  mean:     {:.3f} ms\n", mean_ms);
    fmt::print("  p50:      {:.3f} ms\n", percentile_ms(50));
    fmt::print("  p95:      {:.3f} ms\n", percentile_ms(95));
    fmt::print("  p99:      {:.3f} ms\n", percentile_ms(99));
    fmt::print("  p99.9:    {:.3f} ms\n", percentile_ms(99.9));
    fmt::print("  max:      {:.3f} ms\n", static_cast<double>(samples.back()) / 1000.0);
    fmt::print("\n");
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
        ("address", bpo::value<std::string>()->default_value("::1"),
         "Server IPv6 address")
        ("port", bpo::value<uint16_t>()->default_value(4444),
         "Server UDP port")
        ("server-name", bpo::value<std::string>()->default_value("localhost"),
         "TLS server name (SNI)")
        ("ca", bpo::value<std::string>()->default_value("server.crt"),
         "PEM CA/certificate file used to verify the server")
        ("mode", bpo::value<std::string>()->default_value("throughput"),
         "Benchmark mode: throughput or latency")
        ("stream-type", bpo::value<std::string>()->default_value("bidi"),
         "QUIC stream type: bidi (bidirectional) or uni (unidirectional, throughput only)")
        ("connections", bpo::value<int>()->default_value(1),
         "Number of parallel connections")
        ("streams-per-conn", bpo::value<int>()->default_value(1),
         "Number of concurrent streams per connection")
        ("message-size", bpo::value<size_t>()->default_value(65536),
         "Size of each message in bytes (throughput default: 64 KiB)")
        ("throughput-flush-messages", bpo::value<size_t>()->default_value(0),
         "Flush throughput output every N messages (0 = auto, about one output buffer)")
        ("duration", bpo::value<unsigned>()->default_value(10),
         "Benchmark duration in seconds");

    return app.run(argc, argv, [&app]() -> future<int> {
        std::exception_ptr error;
        try {
            auto&& cfg       = app.configuration();
            auto address     = cfg["address"].as<std::string>();
            auto port        = cfg["port"].as<uint16_t>();
            auto server_name = cfg["server-name"].as<std::string>();
            auto ca_file     = cfg["ca"].as<std::string>();
            auto mode        = cfg["mode"].as<std::string>();
            auto stype       = parse_stream_type(cfg["stream-type"].as<std::string>());
            auto n_conns     = cfg["connections"].as<int>();
            auto n_streams   = cfg["streams-per-conn"].as<int>();
            auto msg_size    = cfg["message-size"].as<size_t>();
            auto flush_messages_cfg = cfg["throughput-flush-messages"].as<size_t>();
            auto dur_s       = cfg["duration"].as<unsigned>();

            if (mode != "throughput" && mode != "latency") {
                throw std::runtime_error(
                    "Unknown mode '" + mode + "': expected throughput or latency");
            }
            if (mode == "latency" && stype != stream_type::bidirectional) {
                throw std::runtime_error("Latency mode requires --stream-type bidi");
            }
            if (n_conns < 1 || n_streams < 1) {
                throw std::runtime_error(
                    "--connections and --streams-per-conn must be >= 1");
            }
            if (msg_size < 1) {
                throw std::runtime_error("--message-size must be >= 1");
            }

            // Build the message payload once (filled with 'Q').
            const std::vector<char> msg(msg_size, 'Q');
            const auto flush_messages = resolve_throughput_flush_messages(flush_messages_cfg, msg_size);

            // Base client config – each connection gets its own quic_client.
            quic_client_config base_cfg;
            base_cfg.remote_address = parse_ipv6_address(address, port);
            base_cfg.server_name    = server_name;
            if (!ca_file.empty()) {
                base_cfg.ca_file = ca_file;
            }
            // Transport limits tuned for the actor-based transport engine.
            base_cfg.session_options.max_pending_send_bytes    = 4 * 1024 * 1024;
            base_cfg.session_options.max_pending_receive_bytes = 64 * 1024 * 1024;
            base_cfg.session_options.transport.initial_max_stream_data_bidi_local  = throughput_stream_window;
            base_cfg.session_options.transport.initial_max_stream_data_bidi_remote = throughput_stream_window;
            base_cfg.session_options.transport.initial_max_stream_data_uni         = throughput_stream_window;
            base_cfg.session_options.transport.initial_max_data         = throughput_connection_window;
            base_cfg.session_options.transport.initial_max_streams_bidi = throughput_stream_limit;
            base_cfg.session_options.transport.initial_max_streams_uni  = throughput_stream_limit;
            base_cfg.session_options.transport.max_window = throughput_connection_window;
            base_cfg.session_options.transport.max_stream_window = throughput_max_stream_window;
            base_cfg.session_options.transport.ack_thresh = throughput_ack_thresh;
            base_cfg.session_options.transport.congestion_control = congestion_control_algorithm::bbr;
            base_cfg.session_options.transport.max_udp_payload_size = throughput_udp_payload_size;
            base_cfg.session_options.transport.max_tx_udp_payload_size = throughput_tx_udp_payload_size;
            base_cfg.session_options.transport.disable_tx_udp_payload_size_shaping = true;

            const auto deadline = bm_clock::now() + std::chrono::seconds(dur_s);

            fmt::print(
                "[client] mode={} stream-type={} conns={} streams/conn={} msg={}B dur={}s flush-msgs={}\n",
                mode,
                stype == stream_type::bidirectional ? "bidi" : "uni",
                n_conns, n_streams, msg_size, dur_s, flush_messages);
            std::cout.flush();

            // ------------------------------------------------------------------
            // Throughput benchmark
            // ------------------------------------------------------------------
            if (mode == "throughput") {
                throughput_result total;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(n_conns);
                for (int c = 0; c < n_conns; ++c) {
                    conn_futs.push_back(
                        run_connection_throughput(
                            base_cfg, n_streams, stype, msg, deadline, flush_messages, total));
                }
                auto conn_results = co_await when_all(conn_futs.begin(), conn_futs.end());
                for (auto& f : conn_results) {
                    try { f.get(); }
                    catch (const std::exception& e) {
                        std::cerr << "[client] connection error: " << e.what() << "\n";
                    }
                }

                double elapsed = std::chrono::duration<double>(
                    bm_clock::now() - bench_start).count();
                print_throughput(total, elapsed, stype, n_conns, n_streams, msg_size);

            // ------------------------------------------------------------------
            // Latency benchmark
            // ------------------------------------------------------------------
            } else {
                latency_samples all_samples;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(n_conns);
                for (int c = 0; c < n_conns; ++c) {
                    conn_futs.push_back(
                        run_connection_latency(
                            base_cfg, n_streams, msg, deadline, all_samples));
                }
                auto conn_results = co_await when_all(conn_futs.begin(), conn_futs.end());
                for (auto& f : conn_results) {
                    try { f.get(); }
                    catch (const std::exception& e) {
                        std::cerr << "[client] connection error: " << e.what() << "\n";
                    }
                }

                double elapsed = std::chrono::duration<double>(
                    bm_clock::now() - bench_start).count();
                print_latency(all_samples, elapsed, stype, n_conns, n_streams, msg_size);
            }

        } catch (...) {
            error = std::current_exception();
        }

        if (error) {
            try {
                std::rethrow_exception(error);
            } catch (const std::exception& e) {
                std::cerr << "[client] fatal: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[client] fatal: unknown exception\n";
            }
            co_return 1;
        }
        co_return 0;
    });
}
