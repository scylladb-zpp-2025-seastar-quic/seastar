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

// Integrated RPC-on-QUIC benchmark client.
//
// Same shape as ../../rpc-quic-transport/src/rpc_bench_client.cc, but uses the
// QUIC-integrated RPC API (protocol::make_quic_client) from the
// feature/quic-rpc-integration branch.
//
// Modes:
//
//   throughput  Opens --connections RPC clients. Each one fires --concurrency
//               in-flight echo calls of size --message-size for --duration s.
//               Only call-type=echo is supported here -- the integrated
//               implementation is not yet stable for no_wait/discard.
//
//   latency     Sequential calls per worker, records per-call RTT and reports
//               p50/p95/p99/p99.9/max/mean. Supports call-type echo or ping.
//
// No request cancellations are issued by the benchmark.

#include <arpa/inet.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <numeric>
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
#include <seastar/rpc/rpc.hh>
#include <seastar/rpc/rpc_quic_transport.hh>
#include <seastar/util/log.hh>

using namespace seastar;
namespace bpo = boost::program_options;

using bm_clock   = std::chrono::steady_clock;
using time_point = bm_clock::time_point;
using us_t       = std::chrono::microseconds;

// ---------------------------------------------------------------------------
// Minimal serializer
// ---------------------------------------------------------------------------

struct serializer {};

template <typename T, typename Output>
inline void write_arithmetic_type(Output& out, T v) {
    static_assert(std::is_arithmetic_v<T>, "must be arithmetic type");
    return out.write(reinterpret_cast<const char*>(&v), sizeof(T));
}

template <typename T, typename Input>
inline T read_arithmetic_type(Input& in) {
    static_assert(std::is_arithmetic_v<T>, "must be arithmetic type");
    T v;
    in.read(reinterpret_cast<char*>(&v), sizeof(T));
    return v;
}

template <typename Output>
inline void write(serializer, Output& output, int32_t v)  { return write_arithmetic_type(output, v); }
template <typename Output>
inline void write(serializer, Output& output, uint32_t v) { return write_arithmetic_type(output, v); }
template <typename Output>
inline void write(serializer, Output& output, int64_t v)  { return write_arithmetic_type(output, v); }
template <typename Output>
inline void write(serializer, Output& output, uint64_t v) { return write_arithmetic_type(output, v); }
template <typename Input>
inline int32_t  read(serializer, Input& input, rpc::type<int32_t>)  { return read_arithmetic_type<int32_t>(input); }
template <typename Input>
inline uint32_t read(serializer, Input& input, rpc::type<uint32_t>) { return read_arithmetic_type<uint32_t>(input); }
template <typename Input>
inline int64_t  read(serializer, Input& input, rpc::type<int64_t>)  { return read_arithmetic_type<int64_t>(input); }
template <typename Input>
inline uint64_t read(serializer, Input& input, rpc::type<uint64_t>) { return read_arithmetic_type<uint64_t>(input); }

template <typename Output>
inline void write(serializer, Output& out, const sstring& v) {
    write_arithmetic_type(out, uint32_t(v.size()));
    out.write(v.c_str(), v.size());
}
template <typename Input>
inline sstring read(serializer, Input& in, rpc::type<sstring>) {
    auto size = read_arithmetic_type<uint32_t>(in);
    sstring ret = uninitialized_string(size);
    in.read(ret.data(), size);
    return ret;
}

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

enum class call_type_t { echo, ping };

static call_type_t parse_call_type(const std::string& s) {
    if (s == "echo") { return call_type_t::echo; }
    if (s == "ping") { return call_type_t::ping; }
    if (s == "discard") {
        throw std::runtime_error(
            "call-type discard is not supported by the integrated RPC/QUIC "
            "benchmark (no_wait is not stable in this implementation)");
    }
    throw std::runtime_error("Unknown call-type '" + s + "': expected echo or ping");
}

// ---------------------------------------------------------------------------
// Result accumulators
// ---------------------------------------------------------------------------

struct throughput_result {
    uint64_t   bytes_sent     = 0;
    uint64_t   bytes_received = 0;
    uint64_t   calls_done     = 0;
    // When the last successful call returned. Used to compute "bench window"
    // elapsed time excluding any teardown hang in client->stop(): integrated
    // QUIC sometimes hangs ~60s on stop, which would otherwise make
    // wall_clock_elapsed inflate and throughput appear collapsed.
    time_point last_call_end{};
};

using latency_samples = std::vector<int64_t>;  // microseconds

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

using rpc_proto = rpc::protocol<serializer>;

template <typename CallFn>
static future<> run_throughput_worker(
        CallFn                       call_fn,
        size_t                       msg_size,
        time_point                   deadline,
        throughput_result&           result) {
    try {
        while (bm_clock::now() < deadline) {
            co_await call_fn();
            const auto now = bm_clock::now();
            result.bytes_sent     += msg_size;
            result.bytes_received += msg_size;
            ++result.calls_done;
            if (now > result.last_call_end) {
                result.last_call_end = now;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[client] throughput worker error: " << e.what() << "\n";
    }
}

template <typename CallFn>
static future<> run_latency_worker(
        CallFn                       call_fn,
        time_point                   deadline,
        latency_samples&             samples) {
    try {
        while (bm_clock::now() < deadline) {
            auto t0 = bm_clock::now();
            co_await call_fn();
            auto rtt_us = std::chrono::duration_cast<us_t>(bm_clock::now() - t0).count();
            samples.push_back(rtt_us);
        }
    } catch (const std::exception& e) {
        std::cerr << "[client] latency worker error: " << e.what() << "\n";
    }
}

// ---------------------------------------------------------------------------
// Per-connection runners
// ---------------------------------------------------------------------------

static future<> run_connection_throughput(
        rpc_proto&                                proto,
        quic::experimental::quic_client_config    qcfg,
        int                                       concurrency,
        const sstring&                            payload,
        time_point                                deadline,
        throughput_result&                        result) {

    rpc::client_options co;
    auto client = co_await proto.make_quic_client(co, std::move(qcfg));

    auto echo = proto.make_client<sstring (sstring)>(1);
    const size_t msg_size = payload.size();

    std::vector<future<>> futs;
    futs.reserve(concurrency);
    for (int i = 0; i < concurrency; ++i) {
        auto call_fn = [&, p = payload]() mutable {
            return echo(*client, p).discard_result();
        };
        futs.push_back(run_throughput_worker(std::move(call_fn), msg_size, deadline, result));
    }

    auto worker_results = co_await when_all(futs.begin(), futs.end());
    for (auto& f : worker_results) {
        try { f.get(); }
        catch (const std::exception& e) {
            std::cerr << "[client] worker error: " << e.what() << "\n";
        }
    }
    try { co_await client->stop(); } catch (...) {}
}

static future<> run_connection_latency(
        rpc_proto&                                proto,
        quic::experimental::quic_client_config    qcfg,
        int                                       concurrency,
        call_type_t                               ctype,
        const sstring&                            payload,
        time_point                                deadline,
        latency_samples&                          samples) {

    rpc::client_options co;
    auto client = co_await proto.make_quic_client(co, std::move(qcfg));

    auto echo = proto.make_client<sstring (sstring)>(1);
    auto ping = proto.make_client<void ()>(3);

    std::vector<future<>> futs;
    futs.reserve(concurrency);
    for (int i = 0; i < concurrency; ++i) {
        if (ctype == call_type_t::ping) {
            auto call_fn = [&]() mutable {
                return ping(*client);
            };
            futs.push_back(run_latency_worker(std::move(call_fn), deadline, samples));
        } else {
            auto call_fn = [&, p = payload]() mutable {
                return echo(*client, p).discard_result();
            };
            futs.push_back(run_latency_worker(std::move(call_fn), deadline, samples));
        }
    }

    auto worker_results = co_await when_all(futs.begin(), futs.end());
    for (auto& f : worker_results) {
        try { f.get(); }
        catch (const std::exception& e) {
            std::cerr << "[client] worker error: " << e.what() << "\n";
        }
    }
    try { co_await client->stop(); } catch (...) {}
}

// ---------------------------------------------------------------------------
// Stats printers
// ---------------------------------------------------------------------------

static const char* call_type_name(call_type_t c) {
    switch (c) {
        case call_type_t::echo: return "echo";
        case call_type_t::ping: return "ping";
    }
    return "?";
}

static void print_throughput(
        const throughput_result& r,
        double                   elapsed_s,
        call_type_t              ctype,
        int                      n_conns,
        int                      concurrency,
        size_t                   msg_size) {

    fmt::print("\n=== Integrated RPC/QUIC Throughput Benchmark: call-type={} ===\n",
        call_type_name(ctype));
    fmt::print("  Connections: {}  Concurrency/conn: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        n_conns, concurrency, msg_size, elapsed_s);
    fmt::print("  Calls: {}  ({:.0f} calls/s)\n",
        r.calls_done, r.calls_done / elapsed_s);
    fmt::print("  TX: {} bytes  ({:.2f} MB/s)\n",
        r.bytes_sent, r.bytes_sent / 1e6 / elapsed_s);
    fmt::print("  RX: {} bytes  ({:.2f} MB/s)\n",
        r.bytes_received, r.bytes_received / 1e6 / elapsed_s);
    fmt::print("\n");
    std::cout.flush();
}

static void print_latency(
        const latency_samples& raw_samples,
        double                 elapsed_s,
        call_type_t            ctype,
        int                    n_conns,
        int                    concurrency,
        size_t                 msg_size) {

    fmt::print("\n=== Integrated RPC/QUIC Latency Benchmark: call-type={} ===\n",
        call_type_name(ctype));
    fmt::print("  Connections: {}  Concurrency/conn: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        n_conns, concurrency, msg_size, elapsed_s);

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
        return static_cast<double>(samples[idx]) / 1000.0;
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
        ("port", bpo::value<uint16_t>()->default_value(10000),
         "Server UDP port")
        ("server-name", bpo::value<std::string>()->default_value("localhost"),
         "TLS server name (SNI)")
        ("ca", bpo::value<std::string>()->default_value("server.crt"),
         "PEM CA/certificate file used to verify the server")
        ("mode", bpo::value<std::string>()->default_value("throughput"),
         "Benchmark mode: throughput or latency")
        ("call-type", bpo::value<std::string>()->default_value("echo"),
         "RPC call type: echo (round-trip) or ping (zero-payload, latency only). "
         "discard/no_wait is intentionally unsupported in the integrated suite.")
        ("connections", bpo::value<int>()->default_value(1),
         "Number of parallel RPC clients")
        ("concurrency", bpo::value<int>()->default_value(1),
         "In-flight calls per client")
        ("message-size", bpo::value<size_t>()->default_value(65536),
         "Payload size in bytes (throughput default: 64 KiB)")
        ("duration", bpo::value<unsigned>()->default_value(10),
         "Benchmark duration in seconds");

    return app.run(argc, argv, [&app]() -> future<int> {
        static logger log("rpc_quic_bench");
        std::exception_ptr error;

        rpc_proto proto(serializer{});
        proto.set_logger(&log);

        try {
            auto&& cfg       = app.configuration();
            auto address     = cfg["address"].as<std::string>();
            auto port        = cfg["port"].as<uint16_t>();
            auto server_name = cfg["server-name"].as<std::string>();
            auto ca_file     = cfg["ca"].as<std::string>();
            auto mode        = cfg["mode"].as<std::string>();
            auto ctype       = parse_call_type(cfg["call-type"].as<std::string>());
            auto n_conns     = cfg["connections"].as<int>();
            auto concurrency = cfg["concurrency"].as<int>();
            auto msg_size    = cfg["message-size"].as<size_t>();
            auto dur_s       = cfg["duration"].as<unsigned>();

            if (mode != "throughput" && mode != "latency") {
                throw std::runtime_error(
                    "Unknown mode '" + mode + "': expected throughput or latency");
            }
            if (mode == "throughput" && ctype == call_type_t::ping) {
                throw std::runtime_error("call-type ping is latency-only");
            }
            if (n_conns < 1 || concurrency < 1) {
                throw std::runtime_error("--connections and --concurrency must be >= 1");
            }
            if (msg_size < 1) {
                throw std::runtime_error("--message-size must be >= 1");
            }

            sstring payload = uninitialized_string(msg_size);
            std::fill(payload.data(), payload.data() + msg_size, 'Q');

            auto addr = parse_ipv6_address(address, port);

            auto make_client_cfg = [&]() {
                quic::experimental::quic_client_config c;
                c.remote_address = addr;
                c.server_name    = server_name;
                if (!ca_file.empty()) { c.ca_file = ca_file; }
                c.alpns = {sstring("seastar-rpc")};
                c.session_options.max_pending_send_bytes    = 4 * 1024 * 1024;
                c.session_options.max_pending_receive_bytes = 4 * 1024 * 1024;
                c.session_options.transport.initial_max_stream_data_bidi_local  = 4 * 1024 * 1024;
                c.session_options.transport.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
                c.session_options.transport.initial_max_data         = 64 * 1024 * 1024;
                c.session_options.transport.initial_max_streams_bidi = 1u << 24;
                return c;
            };

            const auto deadline = bm_clock::now() + std::chrono::seconds(dur_s);

            fmt::print(
                "[client] mode={} call-type={} conns={} concurrency/conn={} msg={}B dur={}s\n",
                mode, call_type_name(ctype), n_conns, concurrency, msg_size, dur_s);
            std::cout.flush();

            if (mode == "throughput") {
                throughput_result total;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(n_conns);
                for (int c = 0; c < n_conns; ++c) {
                    conn_futs.push_back(
                        run_connection_throughput(
                            proto, make_client_cfg(),
                            concurrency, payload, deadline, total));
                }
                auto conn_results = co_await when_all(conn_futs.begin(), conn_futs.end());
                for (auto& f : conn_results) {
                    try { f.get(); }
                    catch (const std::exception& e) {
                        std::cerr << "[client] connection error: " << e.what() << "\n";
                    }
                }

                // Use the "bench window" elapsed time (start → last successful
                // call), not the wall clock until when_all() resolves. The
                // integrated stack can hang ~60s in client->stop() on teardown
                // for 64 KB configs; using wall clock would inflate elapsed
                // and report a misleadingly low throughput. If no calls
                // succeeded, fall back to wall clock (still 0/0 = NaN, but
                // calls_done=0 makes that obvious).
                const auto end = total.last_call_end != time_point{}
                                     ? total.last_call_end
                                     : bm_clock::now();
                double elapsed = std::chrono::duration<double>(end - bench_start).count();
                print_throughput(total, elapsed, ctype, n_conns, concurrency, msg_size);
            } else {
                latency_samples all_samples;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(n_conns);
                for (int c = 0; c < n_conns; ++c) {
                    conn_futs.push_back(
                        run_connection_latency(
                            proto, make_client_cfg(),
                            concurrency, ctype, payload, deadline, all_samples));
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
                print_latency(all_samples, elapsed, ctype, n_conns, concurrency, msg_size);
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
