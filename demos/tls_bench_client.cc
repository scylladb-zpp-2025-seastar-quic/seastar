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

// TLS/TCP benchmark client.
//
// Modes (--mode):
//
//   throughput  Opens --connections TLS connections. Each connection sends
//               --message-size byte messages as fast as possible for
//               --duration seconds, then closes. With --stream-type bidi the
//               server echoes all data; with --stream-type uni it discards it.
//
//   latency     Opens --connections TLS connections. Each connection performs
//               sequential ping-pong: send --message-size bytes, await the full
//               echo, record RTT. Reports p50/p95/p99/p99.9/max/mean RTT.
//
// Run tls_bench_server on the other end before starting this client.

#include <arpa/inet.h>

#include <algorithm>
#include <array>
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
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/when_all.hh>
#include <seastar/net/tls.hh>

using namespace seastar;
namespace bpo = boost::program_options;

namespace {

using bm_clock = std::chrono::steady_clock;
using time_point = bm_clock::time_point;
using us_t = std::chrono::microseconds;
static constexpr size_t throughput_buffer_size = 256 * 1024;

enum class traffic_mode : char {
    bidirectional = 'B',
    unidirectional = 'U',
};

struct throughput_result {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t messages_sent = 0;
};

using latency_samples = std::vector<int64_t>;

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

static traffic_mode parse_traffic_mode(const std::string& s) {
    if (s == "bidi") {
        return traffic_mode::bidirectional;
    }
    if (s == "uni") {
        return traffic_mode::unidirectional;
    }
    throw std::runtime_error("Unknown stream-type '" + s + "': expected bidi or uni");
}

static const char* traffic_mode_name(traffic_mode mode) {
    return mode == traffic_mode::bidirectional ? "bidi" : "uni";
}

static size_t resolve_throughput_flush_messages(size_t configured, size_t msg_size) {
    if (configured > 0) {
        return configured;
    }
    return std::max<size_t>(1, throughput_buffer_size / std::max<size_t>(msg_size, 1));
}

static future<shared_ptr<tls::certificate_credentials>> make_client_credentials(
        const std::string& ca_file) {
    auto creds = make_shared<tls::certificate_credentials>();
    if (ca_file.empty()) {
        co_await creds->set_system_trust();
    } else {
        co_await creds->set_x509_trust_file(ca_file, tls::x509_crt_format::PEM);
    }
    co_return creds;
}

static future<connected_socket> connect_tls(
        shared_ptr<tls::certificate_credentials> creds,
        socket_address remote,
        const sstring& server_name) {
    tls::tls_options options;
    options.server_name = server_name;
    auto conn = co_await tls::connect(creds, remote, options);
    conn.set_nodelay(true);
    co_return conn;
}

static future<> write_mode_header(output_stream<char>& out, traffic_mode mode) {
    std::array<char, 1> header{static_cast<char>(mode)};
    co_await out.write(header.data(), header.size());
    co_await out.flush();
}

static future<> run_bidi_throughput_connection(
        shared_ptr<tls::certificate_credentials> creds,
        socket_address remote,
        const sstring& server_name,
        const std::vector<char>& msg,
        time_point deadline,
        size_t flush_messages,
        throughput_result& result) {

    auto conn = co_await connect_tls(std::move(creds), remote, server_name);
    auto input = make_lw_shared<input_stream<char>>(conn.input());
    auto output = make_lw_shared<output_stream<char>>(conn.output(throughput_buffer_size));
    auto bytes_rx = make_lw_shared<uint64_t>(0);
    auto bytes_tx = make_lw_shared<uint64_t>(0);
    auto msgs_tx = make_lw_shared<uint64_t>(0);

    co_await write_mode_header(*output, traffic_mode::bidirectional);

    auto sender = [output, bytes_tx, msgs_tx, deadline,
                   data = msg.data(), size = msg.size(), flush_messages]() -> future<> {
        size_t pending_messages = 0;
        while (bm_clock::now() < deadline) {
            co_await output->write(data, size);
            *bytes_tx += size;
            ++(*msgs_tx);
            ++pending_messages;
            if (pending_messages >= flush_messages) {
                co_await output->flush();
                pending_messages = 0;
            }
        }
        if (pending_messages > 0) {
            co_await output->flush();
        }
        co_await output->close();
    };

    auto receiver = [input, bytes_rx]() -> future<> {
        while (true) {
            auto buf = co_await input->read();
            if (buf.empty()) {
                co_return;
            }
            *bytes_rx += buf.size();
        }
    };

    std::exception_ptr error;
    try {
        co_await when_all_succeed(sender(), receiver()).discard_result();
    } catch (...) {
        error = std::current_exception();
    }

    try {
        co_await output->close();
    } catch (...) {
    }
    try {
        co_await input->close();
    } catch (...) {
    }

    if (error) {
        std::rethrow_exception(error);
    }

    result.bytes_sent += *bytes_tx;
    result.bytes_received += *bytes_rx;
    result.messages_sent += *msgs_tx;
}

static future<> run_uni_throughput_connection(
        shared_ptr<tls::certificate_credentials> creds,
        socket_address remote,
        const sstring& server_name,
        const std::vector<char>& msg,
        time_point deadline,
        size_t flush_messages,
        throughput_result& result) {

    auto conn = co_await connect_tls(std::move(creds), remote, server_name);
    auto output = conn.output(throughput_buffer_size);

    co_await write_mode_header(output, traffic_mode::unidirectional);

    size_t pending_messages = 0;
    while (bm_clock::now() < deadline) {
        co_await output.write(msg.data(), msg.size());
        result.bytes_sent += msg.size();
        ++result.messages_sent;
        ++pending_messages;
        if (pending_messages >= flush_messages) {
            co_await output.flush();
            pending_messages = 0;
        }
    }
    if (pending_messages > 0) {
        co_await output.flush();
    }
    co_await output.close();
}

static future<> run_latency_connection(
        shared_ptr<tls::certificate_credentials> creds,
        socket_address remote,
        const sstring& server_name,
        const std::vector<char>& msg,
        time_point deadline,
        latency_samples& samples) {

    auto conn = co_await connect_tls(std::move(creds), remote, server_name);
    auto input = conn.input();
    auto output = conn.output();
    const auto msg_size = msg.size();

    co_await write_mode_header(output, traffic_mode::bidirectional);

    while (bm_clock::now() < deadline) {
        auto t0 = bm_clock::now();
        co_await output.write(msg.data(), msg_size);
        co_await output.flush();

        size_t received = 0;
        bool eof = false;
        while (received < msg_size && !eof) {
            auto buf = co_await input.read();
            if (buf.empty()) {
                eof = true;
                break;
            }
            received += buf.size();
        }

        if (eof) {
            break;
        }
        samples.push_back(std::chrono::duration_cast<us_t>(bm_clock::now() - t0).count());
    }

    try {
        co_await output.close();
    } catch (...) {
    }
    try {
        co_await input.close();
    } catch (...) {
    }
}

static future<> run_connection_throughput(
        shared_ptr<tls::certificate_credentials> creds,
        socket_address remote,
        const sstring& server_name,
        traffic_mode mode,
        const std::vector<char>& msg,
        time_point deadline,
        size_t flush_messages,
        throughput_result& result) {
    if (mode == traffic_mode::bidirectional) {
        co_await run_bidi_throughput_connection(
            std::move(creds), remote, server_name, msg, deadline, flush_messages, result);
    } else {
        co_await run_uni_throughput_connection(
            std::move(creds), remote, server_name, msg, deadline, flush_messages, result);
    }
}

static void print_throughput(
        const throughput_result& result,
        double elapsed_s,
        traffic_mode mode,
        int connections,
        size_t msg_size) {
    fmt::print("\n=== TLS/TCP Throughput Benchmark: {} ===\n", traffic_mode_name(mode));
    fmt::print("  Connections: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        connections, msg_size, elapsed_s);
    fmt::print("  TX: {} bytes  ({:.2f} MB/s, {:.0f} msg/s)\n",
        result.bytes_sent,
        result.bytes_sent / 1e6 / elapsed_s,
        result.messages_sent / elapsed_s);
    if (mode == traffic_mode::bidirectional) {
        fmt::print("  RX: {} bytes  ({:.2f} MB/s)\n",
            result.bytes_received,
            result.bytes_received / 1e6 / elapsed_s);
    }
    fmt::print("\n");
    std::cout.flush();
}

static void print_latency(
        const latency_samples& raw_samples,
        double elapsed_s,
        int connections,
        size_t msg_size) {
    fmt::print("\n=== TLS/TCP Latency Benchmark: bidi ===\n");
    fmt::print("  Connections: {}  Msg size: {} B  Elapsed: {:.2f} s\n",
        connections, msg_size, elapsed_s);

    if (raw_samples.empty()) {
        fmt::print("  No samples collected.\n\n");
        std::cout.flush();
        return;
    }

    auto samples = raw_samples;
    std::sort(samples.begin(), samples.end());
    const auto count = samples.size();

    auto percentile_ms = [&](double p) {
        size_t idx = static_cast<size_t>(p / 100.0 * static_cast<double>(count));
        if (idx >= count) {
            idx = count - 1;
        }
        return static_cast<double>(samples[idx]) / 1000.0;
    };

    const auto mean_ms = static_cast<double>(
        std::accumulate(samples.begin(), samples.end(), int64_t{0}))
        / static_cast<double>(count) / 1000.0;

    fmt::print("  Samples:  {}\n", count);
    fmt::print("  mean:     {:.3f} ms\n", mean_ms);
    fmt::print("  p50:      {:.3f} ms\n", percentile_ms(50));
    fmt::print("  p95:      {:.3f} ms\n", percentile_ms(95));
    fmt::print("  p99:      {:.3f} ms\n", percentile_ms(99));
    fmt::print("  p99.9:    {:.3f} ms\n", percentile_ms(99.9));
    fmt::print("  max:      {:.3f} ms\n", static_cast<double>(samples.back()) / 1000.0);
    fmt::print("\n");
    std::cout.flush();
}

}

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
        ("address", bpo::value<std::string>()->default_value("::1"),
         "Server IPv6 address")
        ("port", bpo::value<uint16_t>()->default_value(4444),
         "Server TCP port")
        ("server-name", bpo::value<std::string>()->default_value("localhost"),
         "TLS server name (SNI)")
        ("ca", bpo::value<std::string>()->default_value("server.crt"),
         "PEM CA/certificate file used to verify the server")
        ("mode", bpo::value<std::string>()->default_value("throughput"),
         "Benchmark mode: throughput or latency")
        ("stream-type", bpo::value<std::string>()->default_value("bidi"),
         "Traffic mode: bidi (echo) or uni (discard, throughput only)")
        ("connections", bpo::value<int>()->default_value(1),
         "Number of parallel TLS connections")
        ("message-size", bpo::value<size_t>()->default_value(65536),
         "Size of each message in bytes")
        ("throughput-flush-messages", bpo::value<size_t>()->default_value(0),
         "Flush throughput output every N messages (0 = auto, about one output buffer)")
        ("duration", bpo::value<unsigned>()->default_value(10),
         "Benchmark duration in seconds");

    return app.run(argc, argv, [&app]() -> future<int> {
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address = cfg["address"].as<std::string>();
            auto port = cfg["port"].as<uint16_t>();
            auto server_name = sstring(cfg["server-name"].as<std::string>());
            auto ca_file = cfg["ca"].as<std::string>();
            auto bench_mode = cfg["mode"].as<std::string>();
            auto traffic = parse_traffic_mode(cfg["stream-type"].as<std::string>());
            auto connections = cfg["connections"].as<int>();
            auto msg_size = cfg["message-size"].as<size_t>();
            auto flush_messages_cfg = cfg["throughput-flush-messages"].as<size_t>();
            auto duration_s = cfg["duration"].as<unsigned>();

            if (bench_mode != "throughput" && bench_mode != "latency") {
                throw std::runtime_error(
                    "Unknown mode '" + bench_mode + "': expected throughput or latency");
            }
            if (bench_mode == "latency" && traffic != traffic_mode::bidirectional) {
                throw std::runtime_error("Latency mode requires --stream-type bidi");
            }
            if (connections < 1) {
                throw std::runtime_error("--connections must be >= 1");
            }
            if (msg_size < 1) {
                throw std::runtime_error("--message-size must be >= 1");
            }

            const auto remote = parse_ipv6_address(address, port);
            const auto creds = co_await make_client_credentials(ca_file);
            const std::vector<char> msg(msg_size, 'T');
            const auto flush_messages = resolve_throughput_flush_messages(flush_messages_cfg, msg_size);
            const auto deadline = bm_clock::now() + std::chrono::seconds(duration_s);

            fmt::print(
                "[client] mode={} stream-type={} conns={} msg={}B dur={}s flush-msgs={}\n",
                bench_mode,
                traffic_mode_name(traffic),
                connections,
                msg_size,
                duration_s,
                flush_messages);
            std::cout.flush();

            if (bench_mode == "throughput") {
                throughput_result total;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(connections);
                for (int i = 0; i < connections; ++i) {
                    conn_futs.push_back(run_connection_throughput(
                        creds, remote, server_name, traffic, msg, deadline, flush_messages, total));
                }

                auto results = co_await when_all(conn_futs.begin(), conn_futs.end());
                for (auto& f : results) {
                    try {
                        f.get();
                    } catch (const std::exception& e) {
                        std::cerr << "[client] connection error: " << e.what() << "\n";
                    }
                }

                const auto elapsed = std::chrono::duration<double>(
                    bm_clock::now() - bench_start).count();
                print_throughput(total, elapsed, traffic, connections, msg_size);
            } else {
                latency_samples all_samples;
                const auto bench_start = bm_clock::now();

                std::vector<future<>> conn_futs;
                conn_futs.reserve(connections);
                for (int i = 0; i < connections; ++i) {
                    conn_futs.push_back(run_latency_connection(
                        creds, remote, server_name, msg, deadline, all_samples));
                }

                auto results = co_await when_all(conn_futs.begin(), conn_futs.end());
                for (auto& f : results) {
                    try {
                        f.get();
                    } catch (const std::exception& e) {
                        std::cerr << "[client] connection error: " << e.what() << "\n";
                    }
                }

                const auto elapsed = std::chrono::duration<double>(
                    bm_clock::now() - bench_start).count();
                print_latency(all_samples, elapsed, connections, msg_size);
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
