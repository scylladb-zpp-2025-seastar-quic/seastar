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

// TLS/TCP benchmark server.
//
// The client sends a one-byte mode header per connection:
//   'B' -> echo all received data back to the client
//   'U' -> read and discard all received data
//
// Prints throughput statistics every --stats-interval seconds.
// Use alongside tls_bench_client to compare TLS/TCP against QUIC.

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
#include <seastar/core/sleep.hh>
#include <seastar/net/tls.hh>

#include "../apps/lib/stop_signal.hh"

using namespace seastar;
namespace bpo = boost::program_options;

namespace {

enum class traffic_mode : char {
    bidirectional = 'B',
    unidirectional = 'U',
};
static constexpr size_t throughput_buffer_size = 256 * 1024;
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

static traffic_mode parse_mode_header(char wire_mode) {
    switch (wire_mode) {
    case static_cast<char>(traffic_mode::bidirectional):
        return traffic_mode::bidirectional;
    case static_cast<char>(traffic_mode::unidirectional):
        return traffic_mode::unidirectional;
    default:
        throw std::runtime_error(fmt::format("Unknown connection mode '{}'", wire_mode));
    }
}

struct server_stats {
    uint64_t bytes_received = 0;
    uint64_t bytes_echoed = 0;
    uint64_t connections_accepted = 0;
    uint64_t connections_completed = 0;
};

static server_stats g_stats;

static future<> handle_bench_connection(connected_socket conn) {
    conn.set_nodelay(true);

    auto input = conn.input();
    auto output = conn.output(throughput_buffer_size);
    size_t buffered_echo_bytes = 0;

    try {
        auto mode_buf = co_await input.read_exactly(1);
        if (!mode_buf.empty()) {
            auto mode = parse_mode_header(mode_buf.get()[0]);

            while (true) {
                auto buf = co_await input.read();
                if (buf.empty()) {
                    break;
                }

                g_stats.bytes_received += buf.size();
                if (mode == traffic_mode::bidirectional) {
                    co_await output.write(buf.get(), buf.size());
                    buffered_echo_bytes += buf.size();
                    if (buffered_echo_bytes >= g_throughput_flush_bytes) {
                        co_await output.flush();
                        buffered_echo_bytes = 0;
                    }
                    g_stats.bytes_echoed += buf.size();
                }
            }
            if (mode == traffic_mode::bidirectional && buffered_echo_bytes > 0) {
                co_await output.flush();
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[server] connection error: " << e.what() << "\n";
    }

    try {
        co_await output.close();
    } catch (...) {
    }
    try {
        co_await input.close();
    } catch (...) {
    }
    ++g_stats.connections_completed;
}

static future<> accept_loop(server_socket& server, gate& sessions, abort_source& as) {
    while (true) {
        accept_result ar;
        try {
            ar = co_await server.accept();
        } catch (...) {
            if (as.abort_requested()) {
                co_return;
            }
            throw;
        }

        ++g_stats.connections_accepted;
        (void)with_gate(sessions, [conn = std::move(ar.connection)]() mutable {
            return handle_bench_connection(std::move(conn));
        }).handle_exception([](std::exception_ptr ep) {
            try {
                std::rethrow_exception(ep);
            } catch (const std::exception& e) {
                std::cerr << "[server] connection task failed: " << e.what() << "\n";
            }
        }).or_terminate();
    }
}

static future<> print_stats_loop(unsigned interval_s, abort_source& as) {
    uint64_t prev_rx = 0;
    uint64_t prev_tx = 0;

    try {
        while (true) {
            co_await sleep_abortable(std::chrono::seconds(interval_s), as);
            auto rx = g_stats.bytes_received;
            auto tx = g_stats.bytes_echoed;
            auto rx_mb_s = static_cast<double>(rx - prev_rx) / 1e6 / interval_s;
            auto tx_mb_s = static_cast<double>(tx - prev_tx) / 1e6 / interval_s;
            prev_rx = rx;
            prev_tx = tx;

            fmt::print(
                "[server] conns={} conns_done={} rx={:.1f} MB/s tx={:.1f} MB/s\n",
                g_stats.connections_accepted,
                g_stats.connections_completed,
                rx_mb_s,
                tx_mb_s);
            std::cout.flush();
        }
    } catch (const sleep_aborted&) {
    }
}

}

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
        ("address", bpo::value<std::string>()->default_value("::1"),
         "Server IPv6 address")
        ("port", bpo::value<uint16_t>()->default_value(4444),
         "Server TCP port")
        ("crt", bpo::value<std::string>()->default_value("server.crt"),
         "PEM certificate file")
        ("key,k", bpo::value<std::string>()->default_value("server.key"),
         "PEM private-key file")
        ("throughput-flush-bytes", bpo::value<size_t>()->default_value(0),
         "Flush echoed throughput data every N bytes (0 = auto, one output buffer)")
        ("stats-interval", bpo::value<unsigned>()->default_value(1),
         "Throughput stats printing interval in seconds (0 to disable)");

    return app.run(argc, argv, [&app]() -> future<int> {
        server_socket server;
        gate sessions;
        abort_source shutdown_as;
        abort_source stats_as;
        std::optional<future<>> accept_task;
        std::optional<future<>> stats_task;
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address = cfg["address"].as<std::string>();
            auto port = cfg["port"].as<uint16_t>();
            auto crt = cfg["crt"].as<std::string>();
            auto key = cfg["key"].as<std::string>();
            auto flush_bytes = cfg["throughput-flush-bytes"].as<size_t>();
            auto stats_interval = cfg["stats-interval"].as<unsigned>();
            g_throughput_flush_bytes = flush_bytes > 0 ? flush_bytes : throughput_buffer_size;

            auto creds = make_shared<tls::server_credentials>(make_shared<tls::dh_params>());
            creds->set_client_auth(tls::client_auth::NONE);
            co_await creds->set_x509_key_file(crt, key, tls::x509_crt_format::PEM);

            listen_options opts;
            opts.reuse_address = true;
            server = tls::listen(creds, parse_ipv6_address(address, port), opts);

            accept_task.emplace(accept_loop(server, sessions, shutdown_as));
            if (stats_interval > 0) {
                stats_task.emplace(print_stats_loop(stats_interval, stats_as));
            }

            fmt::print("[server] TLS bench server listening on [{}]:{}\n", address, port);
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

        shutdown_as.request_abort();
        stats_as.request_abort();

        try {
            server.abort_accept();
        } catch (...) {
        }

        if (stats_task) {
            try {
                co_await std::move(*stats_task);
            } catch (...) {
            }
        }
        if (accept_task) {
            try {
                co_await std::move(*accept_task);
            } catch (...) {
                if (!error) {
                    error = std::current_exception();
                }
            }
        }
        try {
            co_await sessions.close();
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
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
