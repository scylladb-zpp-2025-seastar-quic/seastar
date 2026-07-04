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
//   'L' -> echo and flush every read for latency measurements
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
#include <seastar/core/sharded.hh>
#include <seastar/net/tls.hh>

#include "../apps/lib/stop_signal.hh"

using namespace seastar;
namespace bpo = boost::program_options;

namespace {

enum class traffic_mode : char {
    bidirectional = 'B',
    unidirectional = 'U',
    latency = 'L',
};
static constexpr size_t throughput_buffer_size = 256 * 1024;
static thread_local size_t g_throughput_flush_bytes = throughput_buffer_size;

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
    case static_cast<char>(traffic_mode::latency):
        return traffic_mode::latency;
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

static thread_local server_stats g_stats;

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
                if (mode != traffic_mode::unidirectional) {
                    co_await output.write(buf.get(), buf.size());
                    buffered_echo_bytes += buf.size();
                    if (mode == traffic_mode::latency
                            || buffered_echo_bytes >= g_throughput_flush_bytes) {
                        co_await output.flush();
                        buffered_echo_bytes = 0;
                    }
                    g_stats.bytes_echoed += buf.size();
                }
            }
            if (mode != traffic_mode::unidirectional && buffered_echo_bytes > 0) {
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


struct tls_bench_server_config {
    socket_address listen_address;
    sstring crt_file;
    sstring key_file;
    size_t flush_bytes = throughput_buffer_size;
};

class tls_bench_server_shard final {
public:
    future<> start(tls_bench_server_config config) {
        g_throughput_flush_bytes = config.flush_bytes;
        _credentials = make_shared<tls::server_credentials>(make_shared<tls::dh_params>());
        _credentials->set_client_auth(tls::client_auth::NONE);
        co_await _credentials->set_x509_key_file(
            config.crt_file, config.key_file, tls::x509_crt_format::PEM);

        listen_options options;
        options.reuse_address = true;
        _server = tls::listen(_credentials, config.listen_address, options);
        _accept_task.emplace(accept_loop(_server, _sessions, _shutdown));
        _started = true;
    }

    future<> stop() {
        if (!_started) {
            co_return;
        }
        _shutdown.request_abort();
        try {
            _server.abort_accept();
        } catch (...) {
        }

        std::exception_ptr error;
        if (_accept_task) {
            try {
                co_await std::move(*_accept_task);
            } catch (...) {
                error = std::current_exception();
            }
            _accept_task.reset();
        }
        try {
            co_await _sessions.close();
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
        }
        _credentials = {};
        _started = false;
        if (error) {
            std::rethrow_exception(error);
        }
    }

private:
    shared_ptr<tls::server_credentials> _credentials;
    server_socket _server;
    gate _sessions;
    abort_source _shutdown;
    std::optional<future<>> _accept_task;
    bool _started = false;
};

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
         "Flush echoed throughput data every N bytes (0 = auto, one output buffer)");

    return app.run(argc, argv, [&app]() -> future<int> {
        sharded<tls_bench_server_shard> server;
        bool shards_started = false;
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address = cfg["address"].as<std::string>();
            auto port = cfg["port"].as<uint16_t>();
            auto flush_bytes = cfg["throughput-flush-bytes"].as<size_t>();

            tls_bench_server_config server_config;
            server_config.listen_address = parse_ipv6_address(address, port);
            server_config.crt_file = cfg["crt"].as<std::string>();
            server_config.key_file = cfg["key"].as<std::string>();
            server_config.flush_bytes = flush_bytes > 0
                ? flush_bytes
                : throughput_buffer_size;

            co_await server.start();
            shards_started = true;
            co_await server.invoke_on_all(
                [server_config] (tls_bench_server_shard& shard) mutable {
                    return shard.start(server_config);
                });

            fmt::print("[server] TLS bench server listening on [{}]:{} with {} shards\n",
                address, port, this_smp_shard_count());
            fmt::print("[server] throughput flush-bytes={}\n", server_config.flush_bytes);
            fmt::print("[server] Ctrl-C to stop.\n");
            std::cout.flush();

            seastar_apps_lib::stop_signal stop_signal;
            co_await stop_signal.wait();
            fmt::print("[server] shutting down...\n");
            std::cout.flush();
        } catch (...) {
            error = std::current_exception();
        }

        if (shards_started) {
            try {
                co_await server.stop();
            } catch (...) {
                if (!error) {
                    error = std::current_exception();
                }
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
