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

// Integrated RPC-on-QUIC benchmark server.
//
// Same shape as ../../rpc-quic-transport/src/rpc_bench_server.cc, but uses the
// QUIC-integrated RPC API from feature/quic-rpc-integration:
//   - a QUIC-backed rpc::server acceptor instead of an rpc_quic_adapters socket
//   - header <seastar/rpc/rpc_quic_transport.hh>
//
// The integrated implementation is currently stable only for "well-behaved"
// clients (no cancellations, no no_wait calls). To stay within that envelope
// this benchmark only registers two verbs:
//
//   verb 1  echo(sstring) -> sstring   -- returns the received payload
//   verb 3  ping() -> void              -- zero-payload round-trip
//
// (Verb id 2 / no_wait "discard" is intentionally not registered; the matching
//  client also omits it.)

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
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/quic/quic_server.hh>
#include <seastar/rpc/rpc.hh>
#include <seastar/rpc/rpc_quic_transport.hh>
#include <seastar/util/log.hh>

#include "../../apps/lib/stop_signal.hh"

using namespace seastar;
namespace bpo = boost::program_options;

// ---------------------------------------------------------------------------
// Minimal serializer -- matches the transport-suite benchmarks
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

struct server_stats {
    uint64_t bytes_received = 0;
    uint64_t bytes_echoed   = 0;
    uint64_t calls_echo     = 0;
    uint64_t calls_ping     = 0;
};

static server_stats g_stats;

static future<> print_stats_loop(unsigned interval_s, abort_source& as) {
    uint64_t prev_rx = 0, prev_tx = 0;
    uint64_t prev_calls = 0;
    try {
        while (true) {
            co_await sleep_abortable(std::chrono::seconds(interval_s), as);
            uint64_t rx = g_stats.bytes_received;
            uint64_t tx = g_stats.bytes_echoed;
            uint64_t calls = g_stats.calls_echo + g_stats.calls_ping;
            double rx_mb_s = static_cast<double>(rx - prev_rx) / 1e6 / interval_s;
            double tx_mb_s = static_cast<double>(tx - prev_tx) / 1e6 / interval_s;
            double call_rate = static_cast<double>(calls - prev_calls) / interval_s;
            prev_rx = rx; prev_tx = tx; prev_calls = calls;
            fmt::print(
                "[server] calls/s={:.0f} echo={} ping={} rx={:.1f} MB/s tx={:.1f} MB/s\n",
                call_rate,
                g_stats.calls_echo, g_stats.calls_ping,
                rx_mb_s, tx_mb_s);
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
        ("port", bpo::value<uint16_t>()->default_value(10000),
         "Server UDP port")
        ("crt", bpo::value<std::string>()->default_value("server.crt"),
         "PEM certificate file")
        ("key,k", bpo::value<std::string>()->default_value("server.key"),
         "PEM private-key file")
        ("stats-interval", bpo::value<unsigned>()->default_value(1),
         "Stats printing interval in seconds (0 to disable)")
        ("max-memory", bpo::value<uint64_t>()->default_value(256'000'000),
         "RPC server max in-flight memory (bytes)");

    return app.run(argc, argv, [&app]() -> future<int> {
        static logger log("rpc_quic_bench");
        std::exception_ptr error;
        abort_source stats_as;
        std::optional<future<>> stats_task;

        rpc::protocol<serializer> myrpc(serializer{});
        myrpc.set_logger(&log);

        // verb 1: echo payload back
        myrpc.register_handler(1, [](sstring payload) {
            g_stats.bytes_received += payload.size();
            g_stats.bytes_echoed   += payload.size();
            ++g_stats.calls_echo;
            return payload;
        });
        // verb 3: ping -> empty reply
        myrpc.register_handler(3, []() {
            ++g_stats.calls_ping;
            return make_ready_future<>();
        });

        std::unique_ptr<rpc::protocol<serializer>::server> server;

        try {
            auto&& cfg = app.configuration();
            auto address    = cfg["address"].as<std::string>();
            auto port       = cfg["port"].as<uint16_t>();
            auto crt        = cfg["crt"].as<std::string>();
            auto key        = cfg["key"].as<std::string>();
            auto stats_intv = cfg["stats-interval"].as<unsigned>();
            auto max_mem    = cfg["max-memory"].as<uint64_t>();

            auto listen_addr = parse_ipv6_address(address, port);

            quic::experimental::quic_server_config server_cfg;
            server_cfg.listen_address = listen_addr;
            server_cfg.crt_file = crt;
            server_cfg.key_file = key;
            server_cfg.alpns = {sstring("seastar-rpc")};
            server_cfg.session_options.max_pending_send_bytes    = 4 * 1024 * 1024;
            server_cfg.session_options.max_pending_receive_bytes = 4 * 1024 * 1024;
            server_cfg.session_options.transport.initial_max_stream_data_bidi_local  = 4 * 1024 * 1024;
            server_cfg.session_options.transport.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
            server_cfg.session_options.transport.initial_max_data        = 64 * 1024 * 1024;
            server_cfg.session_options.transport.initial_max_streams_bidi = 1u << 24;

            rpc::resource_limits limits;
            limits.bloat_factor       = 1;
            limits.basic_request_size = 0;
            limits.max_memory         = max_mem;

            rpc::server_options so;

            server = std::make_unique<rpc::protocol<serializer>::server>(
                    myrpc, so, std::move(server_cfg), limits);

            if (stats_intv > 0) {
                stats_task.emplace(print_stats_loop(stats_intv, stats_as));
            }

            fmt::print("[server] RPC bench server listening on [{}]:{}\n", address, port);
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
        if (server) {
            try { co_await server->stop(); } catch (...) {}
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
