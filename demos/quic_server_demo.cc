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

#include <arpa/inet.h>

#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/reactor.hh>
#include <seastar/quic/quic_server.hh>

#include "../apps/lib/stop_signal.hh"

using namespace seastar;
using namespace seastar::quic::experimental;
namespace bpo = boost::program_options;

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

static future<> handle_session(connection session, bool verbose, uint64_t conn_id) {
    try {
        while (session.is_open()) {
            auto msg = co_await session.receive();
            if (verbose) {
                std::cout << "[server conn#" << conn_id << "] recv sid=" << msg.stream
                          << " bytes=" << msg.payload.size() << "\n";
            } else {
                std::cout.write(msg.payload.get(), static_cast<std::streamsize>(msg.payload.size()));
                if (msg.payload.size() && msg.payload.get()[msg.payload.size() - 1] != '\n') {
                    std::cout << "\n";
                }
            }
            std::cout.flush();

            co_await session.send(msg.stream, std::move(msg.payload), msg.fin);
        }
    } catch (const quic_exception& e) {
        if (e.code() != quic_error::closed) {
            std::cerr << "[server conn#" << conn_id << "] session error: " << e.what() << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[server conn#" << conn_id << "] session exception: " << e.what() << "\n";
    }

    try {
        co_await session.close();
    } catch (...) {
    }
}

static future<> accept_loop(quic_server& server, gate& sessions, bool verbose) {
    uint64_t next_conn_id = 1;
    while (true) {
        connection session;
        try {
            session = co_await server.accept();
        } catch (const quic_exception& e) {
            if (e.code() == quic_error::closed) {
                co_return;
            }
            throw;
        }
        auto conn_id = next_conn_id++;
        if (verbose) {
            std::cout << "[server conn#" << conn_id << "] accepted\n";
            std::cout.flush();
        }

        (void)with_gate(
          sessions, [session = std::move(session), verbose, conn_id]() mutable { return handle_session(std::move(session), verbose, conn_id); })
          .handle_exception([](std::exception_ptr ep) {
              try {
                  std::rethrow_exception(ep);
              } catch (const std::exception& e) {
                  std::cerr << "[server] connection task failed: " << e.what() << "\n";
              }
          })
          .or_terminate();
    }
}

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
      ("address", bpo::value<std::string>()->default_value("::1"), "Server IPv6 address")
      ("port", bpo::value<uint16_t>()->default_value(4444), "Server UDP port")
      ("crt", bpo::value<std::string>()->default_value("server.crt"), "PEM certificate file")
      ("key,k", bpo::value<std::string>()->default_value("server.key"), "PEM key file")
      ("verbose,v", bpo::value<bool>()->default_value(false)->implicit_value(true), "Verbose logging");

    return app.run(argc, argv, [&app]() -> future<int> {
        quic_server server;
        gate sessions;
        std::optional<future<>> accept_task;
        std::exception_ptr error;
        bool verbose = false;

        try {
            auto&& cfg = app.configuration();
            auto address = cfg["address"].as<std::string>();
            auto port = cfg["port"].as<uint16_t>();
            auto crt = cfg["crt"].as<std::string>();
            auto key = cfg["key"].as<std::string>();
            verbose = cfg["verbose"].as<bool>();

            quic_server_config server_cfg;
            server_cfg.listen_address = parse_ipv6_address(address, port);
            server_cfg.crt_file = crt;
            server_cfg.key_file = key;

            co_await server.start(std::move(server_cfg));
            accept_task.emplace(accept_loop(server, sessions, verbose));

            std::cout << "QUIC server listening on [" << address << "]:" << port << "\n";
            std::cout.flush();

            seastar_apps_lib::stop_signal stop_signal;
            co_await stop_signal.wait();
            std::cout << "[server] SIGINT received, disconnecting clients...\n";
            std::cout.flush();
        } catch (...) {
            error = std::current_exception();
        }

        try {
            co_await server.stop();
        } catch (...) {
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
