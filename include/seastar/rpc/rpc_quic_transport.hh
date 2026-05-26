/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may obtain a copy of the License at
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

#pragma once

#include <seastar/core/coroutine.hh>
#include <seastar/quic/quic_client.hh>
#include <seastar/quic/quic_server.hh>
#include <seastar/quic/quic.hh>
#include <seastar/rpc/rpc.hh>

namespace seastar::rpc {

class connected_socket_transport final : public connection::transport {
    connected_socket _fd;
    input_stream<char> _input;
    output_stream<char> _output;

public:
    explicit connected_socket_transport(connected_socket fd) noexcept;

    input_stream<char>& input() override;
    output_stream<char>& output() override;
    void shutdown_input() override;
    void shutdown_output() override;
};

} // namespace seastar::rpc

namespace seastar::rpc::experimental {

std::unique_ptr<server::acceptor> make_quic_server_acceptor(seastar::quic::experimental::quic_server_config config);

class quic_client_transport final : public connection::transport {
public:
    quic_client_transport(
            seastar::quic::experimental::quic_client client,
            seastar::quic::experimental::connection conn,
            seastar::quic::experimental::stream control_stream);
    quic_client_transport(
            seastar::quic::experimental::connection conn,
            seastar::quic::experimental::stream control_stream);

    input_stream<char>& input() override;
    output_stream<char>& output() override;
    void shutdown_input() override;
    void shutdown_output() override;
    future<> stop() override;
    bool supports_multiplexed_requests() const override;
    future<std::unique_ptr<connection::transport::stream>> open_request_stream() override;

private:
    std::optional<seastar::quic::experimental::quic_client> _client;
    seastar::quic::experimental::connection _conn;
    seastar::quic::experimental::stream _control_stream;
    input_stream<char> _control_input;
    output_stream<char> _control_output;
};

class quic_server_transport final : public connection::transport {
public:
    quic_server_transport(
            seastar::quic::experimental::connection conn,
            seastar::quic::experimental::stream control_stream);

    input_stream<char>& input() override;
    output_stream<char>& output() override;
    void shutdown_input() override;
    void shutdown_output() override;
    future<> stop() override;
    bool supports_multiplexed_requests() const override;
    future<std::unique_ptr<connection::transport::stream>> accept_request_stream() override;

private:
    seastar::quic::experimental::connection _conn;
    seastar::quic::experimental::stream _control_stream;
    input_stream<char> _control_input;
    output_stream<char> _control_output;
};

} // namespace seastar::rpc::experimental

namespace seastar::rpc {

template <typename Serializer, typename MsgType>
future<std::unique_ptr<typename protocol<Serializer, MsgType>::client>>
protocol<Serializer, MsgType>::make_quic_client(quic::experimental::quic_client_config config) {
    return make_quic_client(client_options{}, std::move(config));
}

template <typename Serializer, typename MsgType>
future<std::unique_ptr<typename protocol<Serializer, MsgType>::client>>
protocol<Serializer, MsgType>::make_quic_client(client_options options, quic::experimental::quic_client_config config) {
    quic::experimental::quic_client quic_client;
    auto session = co_await quic_client.connect(std::move(config));
    auto peer_addr = session.peer_address();
    auto local_addr = session.local_address();
    auto control_stream = co_await session.open_stream();
    auto transport = std::make_unique<experimental::quic_client_transport>(
            std::move(quic_client),
            std::move(session),
            std::move(control_stream));

    co_return std::make_unique<typename protocol<Serializer, MsgType>::client>(
            *this,
            std::move(options),
            std::move(transport),
            peer_addr,
            local_addr);
}

template <typename Serializer, typename MsgType>
protocol<Serializer, MsgType>::server::server(protocol& proto, quic::experimental::quic_server_config config, resource_limits memory_limit)
        : rpc::server(&proto, experimental::make_quic_server_acceptor(std::move(config)), memory_limit) {
}

template <typename Serializer, typename MsgType>
protocol<Serializer, MsgType>::server::server(protocol& proto, server_options opts, quic::experimental::quic_server_config config, resource_limits memory_limit)
        : rpc::server(&proto, std::move(opts), experimental::make_quic_server_acceptor(std::move(config)), memory_limit) {
}

} // namespace seastar::rpc
