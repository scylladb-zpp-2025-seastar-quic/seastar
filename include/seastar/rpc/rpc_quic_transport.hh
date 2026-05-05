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
#include <seastar/quic/quic.hh>
#include <seastar/rpc/rpc.hh>

namespace seastar::rpc::experimental {

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
    future<internal::incoming_request> receive_request(connection& owner) override;
    future<> send_request(connection& owner, int64_t msg_id, snd_buf data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel, bool expect_response) override;

private:
    std::optional<seastar::quic::experimental::quic_client> _client;
    seastar::quic::experimental::connection _conn;
    seastar::quic::experimental::stream _control_stream;
    input_stream<char> _control_input;
    output_stream<char> _control_output;
    semaphore _send_sem = semaphore(1);
    gate _response_gate;
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
    future<internal::incoming_request> receive_request(connection& owner) override;
    future<> send_request(connection& owner, int64_t msg_id, snd_buf data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel, bool expect_response) override;

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
            local_addr,
            false);
}

} // namespace seastar::rpc
