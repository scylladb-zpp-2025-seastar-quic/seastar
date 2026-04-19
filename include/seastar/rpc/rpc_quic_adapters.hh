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

#pragma once

#include <seastar/net/api.hh>
#include <seastar/quic/quic_client.hh>
#include <seastar/quic/quic_server.hh>

namespace seastar::rpc::experimental {

/// Creates a server_socket backed by QUIC transport.
///
/// The returned server_socket can be passed directly to rpc::server
/// in place of a TCP server_socket. Each accepted connection creates
/// a QUIC connection with a single bidirectional stream that carries
/// the RPC protocol.
server_socket make_quic_server_socket(quic::experimental::quic_server_config config);

/// Creates a socket backed by QUIC transport.
///
/// The returned socket can be passed directly to rpc::client in place
/// of a TCP socket. On connect(), it establishes a QUIC connection
/// and opens a single bidirectional stream for the RPC protocol.
seastar::socket make_quic_client_socket(quic::experimental::quic_client_config config);

} // namespace seastar::rpc::experimental
