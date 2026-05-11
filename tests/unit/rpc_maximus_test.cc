/*
 * Unit tests for the RPC implementation on branch maximus-working
 * (include/seastar/rpc/rpc.hh + src/rpc/rpc.cc — the version that
 *  introduces the connection::transport abstraction and make_quic_client).
 *
 * These tests drive the TCP loopback path so the protocol/state-machine
 * logic is exercised independently of any QUIC transport.
 */

#include <seastar/rpc/rpc.hh>
#include "rpc_test_body.inc.hh"
