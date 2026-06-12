/*
 * Unit tests for the RPC implementation driving the TCP loopback path, so the
 * protocol/state-machine logic is exercised independently of any QUIC
 * transport. This is the baseline that predates the QUIC-transport variant
 * (see rpc_quic_test.cc).
 */

#include <seastar/rpc/rpc.hh>
#include "rpc_test_body_tcp.inc.hh"
