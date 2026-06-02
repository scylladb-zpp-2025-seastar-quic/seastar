/*
 * Unit tests for RPC over QUIC.
 *
 * Every test drives a real QUIC transport (TLS handshake + ngtcp2),
 * using the build-time `testcrt` certificate placed next to the test
 * executable.
 */

#include <seastar/rpc/rpc.hh>
#include <seastar/rpc/rpc_quic_transport.hh>
#include "rpc_test_body.inc.hh"
