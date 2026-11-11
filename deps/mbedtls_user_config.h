#pragma once

// Sogen sets mbedTLS's time source: the client random of a TLS 1.2 handshake starts with the time, and a reproducible
// run's handshakes must not take it from the host.
#define MBEDTLS_PLATFORM_TIME_ALT
