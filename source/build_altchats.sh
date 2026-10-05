#!/bin/sh
set -eu
cd "$(dirname "$0")"
compiler=${CC:-cc}
flags=${CFLAGS:--Os -s -Wall -Wextra -Wpedantic}
crypto="crypto/noise.c crypto/sha256.c crypto/chacha20_poly1305.c"
"$compiler" -std=c99 $flags altchats_relay.c $crypto -o altchats_relay -lrt
"$compiler" -std=c99 $flags altchats_client.c altchats_session.c $crypto -o altchats_client -pthread -lrt
"$compiler" -std=c99 $flags altchats_web.c altchats_session.c $crypto -o altchats_web -lrt
printf '%s\n' 'Built altchats_relay, altchats_client and altchats_web.'
