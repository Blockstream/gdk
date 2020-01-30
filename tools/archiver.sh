#! /usr/bin/env bash
set -e

boost_chrono_lib=$1/boost/build/lib/libboost_chrono.a
boost_log_lib=$1/boost/build/lib/libboost_log.a
boost_system_lib=$1/boost/build/lib/libboost_system.a
boost_thread_lib=$1/boost/build/lib/libboost_thread.a
greenaddress_lib=$1/src/libgreenaddress.a
openssl_crypto_lib=$1/openssl/build/lib/libcrypto.a
openssl_ssl_lib=$1/openssl/build/lib/libssl.a
secp256k1_lib=$1/libwally-core/build/lib/libsecp256k1.a
wally_lib=$1/libwally-core/build/lib/libwallycore.a
libevent=$1/libevent/build/lib/libevent.a
libevent_pthread=$1/libevent/build/lib/libevent_pthreads.a
libz=$1/zlib/build/lib/libz.a

libcurve25519_donna=$1/tor/src/lib/libcurve25519_donna.a
tor_ed25519_donna=$1/tor/src/ext/ed25519/donna/libed25519_donna.a
tor_ed25519_ref10=$1/tor/src/ext/ed25519/ref10/libed25519_ref10.a
tor_core=$1/tor/src/core/libtor-app.a
tor_keccak=$1/tor/src/ext/keccak-tiny/libkeccak-tiny.a
tor_trunnel=$1/tor/src/trunnel/libor-trunnel.a
tor_intmath=$1/tor/src/lib/libtor-intmath.a
tor_lock=$1/tor/src/lib/libtor-lock.a
tor_malloc=$1/tor/src/lib/libtor-malloc.a
tor_math=$1/tor/src/lib/libtor-math.a
tor_memarea=$1/tor/src/lib/libtor-memarea.a
tor_meminfo=$1/tor/src/lib/libtor-meminfo.a
tor_osinfo=$1/tor/src/lib/libtor-osinfo.a
tor_process=$1/tor/src/lib/libtor-process.a
tor_sandbox=$1/tor/src/lib/libtor-sandbox.a
tor_smartlist_core=$1/tor/src/lib/libtor-smartlist-core.a
tor_string=$1/tor/src/lib/libtor-string.a
tor_term=$1/tor/src/lib/libtor-term.a
tor_time=$1/tor/src/lib/libtor-time.a
tor_thread=$1/tor/src/lib/libtor-thread.a
tor_wallclock=$1/tor/src/lib/libtor-wallclock.a
tor_log=$1/tor/src/lib/libtor-log.a
tor_tls=$1/tor/src/lib/libtor-tls.a
tor_compress=$1/tor/src/lib/libtor-compress.a
tor_container=$1/tor/src/lib/libtor-container.a
tor_crypt_ops=$1/tor/src/lib/libtor-crypt-ops.a
tor_ctime=$1/tor/src/lib/libtor-ctime.a
tor_encoding=$1/tor/src/lib/libtor-encoding.a
tor_net=$1/tor/src/lib/libtor-net.a
tor_err=$1/tor/src/lib/libtor-err.a
tor_evloop=$1/tor/src/lib/libtor-evloop.a
tor_fdio=$1/tor/src/lib/libtor-fdio.a
tor_fs=$1/tor/src/lib/libtor-fs.a
tor_geoip=$1/tor/src/lib/libtor-geoip.a
tor_version=$1/tor/src/lib/libtor-version.a
tor_buf=$1/tor/src/lib/libtor-buf.a
tor_pubsub=$1/tor/src/lib/libtor-pubsub.a
tor_dispatch=$1/tor/src/lib/libtor-dispatch.a
tor_trace=$1/tor/src/lib/libtor-trace.a
tor_confmgt=$1/tor/src/lib/libtor-confmgt.a
gdk_rust=$1/subprojects/gdk_rust/libgdk_rust.a

libraries="$boost_chrono_lib $boost_log_lib $boost_system_lib $boost_thread_lib $openssl_crypto_lib $openssl_ssl_lib $secp256k1_lib $wally_lib $libevent $libevent_pthread $libcurve25519_donna $libz $tor_ed25519_donna $tor_ed25519_ref10 $tor_core $tor_keccak $tor_trunnel $tor_intmath $tor_lock $tor_malloc $tor_math $tor_memarea $tor_meminfo $tor_osinfo $tor_process $tor_sandbox $tor_smartlist_core $tor_string $tor_term $tor_time $tor_thread $tor_wallclock $tor_log $tor_tls $tor_compress $tor_container $tor_crypt_ops $tor_ctime $tor_encoding $tor_net $tor_err $tor_evloop $tor_fdio $tor_fs $tor_geoip $tor_version $tor_buf $tor_pubsub $tor_dispatch $tor_trace $tor_confmgt $gdk_rust"
if [ "$(uname)" = "Darwin" ]; then
  libtool -static -o $1/src/libgreenaddress_full.a $libraries $1/src/*@@greenaddress@sha/*.o
else
  echo "create $1/src/libgreenaddress_full.a" > $1/src/libgreenaddress.mri
  for lib in $libraries; do
    if [ -f $lib ]; then
        echo "addlib $lib" >> $1/src/libgreenaddress.mri
    fi
  done
  echo "addlib ${greenaddress_lib}" >> $1/src/libgreenaddress.mri
  echo "save" >> $1/src/libgreenaddress.mri
  echo "end" >> $1/src/libgreenaddress.mri
  $2 -M < $1/src/libgreenaddress.mri
fi
