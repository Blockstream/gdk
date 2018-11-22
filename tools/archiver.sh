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

libraries="$boost_chrono_lib $boost_log_lib $boost_system_lib $boost_thread_lib $openssl_crypto_lib $openssl_ssl_lib $secp256k1_lib $wally_lib"
libtool -static -o ${greenaddress_lib} $libraries $1/src/src@@greenaddress@sha/*.o
