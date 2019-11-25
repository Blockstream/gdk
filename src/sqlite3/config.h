#ifndef GDKSQLITE_CONFIG_CONFIG_H
#define GDKSQLITE_CONFIG_CONFIG_H

#define SQLITE_ENABLE_DESERIALIZE 1
#define SQLITE_OMIT_DEPRECATED 1
#define SQLITE_DQS 0
#define SQLITE_THREADSAFE 0
#define SQLITE_DEFAULT_MEMSTATUS 0
#define SQLITE_DEFAULT_AUTOVACUUM 0
#define SQLITE_OMIT_AUTOVACUUM 1
#define SQLITE_DEFAULT_SYNCHRONOUS 0
#define SQLITE_DEFAULT_WAL_SYNCHRONOUS 1
#define SQLITE_LIKE_DOESNT_MATCH_BLOBS 1
#define SQLITE_MAX_EXPR_DEPTH 0
#define SQLITE_OMIT_DECLTYPE 1
#define SQLITE_OMIT_PROGRESS_CALLBACK 1
#define SQLITE_OMIT_SHARED_CACHE 1
#ifndef __clang__
#ifndef __FreeBSD__
#define SQLITE_USE_ALLOCA 1
#endif
#endif
#define SQLITE_DEFAULT_AUTOMATIC_INDEX 0
#define SQLITE_OMIT_BLOB_LITERAL 1
#define SQLITE_OMIT_COMPLETE 1
#define SQLITE_OMIT_GET_TABLE 1
#define SQLITE_OMIT_INCRBLOB 1
#define SQLITE_OMIT_LIKE_OPTIMIZATION 1
#define SQLITE_OMIT_LOAD_EXTENSION 1
#define SQLITE_OMIT_OR_OPTIMIZATION 1
#define SQLITE_OMIT_SUBQUERY 1
#define SQLITE_OMIT_TCL_VARIABLE 1
#define SQLITE_OMIT_TEMPDB 1
#define SQLITE_OMIT_TRACE 1
#define SQLITE_OMIT_UTF16 1
#define SQLITE_OMIT_WAL 1
#define SQLITE_TEMP_STORE 3
#define SQLITE_ENABLE_API_ARMOR 1
#define SQLITE_SQLITE_OMIT_ALTERTABLE 1
#define SQLITE_OMIT_AUTHORIZATION 1
#define SQLITE_OMIT_AUTOINCREMENT 1

#if __clang__
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wunknown-warning-option"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wunused-value"
#pragma clang diagnostic ignored "-Wcast-function-type"
#pragma clang diagnostic ignored "-Wunused-but-set-variable"
#pragma clang diagnostic ignored "-Wmaybe-uninitialized"
#pragma clang diagnostic ignored "-Wsometimes-uninitialized"
#pragma clang diagnostic ignored "-Wimplicit-function-declaration"
#pragma clang diagnostic ignored "-Wunused-function"
#else
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-value"
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
#pragma GCC diagnostic ignored "-Wunused-function"
#if __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#endif

#endif /*GDKSQLITE_CONFIG_CONFIG_H*/
