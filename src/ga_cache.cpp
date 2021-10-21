#include <algorithm>
#include <array>
#include <fstream>
#include <vector>

#include "assertion.hpp"
#include "ga_cache.hpp"
#include "inbuilt.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "session.hpp"
#include "sqlite3/sqlite3.h"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {

        constexpr int VERSION = 1;
        constexpr const char* KV_SELECT = "SELECT value FROM KeyValue WHERE key = ?1;";
        constexpr const char* TX_SELECT = "SELECT timestamp, txid, block, spent, spv_status, data FROM Tx "
                                          "WHERE subaccount = ?1 ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3;";
        constexpr const char* TXID_SELECT = "SELECT timestamp, txid, block, spent, spv_status, data FROM Tx "
                                            "WHERE subaccount = ?1 AND txid = ?2;";
        constexpr const char* TX_LATEST = "SELECT MAX(timestamp) FROM Tx WHERE subaccount = ?1;";
        constexpr const char* TX_EARLIEST_MEMPOOL
            = "SELECT MIN(timestamp) FROM Tx WHERE subaccount = ?1 AND block = 0;";
        constexpr const char* TX_EARLIEST_BLOCK
            = "SELECT MIN(timestamp) FROM Tx WHERE subaccount = ?1 AND block >= ?2;";
        constexpr const char* TX_UPSERT = "INSERT INTO Tx(subaccount, timestamp, txid, block, spent, spv_status, data) "
                                          "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) "
                                          "ON CONFLICT(subaccount, timestamp) DO UPDATE SET data = ?4;";
        constexpr const char* TX_SPV_UPDATE = "UPDATE Tx SET spv_status = ?1 WHERE txid = ?2;";
        constexpr const char* TX_DELETE_ALL = "DELETE FROM Tx WHERE subaccount = ?1 AND timestamp >= ?2;";
        constexpr const char* TXDATA_INSERT = "INSERT INTO TxData(txid, rawtx) VALUES (?1, ?2) "
                                              "ON CONFLICT(txid) DO NOTHING;";
        constexpr const char* TXDATA_SELECT = "SELECT rawtx FROM TxData WHERE txid = ?1;";

        static auto get_new_memory_db()
        {
            sqlite3* tmpdb = nullptr;
            const int rc = sqlite3_open(":memory:", &tmpdb);
            GDK_RUNTIME_ASSERT(rc == SQLITE_OK);
            return cache::sqlite3_ptr{ tmpdb, [](sqlite3* p) { sqlite3_close(p); } };
        }

        static auto create_db_schema(cache::sqlite3_ptr db)
        {
            const auto exec_check = [&db](const char* sql) {
                char* err_msg = nullptr;
                const int rc = sqlite3_exec(db.get(), sql, 0, 0, &err_msg);
                if (rc != SQLITE_OK) {
                    GDK_LOG_SEV(log_level::info) << "Bad exec_check RC " << rc << " err_msg: " << err_msg;
                    GDK_RUNTIME_ASSERT(false);
                }
            };
            exec_check("CREATE TABLE IF NOT EXISTS LiquidOutput(txid BLOB NOT NULL, vout INTEGER NOT NULL, assetid "
                       "BLOB NOT NULL, "
                       "satoshi INTEGER NOT NULL, abf BLOB NOT NULL, vbf BLOB NOT NULL, PRIMARY KEY (txid, vout));");

            exec_check(
                "CREATE TABLE IF NOT EXISTS KeyValue(key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY(key));");

            exec_check("CREATE TABLE IF NOT EXISTS LiquidBlindingNonce(pubkey BLOB NOT NULL, script BLOB NOT NULL, "
                       "nonce BLOB NOT "
                       "NULL, PRIMARY KEY(pubkey, script));");

            exec_check(
                "CREATE TABLE IF NOT EXISTS Tx(subaccount INTEGER NOT NULL, timestamp INTEGER NOT NULL, txid BLOB "
                "NOT NULL, block INTEGER NOT NULL, spent INTEGER NOT NULL, spv_status INTEGER NOT NULL, "
                "data BLOB NOT NULL, PRIMARY KEY(subaccount, timestamp));");

            exec_check(
                "CREATE TABLE IF NOT EXISTS TxData(txid BLOB NOT NULL, rawtx BLOB NOT NULL, PRIMARY KEY(txid));");
            return db;
        }

        static auto get_db()
        {
            // Verify thread safety in the event that sqlite has been upgraded
            GDK_RUNTIME_ASSERT(sqlite3_threadsafe());
            return create_db_schema(get_new_memory_db());
        }

        static const char* db_log_error(sqlite3* db) noexcept
        {
            try {
                auto err_msg = sqlite3_errmsg(db);
                GDK_LOG_SEV(log_level::error) << "DB error: " << err_msg;
                return err_msg;
            } catch (const std::exception&) {
            }
            return "Unknown DB error";
        }

        static inline const char* db_log_error(cache::sqlite3_stmt_ptr& stmt) noexcept
        {
            return db_log_error(sqlite3_db_handle(stmt.get()));
        }

        static cache::sqlite3_stmt_ptr get_stmt(bool enable, cache::sqlite3_ptr& db, const char* statement)
        {
            sqlite3_stmt* stmt = nullptr;
            if (enable) {
                if (sqlite3_prepare_v3(db.get(), statement, -1, SQLITE_PREPARE_PERSISTENT, &stmt, NULL) != SQLITE_OK) {
                    GDK_RUNTIME_ASSERT_MSG(false, db_log_error(db.get()));
                }
            }
            return cache::sqlite3_stmt_ptr{ stmt, [](sqlite3_stmt* p) { sqlite3_finalize(p); } };
        }

        static void stmt_check_clean(cache::sqlite3_stmt_ptr& stmt) noexcept
        {
            if (sqlite3_clear_bindings(stmt.get()) != SQLITE_OK) {
                db_log_error(stmt);
            }
            if (sqlite3_reset(stmt.get()) != SQLITE_OK) {
                db_log_error(stmt);
            }
        }

        static auto stmt_clean(cache::sqlite3_stmt_ptr& stmt)
        {
            return gsl::finally([&stmt] { stmt_check_clean(stmt); });
        }

        static void save_db_file(byte_span_t key, byte_span_t data, const std::string& path)
        {
            GDK_RUNTIME_ASSERT(!key.empty() && !data.empty());
            std::ofstream f(path, f.out | f.binary);
            if (f.is_open()) {
                const size_t encrypted_len = aes_gcm_encrypt_get_length(data);
                std::vector<unsigned char> cyphertext(encrypted_len);
                GDK_RUNTIME_ASSERT(aes_gcm_encrypt(key, data, cyphertext) == encrypted_len);

                for (size_t written = 0; written != encrypted_len; written = f.tellp()) {
                    auto p = reinterpret_cast<const char*>(&cyphertext[written]);
                    f.write(p, encrypted_len - written);
                }
            }
        }

        static std::vector<unsigned char> load_db_file(byte_span_t key, const std::string& path)
        {
            GDK_RUNTIME_ASSERT(!key.empty());
            std::ifstream f(path, f.in | f.binary);
            if (!f.is_open()) {
                GDK_LOG_SEV(log_level::info) << "Load db, no file or bad file " << path;
                return std::vector<unsigned char>();
            }

            f.seekg(0, f.end);
            std::vector<unsigned char> cyphertext(f.tellg());
            f.seekg(0, f.beg);

            size_t read = 0;
            while (read != cyphertext.size()) {
                auto p = reinterpret_cast<char*>(&cyphertext[read]);
                f.read(p, cyphertext.size() - read);
                read += f.gcount();
            }

            const size_t decrypted_len = aes_gcm_decrypt_get_length(cyphertext);
            std::vector<unsigned char> plaintext(decrypted_len);
            GDK_RUNTIME_ASSERT(aes_gcm_decrypt(key, cyphertext, plaintext) == decrypted_len);
            return plaintext;
        }

        static std::string get_persistent_storage_file(
            const std::string& data_dir, const std::string& db_name, int version)
        {
            return data_dir + '/' + std::to_string(version) + db_name + ".sqliteaesgcm";
        }

        static void clean_up_old_db(const std::string& data_dir, const std::string& db_name)
        {
            for (int version = 0; version < VERSION; ++version) {
                const auto path = get_persistent_storage_file(data_dir, db_name, version);
                {
                    const std::ifstream f(path, f.in | f.binary);
                    if (!f.is_open()) {
                        continue;
                    }
                }
                GDK_LOG_SEV(log_level::info) << "Deleting old version " << version << " db file " << path;
                unlink(path.c_str());
            }
        }

        static bool load_db_impl(byte_span_t key, const std::string& path, cache::sqlite3_ptr& db)
        {
            std::vector<unsigned char> plaintext;
            try {
                plaintext = load_db_file(key, path);
            } catch (const std::exception& ex) {
                GDK_LOG_SEV(log_level::info) << "Bad decryption for file " << path << " error " << ex.what();
                unlink(path.c_str());
            }

            if (plaintext.empty()) {
                return false;
            }

            const auto tmpdb = get_new_memory_db();
            const int rc = sqlite3_deserialize(
                tmpdb.get(), "main", plaintext.data(), plaintext.size(), plaintext.size(), SQLITE_DESERIALIZE_READONLY);

            if (rc != SQLITE_OK) {
                GDK_LOG_SEV(log_level::info) << "Bad sqlite3_deserialize for file " << path << " RC " << rc;
                unlink(path.c_str());
                return false;
            }

            auto backup = sqlite3_backup_init(db.get(), "main", tmpdb.get(), "main");
            bool ok = backup != nullptr && sqlite3_backup_step(backup, -1) == SQLITE_DONE;
            ok = ok && sqlite3_backup_finish(backup) == SQLITE_OK;
            if (!ok) {
                db_log_error(db.get());
                return false;
            }
            GDK_LOG_SEV(log_level::debug) << path << " updating schema";
            create_db_schema(db);
            GDK_LOG_SEV(log_level::info) << path << " loaded correctly";
            return true;
        }

        static auto step_final(cache::sqlite3_stmt_ptr& stmt)
        {
            GDK_RUNTIME_ASSERT(sqlite3_step(stmt.get()) == SQLITE_DONE);
        }

        static uint32_t get_uint32(cache::sqlite3_stmt_ptr& stmt, int column)
        {
            const auto val = sqlite3_column_int64(stmt.get(), column);
            GDK_RUNTIME_ASSERT(val >= 0 && val < 0xffffffff);
            return static_cast<uint32_t>(val);
        }

        static std::vector<unsigned char> get_blob(cache::sqlite3_stmt_ptr& stmt, int column)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                return std::vector<unsigned char>();
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);

            const auto res = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt.get(), column));
            const auto len = sqlite3_column_bytes(stmt.get(), column);
            std::vector<unsigned char> result(res, res + len);
            step_final(stmt);
            return result;
        }

        static void get_blob(cache::sqlite3_stmt_ptr& stmt, int column, const cache::get_key_value_fn& callback)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                callback(boost::none);
                return;
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);

            const auto res = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt.get(), column));
            const auto len = sqlite3_column_bytes(stmt.get(), column);
            try {
                callback(gsl::make_span(res, len));
            } catch (const std::exception& ex) {
                GDK_LOG_SEV(log_level::error) << "Blob callback exception: " << ex.what();
            }
            step_final(stmt);
        }

        static bool get_tx(cache::sqlite3_stmt_ptr& stmt, const cache::get_transactions_fn& callback)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                return false;
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
            const auto db_timestamp = sqlite3_column_int64(stmt.get(), 0);
            GDK_RUNTIME_ASSERT(db_timestamp > 0);
            const uint64_t timestamp = static_cast<uint64_t>(db_timestamp);

            const auto txid = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt.get(), 1));
            const auto txid_len = sqlite3_column_bytes(stmt.get(), 1);
            GDK_RUNTIME_ASSERT(txid_len == WALLY_TXHASH_LEN);

            const uint32_t block = get_uint32(stmt, 2);
            const uint32_t spent = get_uint32(stmt, 3);
            const uint32_t spv_status = get_uint32(stmt, 4);

            const auto data = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt.get(), 5));
            const auto len = sqlite3_column_bytes(stmt.get(), 5);
            try {
                const auto txhash_hex = b2h_rev(gsl::make_span(txid, txid_len));
                const auto span = gsl::make_span(data, len);
                auto tx_json = nlohmann::json::from_msgpack(span.begin(), span.end());
                callback(timestamp, txhash_hex, block, spent, spv_status, tx_json);
            } catch (const std::exception& ex) {
                GDK_LOG_SEV(log_level::error) << "Tx callback exception: " << ex.what();
                return false; // Stop iterating on any exception
            }
            return true;
        }

        static boost::optional<uint64_t> get_tx_timestamp(cache::sqlite3_stmt_ptr& stmt)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                return boost::optional<uint64_t>(); // No tx found
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
            if (sqlite3_column_type(stmt.get(), 0) == SQLITE_NULL) {
                return boost::optional<uint64_t>(); // No tx found (from e.g. MIN())
            }
            auto db_timestamp = sqlite3_column_int64(stmt.get(), 0);
            GDK_RUNTIME_ASSERT(db_timestamp > 0);
            step_final(stmt);
            return static_cast<uint64_t>(db_timestamp);
        }

        static void bind_blob(cache::sqlite3_stmt_ptr& stmt, int column, byte_span_t blob)
        {
            if (sqlite3_bind_blob(stmt.get(), column, blob.data(), blob.size(), SQLITE_STATIC) != SQLITE_OK) {
                GDK_RUNTIME_ASSERT_MSG(false, db_log_error(stmt));
            }
        }

        static void bind_int(cache::sqlite3_stmt_ptr& stmt, int column, uint64_t value)
        {
            const int64_t bind_value = static_cast<int64_t>(value);
            GDK_RUNTIME_ASSERT(bind_value >= 0);
            if (sqlite3_bind_int64(stmt.get(), column, bind_value) != SQLITE_OK) {
                GDK_RUNTIME_ASSERT_MSG(false, db_log_error(stmt));
            }
        }

        static void bind_liquid_blinding(cache::sqlite3_stmt_ptr& stmt, byte_span_t pubkey, byte_span_t script)
        {
            bind_blob(stmt, 1, pubkey);
            bind_blob(stmt, 2, script);
        }
    } // namespace

    cache::cache(const network_parameters& net_params, const std::string& network_name)
        : m_network_name(network_name)
        , m_net_params(net_params)
        , m_is_liquid(net_params.is_liquid())
        , m_type(0)
        , m_data_dir()
        , m_db_name()
        , m_encryption_key()
        , m_require_write(false)
        , m_db(get_db())
        , m_stmt_liquid_blinding_nonce_search(
              get_stmt(m_is_liquid, m_db, "SELECT nonce FROM LiquidBlindingNonce WHERE pubkey = ?1 AND script = ?2;"))
        , m_stmt_liquid_blinding_nonce_insert(get_stmt(
              m_is_liquid, m_db, "INSERT INTO LiquidBlindingNonce (pubkey, script, nonce) VALUES (?1, ?2, ?3);"))
        , m_stmt_liquid_output_search(get_stmt(
              m_is_liquid, m_db, "SELECT assetid, satoshi, abf, vbf FROM LiquidOutput WHERE txid = ?1 AND vout = ?2;"))
        , m_stmt_liquid_output_insert(get_stmt(m_is_liquid, m_db,
              "INSERT INTO LiquidOutput (txid, vout, assetid, satoshi, abf, vbf) VALUES (?1, ?2, ?3, ?4, ?5, ?6);"))
        , m_stmt_key_value_upsert(get_stmt(
              true, m_db, "INSERT INTO KeyValue(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=?2;"))
        , m_stmt_key_value_search(get_stmt(true, m_db, KV_SELECT))
        , m_stmt_key_value_delete(get_stmt(true, m_db, "DELETE FROM KeyValue WHERE key = ?1;"))
        , m_stmt_tx_search(get_stmt(true, m_db, TX_SELECT))
        , m_stmt_txid_search(get_stmt(true, m_db, TXID_SELECT))
        , m_stmt_tx_latest_search(get_stmt(true, m_db, TX_LATEST))
        , m_stmt_tx_earliest_mempool_search(get_stmt(true, m_db, TX_EARLIEST_MEMPOOL))
        , m_stmt_tx_earliest_block_search(get_stmt(true, m_db, TX_EARLIEST_BLOCK))
        , m_stmt_tx_upsert(get_stmt(true, m_db, TX_UPSERT))
        , m_stmt_tx_spv_update(get_stmt(true, m_db, TX_SPV_UPDATE))
        , m_stmt_tx_delete_all(get_stmt(true, m_db, TX_DELETE_ALL))
        , m_stmt_txdata_insert(get_stmt(true, m_db, TXDATA_INSERT))
        , m_stmt_txdata_search(get_stmt(true, m_db, TXDATA_SELECT))
    {
    }

    cache::~cache() {}

    const std::string& cache::get_network_name() const { return m_network_name; }

    void cache::save_db()
    {
        if (m_db_name.empty() || !m_require_write) {
            return;
        }
        sqlite3_int64 db_size;
        void* db = sqlite3_serialize(m_db.get(), "main", &db_size, 0);
        const auto _stmt_clean = gsl::finally([&db] { sqlite3_free(db); });
        if (db == nullptr || db_size < 1) {
            return;
        }
        const auto data = gsl::make_span(reinterpret_cast<const unsigned char*>(db), db_size);
        const auto path = get_persistent_storage_file(m_data_dir, m_db_name, VERSION);
        save_db_file(m_encryption_key, data, path);
        m_require_write = false;
    }

    void cache::load_db(byte_span_t encryption_key, const uint32_t type)
    {
        GDK_RUNTIME_ASSERT(!encryption_key.empty());

        m_data_dir = gdk_config().value("datadir", std::string{});
        if (m_data_dir.empty()) {
            GDK_LOG_SEV(log_level::info) << "datadir not set - thus no get_persistent_storage_file available";
            return;
        }

        m_type = type;
        const auto intermediate = hmac_sha512(encryption_key, ustring_span(m_network_name));
        // Note: the line below means the file name is endian dependant
        const auto type_span = gsl::make_span(reinterpret_cast<const unsigned char*>(&type), sizeof(m_type));
        m_db_name = b2h(gsl::make_span(hmac_sha512(intermediate, type_span).data(), 16));
        m_encryption_key = sha256(encryption_key);

        const auto path = get_persistent_storage_file(m_data_dir, m_db_name, VERSION);
        if (!load_db_impl(m_encryption_key, path, m_db)) {
            // Failed to load the latest version.
            if (VERSION > 1) {
                // Try to carry forward our client blob from the previous version
                try {
                    const auto prev_path = get_persistent_storage_file(m_data_dir, m_db_name, VERSION - 1);
                    auto db{ get_db() };
                    if (load_db_impl(m_encryption_key, prev_path, db)) {
                        auto stmt{ get_stmt(true, db, KV_SELECT) };
                        const auto _{ stmt_clean(stmt) };
                        const char* blob_key = "client_blob";
                        bind_blob(stmt, 1, ustring_span(blob_key));
                        auto prev_blob = get_blob(stmt, 0);
                        if (!prev_blob.empty()) {
                            upsert_key_value(blob_key, prev_blob);
                        }
                        GDK_LOG_SEV(log_level::info) << "Copied client blob from previous version";
                        m_require_write = true;
                    }
                } catch (const std::exception&) {
                    // Ignore errors; fetch blob from server or recreate instead
                }
            }

            // Clean up old versions only on initial DB creation
            clean_up_old_db(m_data_dir, m_db_name);
        } else {
            // Loaded DB successfully
            if (VERSION == 1) {
                if (m_is_liquid) {
                    // Remove old assets keys if present. Note we don't bother
                    // marking dirty here, since that would force a write on every
                    // DB load. The DB will be saved at some point during normal
                    // wallet operation, after which these two calls are no-ops.
                    clear_key_value("index");
                    clear_key_value("icons");
                    const auto assets_modified = get_inbuilt_data_timestamp(m_net_params, "assets");
                    const auto icons_modified = get_inbuilt_data_timestamp(m_net_params, "icons");
                    bool clean = false;
                    get_key_value("http_assets_modified", { [&clean, &assets_modified](const auto& db_blob) {
                        clean |= !db_blob || !std::equal(db_blob->begin(), db_blob->end(), assets_modified.begin());
                    } });
                    if (!clean) {
                        get_key_value("http_icons_modified", { [&clean, &icons_modified](const auto& db_blob) {
                            clean |= !db_blob || !std::equal(db_blob->begin(), db_blob->end(), icons_modified.begin());
                        } });
                    }
                    if (clean) {
                        // Our compiled-in assets have changed, nuke our diff data.
                        GDK_LOG_SEV(log_level::info) << "Deleting cached http data";
                        clear_key_value("http_assets");
                        upsert_key_value("http_assets_modified", ustring_span(assets_modified));
                        clear_key_value("http_icons");
                        upsert_key_value("http_icons_modified", ustring_span(icons_modified));
                        // Force this change to be written, it will not be
                        // required again until the next gdk upgrade.
                        m_require_write = true;
                    }
                }
            }
        }
    }

    void cache::clear_key_value(const std::string& key)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _{ stmt_clean(m_stmt_key_value_delete) };
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_key_value_delete, 1, key_span);
        step_final(m_stmt_key_value_delete);
        m_require_write = true;
    }

    void cache::get_key_value(const std::string& key, const cache::get_key_value_fn& callback)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _{ stmt_clean(m_stmt_key_value_search) };
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_key_value_search, 1, key_span);
        get_blob(m_stmt_key_value_search, 0, callback);
    }

    void cache::get_transactions(
        uint32_t subaccount, uint64_t start, size_t count, const cache::get_transactions_fn& callback)
    {
        const auto _{ stmt_clean(m_stmt_tx_search) };
        bind_int(m_stmt_tx_search, 1, subaccount);
        bind_int(m_stmt_tx_search, 2, count);
        bind_int(m_stmt_tx_search, 3, start);
        while (get_tx(m_stmt_tx_search, callback)) {
            // No-op
        }
    }

    void cache::get_transaction(
        uint32_t subaccount, const std::string& txhash_hex, const cache::get_transactions_fn& callback)
    {
        const auto txid = h2b_rev(txhash_hex);
        const auto _{ stmt_clean(m_stmt_txid_search) };
        bind_int(m_stmt_txid_search, 1, subaccount);
        bind_blob(m_stmt_txid_search, 2, txid);
        if (get_tx(m_stmt_txid_search, callback)) {
            // At most one txid should be available
            auto&& dummy_cb = [](uint64_t, const std::string&, uint32_t, uint32_t, uint32_t, nlohmann::json&) {};
            GDK_RUNTIME_ASSERT(!get_tx(m_stmt_txid_search, dummy_cb));
        }
    }

    void cache::get_transaction_data(const std::string& txhash_hex, const cache::get_key_value_fn& callback)
    {
        const auto txid = h2b_rev(txhash_hex);
        const auto _{ stmt_clean(m_stmt_txdata_search) };
        bind_blob(m_stmt_txdata_search, 1, txid);
        get_blob(m_stmt_txdata_search, 0, callback);
    }

    void cache::insert_transaction_data(const std::string& txhash_hex, byte_span_t value)
    {
        GDK_RUNTIME_ASSERT(!txhash_hex.empty() && !value.empty());
        const auto txid = h2b_rev(txhash_hex);
        const auto _{ stmt_clean(m_stmt_txdata_insert) };
        bind_blob(m_stmt_txdata_insert, 1, txid);
        bind_blob(m_stmt_txdata_insert, 2, value);
        step_final(m_stmt_txdata_insert);
        m_require_write = true;
    }

    uint64_t cache::get_latest_transaction_timestamp(uint32_t subaccount)
    {
        const auto _{ stmt_clean(m_stmt_tx_latest_search) };
        bind_int(m_stmt_tx_latest_search, 1, subaccount);
        return get_tx_timestamp(m_stmt_tx_latest_search).get_value_or(0);
    }

    void cache::set_latest_block(uint32_t block)
    {
        const auto block_str = std::to_string(block);
        upsert_key_value("last_seen_block", ustring_span(block_str));
    }

    uint32_t cache::get_latest_block()
    {
        uint32_t db_block = 0;
        get_key_value("last_seen_block", { [&db_block](const auto& db_blob) {
            if (db_blob != boost::none) {
                const std::string block_str(db_blob->begin(), db_blob->end());
                db_block = std::strtoul(block_str.c_str(), nullptr, 10);
            }
        } });
        return db_block;
    }

    void cache::insert_transaction(
        uint32_t subaccount, uint64_t timestamp, const std::string& txhash_hex, const nlohmann::json& tx_json)
    {
        const auto txid = h2b_rev(txhash_hex);
        const auto tx_data = nlohmann::json::to_msgpack(tx_json);
        const auto _{ stmt_clean(m_stmt_tx_upsert) };
        bind_int(m_stmt_tx_upsert, 1, subaccount);
        bind_int(m_stmt_tx_upsert, 2, timestamp);
        bind_blob(m_stmt_tx_upsert, 3, txid);
        bind_int(m_stmt_tx_upsert, 4, tx_json.at("block_height"));
        bind_int(m_stmt_tx_upsert, 5, 0); // 0 = Unknown spent status
        bind_int(m_stmt_tx_upsert, 6, 3); // SPV_STATUS_DISABLED
        bind_blob(m_stmt_tx_upsert, 7, tx_data);
        step_final(m_stmt_tx_upsert);
        m_require_write = true;
    }

    void cache::set_transaction_spv_verified(const std::string& txhash_hex)
    {
        const auto txid = h2b_rev(txhash_hex);
        const auto _{ stmt_clean(m_stmt_tx_spv_update) };
        bind_int(m_stmt_tx_spv_update, 1, 1); // SPV_STATUS_VERIFIED
        bind_blob(m_stmt_tx_spv_update, 2, txid);
        step_final(m_stmt_tx_spv_update);
        m_require_write = true;
    }

    void cache::delete_transactions(uint32_t subaccount, uint64_t start_ts)
    {
        const auto _{ stmt_clean(m_stmt_tx_delete_all) };
        bind_int(m_stmt_tx_delete_all, 1, subaccount);
        bind_int(m_stmt_tx_delete_all, 2, start_ts);
        step_final(m_stmt_tx_delete_all);
        m_require_write = true;
    }

    bool cache::delete_mempool_txs(uint32_t subaccount)
    {
        // Delete all transactions from the earliest mempool tx onwards
        boost::optional<uint64_t> db_timestamp;
        {
            const auto _{ stmt_clean(m_stmt_tx_earliest_mempool_search) };
            bind_int(m_stmt_tx_earliest_mempool_search, 1, subaccount);
            db_timestamp = get_tx_timestamp(m_stmt_tx_earliest_mempool_search);
        }
        if (db_timestamp == boost::none) {
            return false; // Cache not updated
        }
        delete_transactions(subaccount, db_timestamp.get());
        return true; // Cache updated
    }

    bool cache::delete_block_txs(uint32_t subaccount, uint32_t start_block)
    {
        // Delete all transactions in the start block or later
        boost::optional<uint64_t> db_timestamp;
        {
            const auto _{ stmt_clean(m_stmt_tx_earliest_block_search) };
            bind_int(m_stmt_tx_earliest_block_search, 1, subaccount);
            bind_int(m_stmt_tx_earliest_block_search, 2, start_block);
            db_timestamp = get_tx_timestamp(m_stmt_tx_earliest_block_search);
        }
        if (db_timestamp == boost::none) {
            return false; // Cache not updated
        }
        delete_transactions(subaccount, db_timestamp.get());
        return true; // Cache updated
    }

    void cache::on_new_transaction(uint32_t subaccount, const std::string& txhash_hex)
    {
        nlohmann::json existing_tx;
        uint32_t existing_tx_block = 0;

        get_transaction(subaccount, txhash_hex,
            { [&existing_tx, &existing_tx_block](uint64_t /*ts*/, const std::string& /*txhash*/, uint32_t block,
                  uint32_t /*spent*/, uint32_t /*spv_status*/, nlohmann::json& tx_json) {
                existing_tx = std::move(tx_json);
                existing_tx_block = block;
            } });

        if (!existing_tx.empty() && existing_tx_block != 0) {
            // We have been notified of a confirmed tx we already had cached as confirmed.
            // Either the tx was reorged or the server is re-processing txs; either way
            // remove all cached txs from the block the tx was originally in onwards, along
            // with any mempool txs.
            delete_block_txs(subaccount, existing_tx_block);
            // Fall through to delete mempool txs
        }
        // Otherwise, we havent seen this tx yet, or we've been re-notified of a mempool tx.
        // Remove any mempool txs this tx could be double spending/replacing
        delete_mempool_txs(subaccount);
    }

    std::vector<unsigned char> cache::get_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_blinding_nonce_search.get());
        const auto _{ stmt_clean(m_stmt_liquid_blinding_nonce_search) };
        bind_liquid_blinding(m_stmt_liquid_blinding_nonce_search, pubkey, script);
        return get_blob(m_stmt_liquid_blinding_nonce_search, 0);
    }

    nlohmann::json cache::get_liquid_output(byte_span_t txhash, const uint32_t vout)
    {
        nlohmann::json utxo;

        GDK_RUNTIME_ASSERT(!txhash.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_output_search.get());
        const auto _{ stmt_clean(m_stmt_liquid_output_search) };
        bind_blob(m_stmt_liquid_output_search, 1, txhash);
        bind_int(m_stmt_liquid_output_search, 2, vout);
        const int rc = sqlite3_step(m_stmt_liquid_output_search.get());
        if (rc == SQLITE_DONE) {
            return utxo;
        }
        GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
        const auto _get_reversed_result = [this](const int column, const int size) {
            GDK_RUNTIME_ASSERT(sqlite3_column_bytes(m_stmt_liquid_output_search.get(), column) == size);
            const auto res = reinterpret_cast<const unsigned char*>(
                sqlite3_column_blob(m_stmt_liquid_output_search.get(), column));
            GDK_RUNTIME_ASSERT(res);
            // cache values are stored in byte order not display order (reversed)
            return b2h_rev(gsl::make_span(res, size));
        };

        utxo["asset_id"] = _get_reversed_result(0, ASSET_TAG_LEN);
        utxo["satoshi"] = sqlite3_column_int64(m_stmt_liquid_output_search.get(), 1);
        utxo["assetblinder"] = _get_reversed_result(2, 32);
        utxo["amountblinder"] = _get_reversed_result(3, 32);

        step_final(m_stmt_liquid_output_search);
        return utxo;
    }

    void cache::upsert_key_value(const std::string& key, byte_span_t value)
    {
        GDK_RUNTIME_ASSERT(!key.empty() && !value.empty());
        const auto _{ stmt_clean(m_stmt_key_value_upsert) };
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_key_value_upsert, 1, key_span);
        bind_blob(m_stmt_key_value_upsert, 2, value);
        step_final(m_stmt_key_value_upsert);
        m_require_write = true;
    }

    void cache::insert_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script, byte_span_t nonce)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty() && !nonce.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_blinding_nonce_insert.get());
        const auto _{ stmt_clean(m_stmt_liquid_blinding_nonce_insert) };
        bind_liquid_blinding(m_stmt_liquid_blinding_nonce_insert, pubkey, script);
        bind_blob(m_stmt_liquid_blinding_nonce_insert, 3, nonce);
        step_final(m_stmt_liquid_blinding_nonce_insert);
        m_require_write = true;
    }

    void cache::insert_liquid_output(byte_span_t txhash, uint32_t vout, nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty() && !utxo.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_output_insert.get());
        const auto _{ stmt_clean(m_stmt_liquid_output_insert) };

        // cache values are stored in byte order not display order (reversed)
        bind_blob(m_stmt_liquid_output_insert, 1, txhash);

        bind_int(m_stmt_liquid_output_insert, 2, vout);
        const auto assetid = h2b_rev(utxo["asset_id"]);
        bind_blob(m_stmt_liquid_output_insert, 3, assetid);

        bind_int(m_stmt_liquid_output_insert, 4, utxo.at("satoshi"));

        const auto abf = h2b_rev(utxo["assetblinder"]);
        bind_blob(m_stmt_liquid_output_insert, 5, abf);
        const auto vbf = h2b_rev(utxo["amountblinder"]);
        bind_blob(m_stmt_liquid_output_insert, 6, vbf);

        step_final(m_stmt_liquid_output_insert);
        m_require_write = true;
    }
} // namespace sdk
} // namespace ga
