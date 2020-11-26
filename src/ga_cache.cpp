#include <algorithm>
#include <array>
#include <fstream>
#include <openssl/evp.h>
#include <vector>

#include "assertion.hpp"
#include "ga_cache.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "session.hpp"
#include "utils.hpp"

namespace std {
template <> struct default_delete<EVP_CIPHER_CTX> {
    void operator()(EVP_CIPHER_CTX* ptr) const { ::EVP_CIPHER_CTX_free(ptr); }
};
} // namespace std

namespace ga {
namespace sdk {

    namespace {

        constexpr int AES_GCM_TAG_SIZE = 16;
        constexpr int AES_GCM_IV_SIZE = 12;
        constexpr int AES_BUFFER = 4096;
        constexpr int OPENSSL_SUCCESS = 1;
        constexpr int VERSION = 1;

        static std::unique_ptr<sqlite3> get_new_memory_db()
        {
            sqlite3* tmpdb = nullptr;
            const int rc = sqlite3_open(":memory:", &tmpdb);
            GDK_RUNTIME_ASSERT(rc == SQLITE_OK);
            return std::unique_ptr<sqlite3>(tmpdb);
        }

        static auto get_db()
        {
            auto db = get_new_memory_db();
            const auto exec_check = [&db](const char* sql) {
                char* err_msg = nullptr;
                const int rc = sqlite3_exec(db.get(), sql, 0, 0, &err_msg);
                if (rc != SQLITE_OK) {
                    GDK_LOG_SEV(log_level::info) << "Bad exec_check RC " << rc << " err_msg: " << err_msg;
                    GDK_RUNTIME_ASSERT(false);
                }
            };
            exec_check("CREATE TABLE LiquidOutput(txid BLOB NOT NULL, vout INTEGER NOT NULL, assetid BLOB NOT NULL, "
                       "satoshi INTEGER NOT NULL, abf BLOB NOT NULL, vbf BLOB NOT NULL, PRIMARY KEY (txid, vout));");

            exec_check("CREATE TABLE KeyValue(key BLOB NOT NULL, value BLOB NOT NULL, PRIMARY KEY(key));");

            exec_check("CREATE TABLE LiquidBlindingNonce(pubkey BLOB NOT NULL, script BLOB NOT NULL, nonce BLOB NOT "
                       "NULL, PRIMARY KEY(pubkey, script));");

            return db;
        }

        static auto get_stmt(bool enable, std::unique_ptr<sqlite3>& db, const char* statement)
        {
            sqlite3_stmt* tmpstmt = nullptr;
            if (enable) {
                int rc = sqlite3_prepare_v3(db.get(), statement, -1, SQLITE_PREPARE_PERSISTENT, &tmpstmt, NULL);
                GDK_RUNTIME_ASSERT_MSG(rc == SQLITE_OK, sqlite3_errmsg(db.get()));
            }
            return tmpstmt;
        }

        static void stmt_check_clean(std::unique_ptr<sqlite3_stmt>& stmt)
        {
            const int rc = sqlite3_clear_bindings(stmt.get());
            GDK_RUNTIME_ASSERT_MSG(rc == SQLITE_OK, sqlite3_errmsg(sqlite3_db_handle(stmt.get())));
            const int rc2 = sqlite3_reset(stmt.get());
            GDK_RUNTIME_ASSERT_MSG(rc2 == SQLITE_OK, sqlite3_errmsg(sqlite3_db_handle(stmt.get())));
        }

        static void openssl_encrypt(byte_span_t key, byte_span_t data, const std::string& path)
        {
            GDK_RUNTIME_ASSERT(!key.empty() && !data.empty());
            std::ofstream f(path, f.out | f.binary);
            if (!f.is_open()) {
                return;
            }
            std::array<unsigned char, AES_BUFFER> buff;
            get_random_bytes(AES_GCM_IV_SIZE, buff.data(), AES_GCM_IV_SIZE);
            const auto ctx = std::unique_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());
            int rc = EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), buff.data());
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
            const auto write_all = [&f, &buff](const size_t total) {
                const size_t initial = f.tellp();
                size_t written = 0;
                while (written != total) {
                    f.write(reinterpret_cast<const char*>(&buff[written]), total - written);
                    const size_t current = f.tellp();
                    written = current - initial;
                }
            };
            write_all(AES_GCM_IV_SIZE);
            int out_len1 = 0;
            int written = 0;

            const int total = data.size();

            while (written != total) {
                const int towrite = total - written > AES_BUFFER ? AES_BUFFER : total - written;
                rc = EVP_EncryptUpdate(ctx.get(), buff.data(), &out_len1, data.data() + written, towrite);
                GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
                write_all(out_len1);
                written += out_len1;
            }

            int out_len2 = 0;
            rc = EVP_EncryptFinal_ex(ctx.get(), buff.data(), &out_len2);
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
            write_all(out_len2);
            rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, buff.data());
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
            write_all(AES_GCM_TAG_SIZE);
        }

        static boost::optional<std::vector<unsigned char>> openssl_decrypt(byte_span_t key, const std::string& path)
        {
            GDK_RUNTIME_ASSERT(!key.empty());
            std::ifstream f(path, f.in | f.binary);
            if (!f.is_open()) {
                GDK_LOG_SEV(log_level::info) << "Load db, no file or bad file " << path;
                return boost::none;
            }

            f.seekg(0, f.end);
            std::vector<unsigned char> out(f.tellg());
            f.seekg(0, f.beg);

            std::array<unsigned char, AES_BUFFER> buff;
            const auto read_all = [&f, &buff](const size_t total) {
                size_t read = 0;
                while (read != total) {
                    f.read(reinterpret_cast<char*>(&buff[read]), total - read);
                    read += f.gcount();
                }
            };
            read_all(AES_GCM_IV_SIZE);
            const auto ctx = std::unique_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new());
            int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), buff.data());
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
            int out_len1 = out.size();
            const int total = out.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
            int read = 0;
            int written = 0;
            while (read != total) {
                const int toread = total - read > AES_BUFFER ? AES_BUFFER : total - read;
                read_all(toread);
                rc = EVP_DecryptUpdate(ctx.get(), out.data() + written, &out_len1, buff.data(), toread);
                GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
                read += toread;
                written += out_len1;
            }

            read_all(AES_GCM_TAG_SIZE);

            rc = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, buff.data());
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);

            int out_len2 = out.size() - out_len1;
            rc = EVP_DecryptFinal_ex(ctx.get(), out.data() + out_len1, &out_len2);
            GDK_RUNTIME_ASSERT(rc == OPENSSL_SUCCESS);
            return out;
        }

        static boost::optional<std::string> get_persistent_storage_file(
            byte_span_t encryption_key, const std::string& network, const uint32_t type, const int version = VERSION)
        {
            const auto datadir = gdk_config().value("datadir", std::string{});
            if (datadir.empty()) {
                GDK_LOG_SEV(log_level::info) << "datadir not set - thus no get_persistent_storage_file available";
                return boost::none;
            }
            const auto network_span = ustring_span(network);
            const auto intermediate = hmac_sha512(encryption_key, network_span);
            const auto type_span = gsl::make_span(reinterpret_cast<const unsigned char*>(&type), 4);
            const auto unique_db = b2h(gsl::make_span(hmac_sha512(intermediate, type_span).data(), 16));
            return datadir + "/" + std::to_string(version) + unique_db + ".sqliteaesgcm";
        }

        static void clean_up_old_db(byte_span_t encryption_key, const uint32_t type, const std::string& network)
        {
            const auto exist = [](const auto& path) {
                const std::ifstream f(path.get(), f.in | f.binary);
                return f.is_open();
            };
            for (int version = 0; version < VERSION; ++version) {
                const auto path = get_persistent_storage_file(encryption_key, network, type, version);
                if (path && exist(path)) {
                    GDK_LOG_SEV(log_level::info) << "Deleting old version " << version << " db file " << path.get();
                    unlink(path->c_str());
                }
            }
        }

        static auto step_final(std::unique_ptr<sqlite3_stmt>& stmt)
        {
            GDK_RUNTIME_ASSERT(sqlite3_step(stmt.get()) == SQLITE_DONE);
        }

        static boost::optional<std::vector<unsigned char>> get_blob(std::unique_ptr<sqlite3_stmt>& stmt, int column)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                return boost::none;
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);

            const auto res = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt.get(), column));
            const auto len = sqlite3_column_bytes(stmt.get(), column);
            std::vector<unsigned char> result(res, res + len);
            step_final(stmt);
            return result;
        }

        static void bind_blob(std::unique_ptr<sqlite3_stmt>& stmt, int column, byte_span_t blob)
        {
            GDK_RUNTIME_ASSERT(
                sqlite3_bind_blob(stmt.get(), column, blob.data(), blob.size(), SQLITE_STATIC) == SQLITE_OK);
        }

        static void bind_liquid_blinding(std::unique_ptr<sqlite3_stmt>& stmt, byte_span_t pubkey, byte_span_t script)
        {
            bind_blob(stmt, 1, pubkey);
            bind_blob(stmt, 2, script);
        }

        static bool has_result(std::unique_ptr<sqlite3_stmt>& stmt)
        {
            const int rc = sqlite3_step(stmt.get());
            if (rc == SQLITE_DONE) {
                return false;
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
            step_final(stmt);
            return true;
        }
    } // namespace

    cache::cache(const network_parameters& net_params, const std::string& network_name)
        : m_network_name(network_name)
        , m_is_liquid(net_params.liquid())
        , m_db(get_db())
        , m_stmt_liquid_blinding_nonce_has(get_stmt(
              m_is_liquid, m_db, "SELECT 1 FROM LiquidBlindingNonce WHERE pubkey = ?1 AND script = ?2 LIMIT 1;"))
        , m_stmt_liquid_blinding_nonce_search(
              get_stmt(m_is_liquid, m_db, "SELECT nonce FROM LiquidBlindingNonce WHERE pubkey = ?1 AND script = ?2;"))
        , m_stmt_liquid_blinding_nonce_insert(get_stmt(
              m_is_liquid, m_db, "INSERT INTO LiquidBlindingNonce (pubkey, script, nonce) VALUES (?1, ?2, ?3);"))
        , m_stmt_liquid_output_has(
              get_stmt(m_is_liquid, m_db, "SELECT 1 FROM LiquidOutput WHERE txid = ?1 AND vout = ?2 LIMIT 1;"))
        , m_stmt_liquid_output_search(get_stmt(
              m_is_liquid, m_db, "SELECT assetid, satoshi, abf, vbf FROM LiquidOutput WHERE txid = ?1 AND vout = ?2;"))
        , m_stmt_liquid_output_insert(get_stmt(m_is_liquid, m_db,
              "INSERT INTO LiquidOutput (txid, vout, assetid, satoshi, abf, vbf) VALUES (?1, ?2, ?3, ?4, ?5, ?6);"))
        , m_stmt_key_value_upsert(get_stmt(
              true, m_db, "INSERT INTO KeyValue(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=?2;"))
        , m_stmt_key_value_search(get_stmt(true, m_db, "SELECT value FROM KeyValue WHERE key = ?1;"))
        , m_stmt_key_value_delete(get_stmt(true, m_db, "DELETE FROM KeyValue WHERE key = ?1;"))
    {
    }

    void cache::save_db(byte_span_t encryption_key)
    {
        GDK_RUNTIME_ASSERT(!encryption_key.empty());
        if (!m_require_write) {
            return;
        }
        const auto path = get_persistent_storage_file(encryption_key, m_network_name, m_type);
        if (!path) {
            GDK_LOG_SEV(log_level::info) << "datadir not set, db won't be saved to file";
            return;
        }
        sqlite3_int64 db_size;
        void* db = sqlite3_serialize(m_db.get(), "main", &db_size, 0);
        const auto _stmt_clean = gsl::finally([&db] { sqlite3_free(db); });
        if (db == nullptr || db_size < 1) {
            return;
        }
        const auto key = sha256(encryption_key);
        const auto data = gsl::make_span(reinterpret_cast<const unsigned char*>(db), db_size);
        openssl_encrypt(key, data, path.get());
        m_require_write = false;
    }

    void cache::load_db(byte_span_t encryption_key, const uint32_t type)
    {
        GDK_RUNTIME_ASSERT(!encryption_key.empty());
        clean_up_old_db(encryption_key, type, m_network_name);
        const auto path = get_persistent_storage_file(encryption_key, m_network_name, type);
        if (!path) {
            GDK_LOG_SEV(log_level::info) << "datadir not set, db won't be restored from file";
            return;
        }
        m_type = type;
        auto plaintext = [&encryption_key, &path]() -> boost::optional<std::vector<unsigned char>> {
            try {
                return openssl_decrypt(sha256(encryption_key), path.get());
            } catch (const std::exception& ex) {
                GDK_LOG_SEV(log_level::info) << "Bad decryption for file " << path.get() << " error " << ex.what();
                unlink(path->c_str());
                return boost::none;
            }
        }();

        if (!plaintext) {
            return;
        }

        const auto tmpdb = get_new_memory_db();
        const int rc = sqlite3_deserialize(
            tmpdb.get(), "main", plaintext->data(), plaintext->size(), plaintext->size(), SQLITE_DESERIALIZE_READONLY);

        if (rc != SQLITE_OK) {
            GDK_LOG_SEV(log_level::info) << "Bad sqlite3_deserialize for file " << path.get() << " RC " << rc;
            unlink(path->c_str());
            return;
        }

        auto backup = sqlite3_backup_init(m_db.get(), "main", tmpdb.get(), "main");
        GDK_RUNTIME_ASSERT(backup);
        const auto _backup_finish
            = gsl::finally([backup] { GDK_RUNTIME_ASSERT(sqlite3_backup_finish(backup) == SQLITE_OK); });
        GDK_RUNTIME_ASSERT(sqlite3_backup_step(backup, -1) == SQLITE_DONE);
        GDK_LOG_SEV(log_level::info) << "sqlite loaded correctly " << path.get();
    }

    void cache::clear_key_value(const std::string& key)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_key_value_delete); });
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_key_value_delete, 1, key_span);
        step_final(m_stmt_key_value_delete);
    }

    boost::optional<std::vector<unsigned char>> cache::get_key_value(const std::string& key)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_key_value_search); });
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_key_value_search, 1, key_span);
        return get_blob(m_stmt_key_value_search, 0);
    }

    bool cache::has_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        if (!m_stmt_liquid_blinding_nonce_has) {
            return false;
        }
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_blinding_nonce_has); });
        bind_liquid_blinding(m_stmt_liquid_blinding_nonce_has, pubkey, script);
        return has_result(m_stmt_liquid_blinding_nonce_has);
    }

    boost::optional<std::vector<unsigned char>> cache::get_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_blinding_nonce_search.get());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_blinding_nonce_search); });
        bind_liquid_blinding(m_stmt_liquid_blinding_nonce_search, pubkey, script);
        return get_blob(m_stmt_liquid_blinding_nonce_search, 0);
    }

    bool cache::has_liquid_output(byte_span_t txhash, const uint32_t vout)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty());
        if (!m_stmt_liquid_blinding_nonce_has) {
            return false;
        }
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_output_has); });
        bind_blob(m_stmt_liquid_output_has, 1, txhash);
        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquid_output_has.get(), 2, vout) == SQLITE_OK);
        return has_result(m_stmt_liquid_output_has);
    }

    boost::optional<nlohmann::json> cache::get_liquid_output(byte_span_t txhash, const uint32_t vout)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_output_search.get());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_output_search); });
        bind_blob(m_stmt_liquid_output_search, 1, txhash);
        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquid_output_search.get(), 2, vout) == SQLITE_OK);
        const int rc = sqlite3_step(m_stmt_liquid_output_search.get());
        if (rc == SQLITE_DONE) {
            return boost::none;
        }
        GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
        nlohmann::json utxo;
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
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_key_value_upsert); });
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
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_blinding_nonce_insert); });
        bind_liquid_blinding(m_stmt_liquid_blinding_nonce_insert, pubkey, script);
        bind_blob(m_stmt_liquid_blinding_nonce_insert, 3, nonce);
        step_final(m_stmt_liquid_blinding_nonce_insert);
        m_require_write = true;
    }

    void cache::insert_liquid_output(byte_span_t txhash, uint32_t vout, nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty() && !utxo.empty());
        GDK_RUNTIME_ASSERT(m_stmt_liquid_output_insert.get());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquid_output_insert); });

        // cache values are stored in byte order not display order (reversed)
        bind_blob(m_stmt_liquid_output_insert, 1, txhash);

        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquid_output_insert.get(), 2, vout) == SQLITE_OK);
        const auto assetid = h2b_rev(utxo["asset_id"]);
        bind_blob(m_stmt_liquid_output_insert, 3, assetid);

        const auto satoshi = utxo.at("satoshi");
        GDK_RUNTIME_ASSERT(sqlite3_bind_int64(m_stmt_liquid_output_insert.get(), 4, satoshi) == SQLITE_OK);

        const auto abf = h2b_rev(utxo["assetblinder"]);
        bind_blob(m_stmt_liquid_output_insert, 5, abf);
        const auto vbf = h2b_rev(utxo["amountblinder"]);
        bind_blob(m_stmt_liquid_output_insert, 6, vbf);

        step_final(m_stmt_liquid_output_insert);
        m_require_write = true;
    }
} // namespace sdk
} // namespace ga
