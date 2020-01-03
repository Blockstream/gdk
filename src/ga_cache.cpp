#include <algorithm>
#include <array>
#include <fstream>
#include <openssl/evp.h>
#include <vector>

#include "assertion.hpp"
#include "ga_cache.hpp"
#include "logging.hpp"
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
        constexpr int VERSION = 0;

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

        static auto get_stmt(sqlite3* db, const char* statement)
        {
            sqlite3_stmt* tmpstmt = nullptr;
            const int rc = sqlite3_prepare_v3(db, statement, -1, SQLITE_PREPARE_PERSISTENT, &tmpstmt, NULL);
            GDK_RUNTIME_ASSERT_MSG(rc == SQLITE_OK, sqlite3_errmsg(db));
            return tmpstmt;
        }

        static void stmt_check_clean(sqlite3_stmt* stmt)
        {
            const int rc = sqlite3_clear_bindings(stmt);
            GDK_RUNTIME_ASSERT_MSG(rc == SQLITE_OK, sqlite3_errmsg(sqlite3_db_handle(stmt)));
            const int rc2 = sqlite3_reset(stmt);
            GDK_RUNTIME_ASSERT_MSG(rc2 == SQLITE_OK, sqlite3_errmsg(sqlite3_db_handle(stmt)));
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

        static auto get_result(sqlite3_stmt* stmt, const int size = 0)
        {
            const auto res = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 0));
            const auto bytes = sqlite3_column_bytes(stmt, 0);
            GDK_RUNTIME_ASSERT(size == 0 || bytes == size);
            const std::vector<unsigned char> result(res, res + bytes);
            GDK_RUNTIME_ASSERT(sqlite3_step(stmt) == SQLITE_DONE);
            return result;
        }

        static void bind_blob(sqlite3_stmt* stmt, const int column, byte_span_t blob)
        {
            GDK_RUNTIME_ASSERT(sqlite3_bind_blob(stmt, column, blob.data(), blob.size(), SQLITE_STATIC) == SQLITE_OK);
        }

        static void bind_liquidblinding(sqlite3_stmt* stmt, byte_span_t pubkey, byte_span_t script)
        {
            bind_blob(stmt, 1, pubkey);
            bind_blob(stmt, 2, script);
        }

        static bool has_result(sqlite3_stmt* stmt, int rc)
        {
            if (rc == SQLITE_DONE) {
                return false;
            }
            GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
            GDK_RUNTIME_ASSERT(sqlite3_step(stmt) == SQLITE_DONE);
            return true;
        }
    } // namespace

    cache::cache(const std::string& network_name)
        : m_network_name(network_name)
        , m_db(get_db())
        , m_stmt_liquidblindingnonce_has(
              get_stmt(m_db.get(), "SELECT 1 FROM LiquidBlindingNonce WHERE pubkey = ?1 AND script = ?2 LIMIT 1;"))
        , m_stmt_liquidblindingnonce_search(
              get_stmt(m_db.get(), "SELECT nonce FROM LiquidBlindingNonce WHERE pubkey = ?1 AND script = ?2;"))
        , m_stmt_liquidblindingnonce_insert(
              get_stmt(m_db.get(), "INSERT INTO LiquidBlindingNonce (pubkey, script, nonce) VALUES (?1, ?2, ?3);"))
        , m_stmt_liquidoutput_has(
              get_stmt(m_db.get(), "SELECT 1 FROM LiquidOutput WHERE txid = ?1 AND vout = ?2 LIMIT 1;"))
        , m_stmt_liquidoutput_search(get_stmt(
              m_db.get(), "SELECT assetid, satoshi, abf, vbf FROM LiquidOutput WHERE txid = ?1 AND vout = ?2;"))
        , m_stmt_liquidoutput_insert(get_stmt(m_db.get(),
              "INSERT INTO LiquidOutput (txid, vout, assetid, satoshi, abf, vbf) VALUES (?1, ?2, ?3, ?4, ?5, ?6);"))
        , m_stmt_keyvalue_upsert(get_stmt(
              m_db.get(), "INSERT INTO KeyValue(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=?2;"))
        , m_stmt_keyvalue_search(get_stmt(m_db.get(), "SELECT value FROM KeyValue WHERE key = ?1;"))
        , m_stmt_keyvalue_delete(get_stmt(m_db.get(), "DELETE FROM KeyValue WHERE key = ?1;"))
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

    void cache::clear_keyvalue(const std::string& key)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_keyvalue_delete.get()); });
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_keyvalue_delete.get(), 1, key_span);
        GDK_RUNTIME_ASSERT(sqlite3_step(m_stmt_keyvalue_delete.get()) == SQLITE_DONE);
    }

    boost::optional<std::vector<unsigned char>> cache::get(const std::string& key)
    {
        GDK_RUNTIME_ASSERT(!key.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_keyvalue_search.get()); });
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_keyvalue_search.get(), 1, key_span);
        const int rc = sqlite3_step(m_stmt_keyvalue_search.get());

        if (rc == SQLITE_DONE) {
            return boost::none;
        }

        GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
        return get_result(m_stmt_keyvalue_search.get());
    }

    bool cache::has_liquidblindingnonce(byte_span_t pubkey, byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidblindingnonce_has.get()); });
        bind_liquidblinding(m_stmt_liquidblindingnonce_has.get(), pubkey, script);
        return has_result(m_stmt_liquidblindingnonce_has.get(), sqlite3_step(m_stmt_liquidblindingnonce_has.get()));
    }

    boost::optional<std::vector<unsigned char>> cache::get_liquidblindingnonce(byte_span_t pubkey, byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidblindingnonce_search.get()); });
        bind_liquidblinding(m_stmt_liquidblindingnonce_search.get(), pubkey, script);
        const int rc = sqlite3_step(m_stmt_liquidblindingnonce_search.get());

        if (rc == SQLITE_DONE) {
            return boost::none;
        }
        GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
        return get_result(m_stmt_liquidblindingnonce_search.get());
    }

    bool cache::has_liquidoutput(byte_span_t txhash, const uint32_t vout)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidoutput_has.get()); });
        bind_blob(m_stmt_liquidoutput_has.get(), 1, txhash);
        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquidoutput_has.get(), 2, vout) == SQLITE_OK);
        const int rc = sqlite3_step(m_stmt_liquidoutput_has.get());
        return has_result(m_stmt_liquidoutput_has.get(), rc);
    }

    boost::optional<nlohmann::json> cache::get_liquidoutput(byte_span_t txhash, const uint32_t vout)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidoutput_search.get()); });
        bind_blob(m_stmt_liquidoutput_search.get(), 1, txhash);
        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquidoutput_search.get(), 2, vout) == SQLITE_OK);
        const int rc = sqlite3_step(m_stmt_liquidoutput_search.get());
        if (rc == SQLITE_DONE) {
            return boost::none;
        }
        GDK_RUNTIME_ASSERT(rc == SQLITE_ROW);
        nlohmann::json utxo;
        const auto _get_result = [this](const int column, const int size) {
            GDK_RUNTIME_ASSERT(sqlite3_column_bytes(m_stmt_liquidoutput_search.get(), column) == size);
            const auto res
                = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(m_stmt_liquidoutput_search.get(), column));
            GDK_RUNTIME_ASSERT(res);
            return b2h(gsl::make_span(res, size));
        };

        utxo["asset_id"] = _get_result(0, ASSET_TAG_LEN);
        utxo["satoshi"] = sqlite3_column_int64(m_stmt_liquidoutput_search.get(), 1);
        utxo["abf"] = _get_result(2, 32);
        utxo["vbf"] = _get_result(3, 32);

        GDK_RUNTIME_ASSERT(sqlite3_step(m_stmt_liquidoutput_search.get()) == SQLITE_DONE);
        return utxo;
    }

    void cache::upsert_keyvalue(const std::string& key, byte_span_t value)
    {
        GDK_RUNTIME_ASSERT(!key.empty() && !value.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_keyvalue_upsert.get()); });
        const auto key_span = ustring_span(key);
        bind_blob(m_stmt_keyvalue_upsert.get(), 1, key_span);
        bind_blob(m_stmt_keyvalue_upsert.get(), 2, value);
        GDK_RUNTIME_ASSERT(sqlite3_step(m_stmt_keyvalue_upsert.get()) == SQLITE_DONE);
        m_require_write = true;
    }

    void cache::insert_liquidblindingnonce(byte_span_t pubkey, byte_span_t script, byte_span_t nonce)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty() && !nonce.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidblindingnonce_insert.get()); });
        bind_liquidblinding(m_stmt_liquidblindingnonce_insert.get(), pubkey, script);
        bind_blob(m_stmt_liquidblindingnonce_insert.get(), 3, nonce);
        GDK_RUNTIME_ASSERT(sqlite3_step(m_stmt_liquidblindingnonce_insert.get()) == SQLITE_DONE);
        m_require_write = true;
    }

    void cache::insert_liquidoutput(byte_span_t txhash, uint32_t vout, nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(!txhash.empty() && !utxo.empty());
        const auto _stmt_clean = gsl::finally([this] { stmt_check_clean(m_stmt_liquidoutput_insert.get()); });

        bind_blob(m_stmt_liquidoutput_insert.get(), 1, txhash);

        GDK_RUNTIME_ASSERT(sqlite3_bind_int(m_stmt_liquidoutput_insert.get(), 2, vout) == SQLITE_OK);
        const auto assetid = h2b(utxo["asset_id"]);
        bind_blob(m_stmt_liquidoutput_insert.get(), 3, assetid);

        const auto satoshi = utxo.at("satoshi");
        GDK_RUNTIME_ASSERT(sqlite3_bind_int64(m_stmt_liquidoutput_insert.get(), 4, satoshi) == SQLITE_OK);

        const auto abf = h2b(utxo["abf"]);
        bind_blob(m_stmt_liquidoutput_insert.get(), 5, abf);
        const auto vbf = h2b(utxo["vbf"]);
        bind_blob(m_stmt_liquidoutput_insert.get(), 6, vbf);

        GDK_RUNTIME_ASSERT(sqlite3_step(m_stmt_liquidoutput_insert.get()) == SQLITE_DONE);
        m_require_write = true;
    }
} // namespace sdk
} // namespace ga
