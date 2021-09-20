#ifndef GDK_GA_CACHE_HPP
#define GDK_GA_CACHE_HPP
#pragma once

#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"
#include <boost/optional.hpp>
#include <nlohmann/json.hpp>

struct sqlite3;
struct sqlite3_stmt;

namespace ga {
namespace sdk {
    class network_parameters;

    struct cache final {
        using sqlite3_ptr = std::shared_ptr<struct ::sqlite3>;
        using sqlite3_stmt_ptr = std::shared_ptr<struct ::sqlite3_stmt>;

        cache(const network_parameters& net_params, const std::string& network_name);
        ~cache();

        nlohmann::json get_liquid_output(byte_span_t txhash, const uint32_t vout);
        void insert_liquid_output(byte_span_t txhash, const uint32_t vout, nlohmann::json& utxo);

        std::vector<unsigned char> get_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script);
        void insert_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script, byte_span_t nonce);

        typedef std::function<void(boost::optional<byte_span_t>)> get_key_value_fn;
        void get_key_value(const std::string& key, const get_key_value_fn& callback);

        void upsert_key_value(const std::string& key, byte_span_t value);
        void clear_key_value(const std::string& key);

        void set_latest_block(uint32_t block);
        uint32_t get_latest_block();

        typedef std::function<void(uint64_t ts, const std::string& txhash, uint32_t block, nlohmann::json& tx_json)>
            get_transactions_fn;
        void get_transactions(
            uint32_t subaccount, uint64_t start_ts, size_t count, const get_transactions_fn& callback);
        void get_transaction(
            uint32_t subaccount, const std::string& txhash_hex, const cache::get_transactions_fn& callback);
        uint64_t get_latest_transaction_timestamp(uint32_t subaccount);
        void insert_transaction(
            uint32_t subaccount, uint64_t timestamp, const std::string& txhash_hex, const nlohmann::json& tx_json);
        void delete_transactions(uint32_t subaccount, uint64_t start_ts = 0);
        void delete_mempool_txs(uint32_t subaccount);
        void delete_block_txs(uint32_t subaccount, uint32_t start_block);
        void on_new_transaction(uint32_t subaccount, const std::string& txhash_hex);

        void save_db();
        void load_db(byte_span_t encryption_key, const uint32_t type);

    private:
        const std::string m_network_name;
        const network_parameters& m_net_params;
        const bool m_is_liquid;
        uint32_t m_type; // Set on first call to load_db
        std::string m_data_dir; // Set on first call to load_db
        std::string m_db_name; // Set on first call to load_db
        std::array<unsigned char, SHA256_LEN> m_encryption_key; // Set on first call to load_db
        bool m_require_write;
        sqlite3_ptr m_db;
        sqlite3_stmt_ptr m_stmt_liquid_blinding_nonce_search;
        sqlite3_stmt_ptr m_stmt_liquid_blinding_nonce_insert;
        sqlite3_stmt_ptr m_stmt_liquid_output_search;
        sqlite3_stmt_ptr m_stmt_liquid_output_insert;
        sqlite3_stmt_ptr m_stmt_key_value_upsert;
        sqlite3_stmt_ptr m_stmt_key_value_search;
        sqlite3_stmt_ptr m_stmt_key_value_delete;
        sqlite3_stmt_ptr m_stmt_tx_search;
        sqlite3_stmt_ptr m_stmt_txid_search;
        sqlite3_stmt_ptr m_stmt_tx_latest_search;
        sqlite3_stmt_ptr m_stmt_tx_mempool_search;
        sqlite3_stmt_ptr m_stmt_tx_block_search;
        sqlite3_stmt_ptr m_stmt_tx_upsert;
        sqlite3_stmt_ptr m_stmt_tx_delete_all;
    };

} // namespace sdk
} // namespace ga

#endif
