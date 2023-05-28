#ifndef GDK_GA_CACHE_HPP
#define GDK_GA_CACHE_HPP
#pragma once

#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"
#include <nlohmann/json.hpp>
#include <optional>

struct sqlite3;
struct sqlite3_stmt;

namespace ga {
namespace sdk {
    class network_parameters;
    class signer;

    struct cache final {
        using sqlite3_ptr = std::shared_ptr<struct ::sqlite3>;
        using sqlite3_stmt_ptr = std::shared_ptr<struct ::sqlite3_stmt>;

        cache(const network_parameters& net_params, const std::string& network_name);
        ~cache();

        const std::string& get_network_name() const;

        nlohmann::json get_liquid_output(byte_span_t txhash, const uint32_t vout);
        void insert_liquid_output(byte_span_t txhash, const uint32_t vout, nlohmann::json& utxo);

        std::vector<unsigned char> get_liquid_blinding_nonce(byte_span_t pubkey, byte_span_t script);
        std::vector<unsigned char> get_liquid_blinding_pubkey(byte_span_t script);
        bool insert_liquid_blinding_data(
            byte_span_t pubkey, byte_span_t script, byte_span_t nonce, byte_span_t blinding_pubkey);

        typedef std::function<void(std::optional<byte_span_t>)> get_key_value_fn;
        void get_key_value(const std::string& key, const get_key_value_fn& callback);

        void upsert_key_value(const std::string& key, byte_span_t value);
        void clear_key_value(const std::string& key);

        void set_latest_block(uint32_t block);
        uint32_t get_latest_block();

        typedef std::function<void(uint64_t ts, const std::string& txhash, uint32_t block, uint32_t spent,
            uint32_t spv_status, nlohmann::json& tx_json)>
            get_transactions_fn;
        void get_transactions(
            uint32_t subaccount, uint64_t start_ts, size_t count, const get_transactions_fn& callback);
        void get_transaction(
            uint32_t subaccount, const std::string& txhash_hex, const cache::get_transactions_fn& callback);
        uint64_t get_latest_transaction_timestamp(uint32_t subaccount);
        void insert_transaction(
            uint32_t subaccount, uint64_t timestamp, const std::string& txhash_hex, const nlohmann::json& tx_json);
        void set_transaction_spv_verified(const std::string& txhash_hex);
        void delete_transactions(uint32_t subaccount, uint64_t start_ts = 0);
        bool delete_mempool_txs(uint32_t subaccount);
        bool delete_block_txs(uint32_t subaccount, uint32_t start_block);
        void on_new_transaction(uint32_t subaccount, const std::string& txhash_hex);
        void get_transaction_data(const std::string& txhash_hex, const get_key_value_fn& callback);
        void insert_transaction_data(const std::string& txhash_hex, byte_span_t value);

        nlohmann::json get_scriptpubkey_data(byte_span_t scriptpubkey);
        void insert_scriptpubkey_data(byte_span_t scriptpubkey, uint32_t subaccount, uint32_t branch, uint32_t pointer,
            uint32_t subtype, uint32_t script_type);
        uint32_t get_latest_scriptpubkey_pointer(uint32_t subaccount);

        void save_db();
        void load_db(byte_span_t encryption_key, std::shared_ptr<signer> signer);

        void update_to_latest_minor_version();

    private:
        bool check_db_changed();

        const std::string m_network_name;
        const std::string m_data_dir;
        const bool m_is_liquid;
        uint32_t m_type; // Set on first call to load_db
        std::string m_db_name; // Set on first call to load_db
        std::array<unsigned char, SHA256_LEN> m_encryption_key; // Set on first call to load_db
        bool m_require_write;
        sqlite3_ptr m_db;
        sqlite3_stmt_ptr m_stmt_liquid_blinding_key_search;
        sqlite3_stmt_ptr m_stmt_liquid_blinding_key_insert;
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
        sqlite3_stmt_ptr m_stmt_tx_earliest_mempool_search;
        sqlite3_stmt_ptr m_stmt_tx_earliest_block_search;
        sqlite3_stmt_ptr m_stmt_tx_upsert;
        sqlite3_stmt_ptr m_stmt_tx_spv_update;
        sqlite3_stmt_ptr m_stmt_tx_delete_all;
        sqlite3_stmt_ptr m_stmt_txdata_insert;
        sqlite3_stmt_ptr m_stmt_txdata_search;
        sqlite3_stmt_ptr m_stmt_scriptpubkey_search;
        sqlite3_stmt_ptr m_stmt_scriptpubkey_insert;
        sqlite3_stmt_ptr m_stmt_scriptpubkey_latest_search;
    };

} // namespace sdk
} // namespace ga

#endif
