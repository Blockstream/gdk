#ifndef GDK_TX_LIST_CACHE_HPP
#define GDK_TX_LIST_CACHE_HPP
#pragma once

#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
    class tx_list_cache {
    public:
        using get_txs_fn_t = std::function<std::vector<nlohmann::json>(uint32_t, nlohmann::json&)>;
        using get_fn_ret_t = std::pair<std::vector<nlohmann::json>, nlohmann::json>;

        // Get an item from the cache, using 'get_txs' to fetch missing entries.
        // Note that 'get_txs' must not lock the mutex on ga_session.
        get_fn_ret_t get(uint32_t first, uint32_t count, get_txs_fn_t get_txs);

        void on_new_transaction(const nlohmann::json& details);
        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

    private:
        uint32_t m_next_uncached_page = 0;
        uint32_t m_first_empty_page = std::numeric_limits<uint32_t>::max();
        std::vector<nlohmann::json> m_tx_cache;
        std::mutex m_mutex;
    };

    class tx_list_caches {
    public:
        void purge_all();
        void purge(uint32_t subaccount);
        std::shared_ptr<tx_list_cache> get(uint32_t subaccount);

        void on_new_block(const nlohmann::json& details);
        void on_new_transaction(uint32_t subaccount, const nlohmann::json& details);
        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

    private:
        std::mutex m_mutex;
        std::map<uint32_t, std::shared_ptr<tx_list_cache>> m_caches;
    };

} // namespace sdk
} // namespace ga

#endif
