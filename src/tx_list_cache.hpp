#ifndef GDK_TX_LIST_CACHE_HPP
#define GDK_TX_LIST_CACHE_HPP
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>

#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
    class tx_list_cache {
    public:
        using container_type = std::deque<nlohmann::json>;
        using iterator = container_type::iterator;
        using locker_t = std::unique_lock<std::mutex>;
        using get_txs_fn_t
            = std::function<container_type(uint32_t, const std::string&, const std::string&, nlohmann::json&)>;
        using get_fn_ret_t = std::pair<container_type, nlohmann::json>;

        // Get an item from the cache, using 'get_txs' to fetch missing entries.
        // Note that 'get_txs' must not lock the mutex on ga_session.
        get_fn_ret_t get(uint32_t first, uint32_t count, get_txs_fn_t get_txs);

        void on_new_block(uint32_t ga_block_height, const nlohmann::json& details);
        void on_new_transaction(const nlohmann::json& details);
        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

    private:
        void remove_mempool_txs(const locker_t& locker);
        void remove_forked_txs(const locker_t& locker, uint32_t block_height);

        std::mutex m_mutex;
        bool m_is_front_dirty = true; // Whether we need to fetch the newest txs from the server
        std::string m_oldest_txhash; // The txhash of the final server result, once returned
        container_type m_tx_cache;
    };

    class tx_list_caches {
    public:
        void purge_all();
        void purge(uint32_t subaccount);
        std::shared_ptr<tx_list_cache> get(uint32_t subaccount);

        void on_new_block(uint32_t ga_block_height, const nlohmann::json& details);
        void on_new_transaction(uint32_t subaccount, const nlohmann::json& details);
        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

    private:
        using locker_t = std::unique_lock<std::mutex>;

        std::mutex m_mutex;
        std::map<uint32_t, std::shared_ptr<tx_list_cache>> m_caches;
    };

} // namespace sdk
} // namespace ga

#endif
