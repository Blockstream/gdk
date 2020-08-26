#include <algorithm>

#include "tx_list_cache.hpp"

namespace ga {
namespace sdk {

    bool tx_list_cache::cache_full() { return m_tx_cache.size() >= CACHE_SIZE; }

    tx_list_cache::get_fn_ret_t tx_list_cache::get(uint32_t first, uint32_t count, get_txs_fn_t get_txs)
    {
        // Code is not optimized for concurrent gets on one subaccount
        std::unique_lock<std::mutex> lock{ m_mutex };

        const auto last = first + count;
        auto fetched = m_tx_cache.size();
        auto page = m_next_uncached_page;
        nlohmann::json state_info = { { "cur_block", 0u }, { "fiat_value", nullptr } };

        auto fetch = [&](uint32_t first, uint32_t last, std::vector<nlohmann::json>& out) {
            const std::vector<nlohmann::json> txs = get_txs(page, state_info);
            if (txs.empty()) {
                m_first_empty_page = page;
            } else {
                fetched += txs.size();
                const auto begin = std::end(txs) - (first >= fetched ? 0 : std::min(fetched - first, txs.size()));
                const auto end = std::end(txs) - (last >= fetched ? 0 : std::min(fetched - last, txs.size()));
                out.insert(std::end(out), begin, end);
            }
            ++page;
        };

        // Add txs to the cache until either it's full or 'last' has been cached
        while (!cache_full() && page < m_first_empty_page && fetched < last) {
            fetch(0, std::numeric_limits<uint32_t>::max(), m_tx_cache);
        }
        m_next_uncached_page = page;

        // Start with cached txs
        const auto begin = std::begin(m_tx_cache) + std::min<uint64_t>(first, m_tx_cache.size());
        const auto end = std::begin(m_tx_cache) + std::min<uint64_t>(last, m_tx_cache.size());
        std::vector<nlohmann::json> result(begin, end);

        // Add txs that don't fit in the cache directly to result
        while (page < m_first_empty_page && fetched < last) {
            fetch(first, last, result);
        }

        return std::make_pair(result, state_info);
    }

    void tx_list_caches::purge_all()
    {
        std::unique_lock<std::mutex> lock{ m_mutex };
        m_caches.clear();
    }

    void tx_list_caches::purge(uint32_t subaccount)
    {
        std::unique_lock<std::mutex> lock{ m_mutex };
        m_caches.erase(subaccount);
    }

    std::shared_ptr<tx_list_cache> tx_list_caches::get(uint32_t subaccount)
    {
        std::unique_lock<std::mutex> lock{ m_mutex };
        std::shared_ptr<tx_list_cache>& cache = m_caches[subaccount];
        if (cache.get() == nullptr) {
            cache.reset(new tx_list_cache());
        }
        return cache;
    }

} // namespace sdk
} // namespace ga
