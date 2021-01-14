#include <algorithm>

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "logging.hpp"
#include "tx_list_cache.hpp"

#if 0 // Change to 1 for info level debug output
#define cache_log_level log_level::info
#else
#define cache_log_level log_level::debug
#endif

namespace ga {
namespace sdk {

    using container_type = tx_list_cache::container_type;
    using value_type = tx_list_cache::container_type::value_type;
    using iterator = tx_list_cache::iterator;
    using get_txs_fn_t = tx_list_cache::get_txs_fn_t;

    /* Cache semantics:
     * - gdk provides a first,count fetch interface in timestamp order.
     * - This means we must always have all txs from the youngest on before we answer any
     *   query, and we must populate the cache sufficiently to return 'count' entries.
     * - Events that change the cache are:
     *   1) The arrival of a tx notification,
     *   2) Block re-orgs, and
     *   3) Logging out/back in.
     * - For 1) We must delete all mempool txs, since an incoming tx may double spend
     *   (or confirm) any unconfirmed tx. Any confirmed txs can remain cached.
     * - For 2), We must delete all mempool txs and additionally all txs younger than
     *   the re-org'd block (since the mempool will change if txs re-enter it, and txs
     *   after the re-org point may be in different blocks or dropped).
     * - For 3), we must assume when logging in that we may have missed a re-org, and
     *   so remove N blocks from the results where N is the largest expected re-org.
     *   However when reconnecting, if we have not missed a block notification this
     *   can be avoided (TODO).
     * - The timestamp of the transaction is the server sort key, but this timestamp
     *   is set when the signed tx is entered into the servers database.
     * - As such, a mempool tx may appear later in the list returned from the server
     *   than a confirmed tx, if it has yet to confirm (e.g. due to low fee).
     * - We must therefore delete all txs from the first until the last mempool tx
     *   when clearing the mempool, and
     * - We must delete all txs from the first until the oldest tx in a re-org'd block
     *   when handling a re-org.
     * - Deleting in this way means we can leave the remaining txs cached, and fetch
     *   from the server until our results contain the first item in the pruned cache,
     *   ensuring that we have not missed any txs.
     * - We minimise the server load/data returned when fetching by using the timestamp
     *   of the youngest cached tx as the end time for the query, and when loading newer
     *   txs we use the start time of any existing cached txs to limit overhead further.
     * - Note that the start and end date passed are absolute regardless of sort order;
     *   start date is inclusive while end date is not; and the default sort order (which
     *   is what we use) means their meanings are reversed from what you'd normally expect.
     * - The above holds true given the information currently returned from the server,
     *   it would be possible to be more efficient if more information is notified in
     *   the future and/or the server data is returned in a more efficient manner.
     */
    namespace {
        static constexpr size_t TXS_PER_PAGE = 30u; // Number of txs per page the server returns

        // Find the last instance of a cache item matching predicate 'fn'
        template <typename FN> static iterator find_last_of(container_type& cache, const FN& fn)
        {
            auto last = cache.end();
            for (auto i = cache.begin(); i != cache.end(); ++i) {
                if (fn(*i)) {
                    last = i;
                }
            }
            return last;
        }

        // Return a date 'num_seconds' seconds after the given date, in the
        // format expected for GA transaction queries.
        std::string get_query_date(const std::string& date, uint32_t num_seconds)
        {
            // Server returned 'created_at' format is "YYYY-MM-DD HH:SS:MM"
            // Server expected query format is "YYYY-MM-DDTHH:SS:MM.000Z"
            using namespace boost::posix_time;
            auto dt = to_iso_extended_string(time_from_string(date) + seconds(num_seconds));
            std::vector<std::string> dt_parts;
            boost::algorithm::split(dt_parts, dt, boost::is_any_of(","));
            return dt_parts.front() + ".000Z";
        }

        void filter_replaced_by(container_type& txs)
        {
            // Remove all replaced transactions
            // TODO: Add 'replaces' to txs that were bumped, and mark replaced?
            txs.erase(std::remove_if(
                          txs.begin(), txs.end(), [](const auto& tx) -> bool { return tx.contains("replaced_by"); }),
                txs.end());
        }

        static void dump_cache(const container_type& cache, const std::string& message)
        {
#if 0 // Change to 1 for cache dumping
            std::ostringstream os;
            os << message << ':';
            if (cache.empty()) {
                os << "(empty)";
            }
            for (const auto& tx : cache) {
                os << "(<" << json_get_value(tx, "block_height", 0)
                   << "> " << json_get_value(tx, "created_at")
                   << " {" << json_get_value(tx, "txhash") << "}),";
            }
            GDK_LOG_SEV(cache_log_level) << os.str();
#else
            (void)cache;
            (void)message;
#endif
        }

        static auto fetch_txs(
            const value_type* start_tx, const value_type* end_tx, nlohmann::json& state_info, get_txs_fn_t get_txs)
        {
            const std::string start_at = start_tx ? json_get_value(*start_tx, "created_at") : std::string();
            const std::string start_date = start_tx ? get_query_date(start_at, 0) : std::string();
            const std::string end_at = end_tx ? json_get_value(*end_tx, "created_at") : std::string();
            const std::string end_date = end_tx ? get_query_date(end_at, 1) : std::string();
            std::string latest_end_at;
            // Load all pages with the same created_at date at once. This can realistically
            // only happen in test environments; Loading all of them prevents us having to
            // deal with several ugly special cases.
            uint32_t page = 0;
            size_t page_tx_count;
            container_type page_txs;
            do {
                container_type tmp{ get_txs(page, start_date, end_date, state_info) };
                if (!tmp.empty()) {
                    latest_end_at = json_get_value(tmp.front(), "created_at");
                }
                page_tx_count = tmp.size();
                filter_replaced_by(tmp);
                page_txs.insert(
                    page_txs.end(), std::make_move_iterator(tmp.begin()), std::make_move_iterator(tmp.end()));
                ++page;
            } while (latest_end_at == end_at && page_tx_count == TXS_PER_PAGE);
            GDK_RUNTIME_ASSERT_MSG(!end_tx || !page_txs.empty(), "Expected at least one transaction");

            bool is_last_page = page_tx_count != TXS_PER_PAGE;

            // Note that created_date is not inclusive and there may be more than one
            // end_tx with the same timestamp, so we must skip to our last cached end_tx + 1
            // to ignore any txs we already have cached.
            if (end_tx) {
                const std::string end_txhash = json_get_value(*end_tx, "txhash");
                auto tx_eq = [&end_txhash](const value_type& tx) { return tx["txhash"] == end_txhash; };
                auto p = std::find_if(page_txs.begin(), page_txs.end(), tx_eq);
                GDK_RUNTIME_ASSERT_MSG(p != page_txs.end(), "Last cached tx not found");
                page_txs.erase(page_txs.begin(), std::next(p));
            }

            if (start_tx) {
                const std::string start_txhash = json_get_value(*start_tx, "txhash");
                auto tx_eq = [&start_txhash](const value_type& tx) { return tx["txhash"] == start_txhash; };
                auto p = std::find_if(page_txs.begin(), page_txs.end(), tx_eq);
                if (p != page_txs.end()) {
                    // We have loaded the txs up until the start of our cache.
                    // Remove the already cached items from the results.
                    page_txs.erase(p, page_txs.end());
                    // The server has more results, but we already have them cached
                    is_last_page = true;
                }
            }

            return std::make_pair(page_txs, is_last_page);
        }
    } // namespace

    tx_list_cache::get_fn_ret_t tx_list_cache::get(uint32_t first, uint32_t count, get_txs_fn_t get_txs)
    {
        const auto move_iter = std::make_move_iterator<iterator>;

        const uint32_t required_cache_size = first + count;
        nlohmann::json state_info = { { "cur_block", 0u }, { "fiat_value", nullptr }, { "have_more_results", false } };
        container_type page_txs;
        bool is_last_page;

        dump_cache(m_tx_cache, "before get");

        if (m_is_front_dirty) {
            // Load any new txs we need from the server
            container_type txs;

            if (m_oldest_txhash == "none") {
                // Previously we had no txs fetched from the server, but we
                // need to re-check since the front of the cache is dirty.
                m_oldest_txhash.clear();
            }

            do {
                // We need to load the newest txs from the server, until we either
                // A) See all txs or the tx at the start of our cache, OR
                // B) Have loaded up to 'required_cache_size' items (if our cache is empty)
                const value_type* start_tx = m_tx_cache.empty() ? nullptr : &m_tx_cache.front();
                const value_type* end_tx = txs.empty() ? nullptr : &txs.back();
                std::tie(page_txs, is_last_page) = fetch_txs(start_tx, end_tx, state_info, get_txs);

                // Add the loaded txs to our collection
                txs.insert(txs.end(), move_iter(page_txs.begin()), move_iter(page_txs.end()));
            } while (!is_last_page && m_tx_cache.empty() && txs.size() < required_cache_size);

            if (is_last_page && m_tx_cache.empty()) {
                // We loaded all the users txs while loading the newest ones.
                // Record the oldest txhash so we know we don't need to load more.
                m_oldest_txhash = txs.empty() ? "none" : txs.back()["txhash"];
            }
            // Add all loaded txs to the start of the tx cache.
            m_tx_cache.insert(m_tx_cache.begin(), move_iter(txs.begin()), move_iter(txs.end()));

            // Avoid reloading new txs until we are dirtied again by a new tx/block.
            m_is_front_dirty = false;
        }

        // At this point, the cache contains the newest txs from the server, followed
        // by any txs we already had cached.

        if (m_tx_cache.empty()) {
            // The caller has no txs.
            return std::make_pair(container_type(), state_info);
        }

        // Load any older txs we need from the server
        while (m_tx_cache.size() < required_cache_size && m_oldest_txhash.empty()) {
            // We need to load more txs from the server to fulfill the callers
            // request, and we have more txs available to fetch.
            const value_type* end_tx = &m_tx_cache.back();
            std::tie(page_txs, is_last_page) = fetch_txs(nullptr, end_tx, state_info, get_txs);

            // Add the loaded txs to the end of the tx cache.
            m_tx_cache.insert(m_tx_cache.end(), move_iter(page_txs.begin()), move_iter(page_txs.end()));

            if (is_last_page) {
                // We have loaded all txs from the server.
                // Record the oldest txhash so we know we don't need to load more.
                m_oldest_txhash = m_tx_cache.back()["txhash"];
            }
        }

        if (first >= m_tx_cache.size()) {
            // Caller is asking for txs beyond the cache size.
            return std::make_pair(container_type(), state_info);
        }

        // return results from the cached txs
        const auto start = m_tx_cache.begin() + first;
        const size_t remaining = std::distance(start, m_tx_cache.end());
        const auto finish = start + std::min<size_t>(count, remaining);

        dump_cache(m_tx_cache, " after get");
        return std::make_pair(container_type{ start, finish }, state_info);
    }

    void tx_list_cache::on_new_block(uint32_t ga_block_height, const nlohmann::json& details)
    {
        (void)ga_block_height;
        const uint32_t diverged = details["diverged_count"];
        if (diverged) {
            GDK_LOG_SEV(log_level::info) << "chain reorg detected, clearing cache...";
            // TODO: Delete only outdated blocks
            m_tx_cache.clear();
            m_is_front_dirty = true;
            m_oldest_txhash.clear();
        } else {
            remove_mempool_txs();
        }
    }

    void tx_list_cache::on_new_transaction(const nlohmann::json& details)
    {
        auto p = find_last_of(
            m_tx_cache, [&details](const auto& tx) -> bool { return tx["txhash"] == details["txhash"]; });
        if (p != m_tx_cache.end() && json_get_value((*p), "block_height", 0) != 0) {
            // We have been notified of a confirmed tx we already had cached as confirmed.
            // Either the tx was reorged or the server is re-processing txs; either way
            // remove all cached txs from the block the tx was originally in onwards, along
            // with any mempool txs.
            remove_forked_txs(json_get_value((*p), "block_height", 0));
        } else {
            // We havent seen this tx yet, or we've been re-notified of a mempool tx.
            // Remove any mempool txs this tx could be double spending/replacing
            remove_mempool_txs();
        }
        // Whether we removed any cached txs or not, there is a new tx we don't have,
        // so the front of the cache needs refreshing
        m_is_front_dirty = true;
    }

    void tx_list_cache::remove_mempool_txs()
    {
        GDK_LOG_SEV(cache_log_level) << "remove_mempool_txs";
        dump_cache(m_tx_cache, "before remove_mempool_txs");
        auto p = find_last_of(
            m_tx_cache, [](const auto& tx) -> bool { return json_get_value(tx, "block_height", 0) == 0; });
        if (p != m_tx_cache.end()) {
            m_tx_cache.erase(m_tx_cache.begin(), std::next(p));
            // We removed some tx, so the front of the cache needs refreshing
            m_is_front_dirty = true;
        }
        if (m_tx_cache.empty()) {
            // We removed all cached txs or had none cached, so we don't know
            // the txhash of the last item the server would return yet.
            m_oldest_txhash.clear();
        }
        dump_cache(m_tx_cache, "after remove_mempool_txs");
    }

    void tx_list_cache::remove_forked_txs(uint32_t block_height)
    {
        GDK_LOG_SEV(cache_log_level) << "remove_forked_txs";
        dump_cache(m_tx_cache, "before remove_forked_txs");
        auto p = find_last_of(m_tx_cache, [block_height](const auto& tx) -> bool {
            const uint32_t bh = json_get_value(tx, "block_height", 0);
            return bh == 0 || bh >= block_height;
        });
        if (p != m_tx_cache.end()) {
            m_tx_cache.erase(m_tx_cache.begin(), std::next(p));
        }
        dump_cache(m_tx_cache, "after remove_forked_txs");
    }

    void tx_list_caches::purge_all() { m_caches.clear(); }

    void tx_list_caches::purge(uint32_t subaccount) { m_caches.erase(subaccount); }

    std::shared_ptr<tx_list_cache> tx_list_caches::get(uint32_t subaccount)
    {
        std::shared_ptr<tx_list_cache>& cache = m_caches[subaccount];
        if (cache.get() == nullptr) {
            cache.reset(new tx_list_cache());
        }
        return cache;
    }

    void tx_list_caches::on_new_block(uint32_t ga_block_height, const nlohmann::json& details)
    {
        GDK_LOG_SEV(cache_log_level) << "on_new_block:" << details.dump();
        for (auto& cache : m_caches) {
            cache.second->on_new_block(ga_block_height, details);
        }
    }

    void tx_list_caches::on_new_transaction(uint32_t subaccount, const nlohmann::json& details)
    {
        GDK_LOG_SEV(cache_log_level) << "on_new_transaction:" << details.dump();
        get(subaccount)->on_new_transaction(details);
    }

} // namespace sdk
} // namespace ga
