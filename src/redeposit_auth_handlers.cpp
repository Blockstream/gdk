#include "redeposit_auth_handlers.hpp"
#include "assertion.hpp"
#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "network_parameters.hpp"
#include "session_impl.hpp"

#include <algorithm>
#include <iterator>
#include <memory>

namespace green {

    namespace {
        // Remove non-expired utxos and return them
        static auto filter_unexpired_utxos(nlohmann::json& utxos, uint64_t block_height)
        {
            nlohmann::json::array_t unexpired;
            auto&& is_not_expired = [block_height](const auto& utxo) -> bool {
                if (auto expiry = j_uint32(utxo, "expiry_height"); expiry) {
                    return *expiry > block_height; // true if not expired yet
                }
                return true; // No expiry_height in UTXO
            };
            auto it = std::remove_if(utxos.begin(), utxos.end(), is_not_expired);
            unexpired.insert(unexpired.end(), std::make_move_iterator(it), std::make_move_iterator(utxos.end()));
            utxos.erase(it, utxos.end());
            return unexpired;
        }
    } // namespace

    //
    // Create redeposit transaction
    //
    create_redeposit_transaction_call::create_redeposit_transaction_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "create_redeposit_transaction")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type create_redeposit_transaction_call::call_impl()
    {
        if (m_result.empty()) {
            // Initial call, verify inputs and set up data for processing
            try {
                initialize();
            } catch (const std::exception& e) {
                m_result = { { "error", e.what() } };
                return state_type::done;
            }
        }

        const auto policy_asset = m_net_params.get_policy_asset();
        auto& utxos = j_ref(m_details, "utxos");
        auto& addressees = j_arrayref(m_result, "addressees");
        if (addressees.size() < utxos.size()) {
            // Fetch a new address for the next asset to redeposit
            const bool is_fee = get_nth_asset_id(addressees.size()) == policy_asset;
            const auto& subaccount = is_fee ? m_fee_subaccount : m_subaccount;
            GDK_RUNTIME_ASSERT(subaccount.has_value());
            nlohmann::json details{ { "subaccount", *subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, std::move(details)));
            return state_type::make_call;
        }

        // We have our addressees, loop to create the redeposit tx
        m_result["utxos"] = std::move(utxos);
        for (;;) {
            create_transaction(*m_session, m_result);
            if (j_strref(m_result, "error") == "Insufficient funds for fees") {
                // Add another fee UTXO and try again
                add_fee_utxo(m_result);
                continue;
            }
            // Any other error, or no error means we are done
            return state_type::done;
        }
    }

    void create_redeposit_transaction_call::initialize()
    {
        const auto policy_asset = m_net_params.get_policy_asset();
        uint64_t block_height;
        auto& utxos = j_ref(m_details, "utxos");
        std::set<std::string> to_erase;

        const auto expired_at = j_uint32(m_details, "expired_at");
        const auto expires_in = j_uint32(m_details, "expires_in");
        if (expired_at) {
            if (expires_in) {
                throw user_error("Only one of \"expired_at\" or \"expires_in\" may be given");
            }
            // Use the absolute expiry height given
            block_height = *expired_at;
        } else {
            // Assume the current block height is the expiry height
            block_height = m_session->get_block_height();
            if (expires_in) {
                // Add the number of relative blocks to the current block height
                block_height += *expires_in;
            }
        }
        for (auto& asset : utxos.items()) {
            // Check all UTXOs are from the same subaccount, with the
            // exception that we allow fees to be paid from any subaccount
            const bool is_fee_asset = asset.key() == policy_asset;
            auto unexpired = filter_unexpired_utxos(asset.value(), block_height);
            if (is_fee_asset && !unexpired.empty()) {
                // Store unexpired fee UTXOs for adding later if required
                m_fee_utxos.swap(unexpired);
                // Reverse them so we can use pop_back() to remove them
                std::reverse(m_fee_utxos.begin(), m_fee_utxos.end());
            }
            const auto& asset_utxos = asset.value();
            if (asset_utxos.empty()) {
                // No expired UTXOs for this asset
                to_erase.insert(asset.key());
            } else {
                if (!is_fee_asset) {
                    // Ensure all asset UTXOs come from the same subaccount
                    if (!m_subaccount) {
                        m_subaccount = j_uint32ref(asset.value().front(), "subaccount");
                    }
                    bool is_same_sa = std::all_of(asset_utxos.begin(), asset_utxos.end(),
                        [this](const auto& u) { return j_uint32ref(u, "subaccount") == *m_subaccount; });
                    if (!is_same_sa) {
                        throw user_error("\"utxos\" elements must be from the same subaccount");
                    }
                }
            }
        }
        for (const auto& asset_id : to_erase) {
            // Remove any assets that don't have expired UTXOs
            j_erase(utxos, asset_id);
        }
        if (utxos.empty()) {
            // No expired UTXOs to redeposit
            throw user_error(res::id_no_utxos_found);
        }
        if (!utxos.contains(policy_asset)) {
            // Add an initial fee UTXO (or throw if none are available)
            utxos[policy_asset] = nlohmann::json::array_t();
            add_fee_utxo(m_details);
        }
        if (const auto fee_rate = j_amount(m_details, "fee_rate"); fee_rate) {
            // Use the callers provided fee rate
            m_result["fee_rate"] = fee_rate->value();
        }
        m_fee_subaccount = j_uint32(m_details, "fee_subaccount");
        if (!m_fee_subaccount) {
            // No fee subaccount given - take it from the first used utxo
            const auto& fee_utxos = j_arrayref(utxos, policy_asset);
            m_fee_subaccount = j_uint32ref(fee_utxos.front(), "subaccount");
        }
        nlohmann::json addressees = nlohmann::json::array_t{};
        if (auto p = m_details.find("addressees"); p != m_details.end()) {
            // Being called with previous result; use the existing addressees
            // to avoid generating new addresses each time we are called
            addressees = std::move(*p);
            // Reset asset/greedy status in case the caller changed them
            size_t n = 0;
            for (auto& addressee : addressees) {
                if (m_net_params.is_liquid()) {
                    addressee["asset_id"] = get_nth_asset_id(n);
                }
                addressee["is_greedy"] = true;
                ++n;
            }
        }
        m_result["addressees"] = std::move(addressees);
    }

    std::string create_redeposit_transaction_call::get_nth_asset_id(size_t n) const
    {
        for (const auto& asset : j_ref(m_details, "utxos").items()) {
            if (!n--) {
                return asset.key();
            }
        }
        GDK_RUNTIME_ASSERT(false);
    }

    void create_redeposit_transaction_call::add_fee_utxo(nlohmann::json& to)
    {
        if (m_fee_utxos.empty()) {
            throw user_error("Insufficient funds for fees"); // FIXME res::
        }
        const auto policy_asset = m_net_params.get_policy_asset();
        auto& fee_utxos = const_cast<json_array_t&>(j_arrayref(j_ref(to, "utxos"), policy_asset));
        fee_utxos.push_back(std::move(m_fee_utxos.back()));
        m_fee_utxos.pop_back();
    }

    void create_redeposit_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        // We have fetched a new address to redeposit to.
        // Add it as a greedy adressee for the asset we are redepositing.
        auto& addressees = const_cast<json_array_t&>(j_arrayref(m_result, "addressees"));
        auto addressee = std::move(next_handler->move_result());
        if (m_net_params.is_liquid()) {
            addressee["asset_id"] = get_nth_asset_id(addressees.size());
        }
        addressee["is_greedy"] = true;
        addressees.emplace_back(std::move(addressee));
    }
} // namespace green
