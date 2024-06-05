#include "redeposit_auth_handlers.hpp"
#include "assertion.hpp"
#include "auth_handler.hpp"
#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "network_parameters.hpp"
#include "session_impl.hpp"

#include <algorithm>
#include <iterator>
#include <memory>

namespace green {

    struct redeposit_data {
        nlohmann::json input_details;
        std::vector<nlohmann::json> fee_utxos;
        nlohmann::json::array_t receive_addresses;
        std::vector<std::string> asset_ids;
        uint32_t subaccount;
    };

    namespace {

        static uint32_t verify_same_subaccount(const nlohmann::json& utxos_set)
        {
            GDK_RUNTIME_ASSERT_MSG(utxos_set.begin()->empty() == false, "can't determine subaccount");
            const auto subaccount = j_uint32ref(utxos_set.begin()->front(), "subaccount");
            for (const auto& utxos : utxos_set) {
                GDK_RUNTIME_ASSERT_MSG(!utxos.empty(), "No utxos for asset");
                bool is_same_sa = std::all_of(utxos.begin(), utxos.end(),
                    [subaccount](const auto& utxo) { return j_uint32(utxo, "subaccount") == subaccount; });
                if (!is_same_sa) {
                    throw user_error("All utxos must be from the same subaccount");
                }
            }
            return subaccount;
        }
        // policy_asset is in the utxos set ( for fees)
        // all utxos belong to the same subaccount
        static void verify_policy_asset(const nlohmann::json& utxos_set, const std::string& policy_asset)
        {
            const auto& policy_asset_utxos = j_array(utxos_set, policy_asset);
            if (!policy_asset_utxos.has_value() || policy_asset_utxos.value().empty()) {
                throw user_error("No utxos for fees");
            }
        }

        // remove utxos that are not expired yet from the utxos input and collect them into a vector
        [[maybe_unused]] static std::vector<nlohmann::json> erase_unexpired_utxos(
            nlohmann::json& utxos, uint32_t current_height)
        {
            std::vector<nlohmann::json> unexpired_utxos;
            const auto utxo_it = std::remove_if(utxos.begin(), utxos.end(),
                [current_height](const auto& utxo) { return j_uint32ref(utxo, "expiry_height") > current_height; });
            unexpired_utxos.insert(
                unexpired_utxos.end(), std::make_move_iterator(utxo_it), std::make_move_iterator(utxos.end()));
            utxos.erase(utxo_it, utxos.end());

            return unexpired_utxos;
        }
    } // namespace

    //
    // Create redeposit transaction
    //
    create_redeposit_transaction_call::create_redeposit_transaction_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "create_redeposit_transaction")
        , m_details(std::make_unique<redeposit_data>())
    {
        m_details->input_details = std::move(details);
    }

    auth_handler::state_type create_redeposit_transaction_call::call_impl()
    {
        const std::string policy_asset = m_net_params.get_policy_asset();
        auto& utxos_set = m_details->input_details.at("utxos");

        if (!utxos_set.empty()) {
            // 1st access to inputs: validity checks + output initialization
            verify_policy_asset(utxos_set, policy_asset);
            m_details->subaccount = verify_same_subaccount(utxos_set);
            m_result = { { "utxos", nlohmann::json::object_t{} }, { "addressees", nlohmann::json::array_t{} } };
        }

        const uint32_t current_height = m_session->get_block_height();
        for (const auto& item : utxos_set.items()) {
            auto unexpired_utxos = erase_unexpired_utxos(item.value(), current_height);
            if (item.key() == policy_asset) {
                m_details->fee_utxos = std::move(unexpired_utxos);
            }
            nlohmann::json::array_t asset_utxos;
            std::copy(item.value().begin(), item.value().end(), std::back_inserter(asset_utxos));
            m_result["utxos"][item.key()] = std::move(asset_utxos);
            m_details->asset_ids.push_back(item.key());
        }
        utxos_set.clear();

        if (m_details->receive_addresses.size() < m_details->asset_ids.size()) {
            // Fetch a new addresses to receive the redeposits on
            nlohmann::json addr_details = { { "subaccount", m_details->subaccount } };
            add_next_handler(new get_receive_address_call(m_session_parent, std::move(addr_details)));
            return state_type::make_call;
        }

        m_result["addressees"] = std::move(m_details->receive_addresses);

        bool tx_created = false;
        while (!tx_created) {
            create_transaction(*m_session, m_result);
            const auto error = j_str_or_empty(m_result, "error");
            if (!error.empty()) {
                // FIXME: res::
                if (error == "Insufficient funds for fees" && !m_details->fee_utxos.empty()) {
                    m_result.at("utxos").emplace_back(std::move(m_details->fee_utxos.back()));
                    m_details->fee_utxos.pop_back();
                } else {
                    return state_type::done;
                }
            } else {
                tx_created = true;
            }
        }
        return state_type::done;
    }

    void create_redeposit_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        nlohmann::json address = std::move(next_handler->move_result());
        address["is_greedy"] = true;
        size_t asset_index = m_details->receive_addresses.size();
        GDK_RUNTIME_ASSERT(asset_index < m_details->asset_ids.size());
        if (m_net_params.is_liquid()) {
            address["asset_id"] = m_details->asset_ids[asset_index];
        }
        m_details->receive_addresses.emplace_back(std::move(address));
    }
} // namespace green
