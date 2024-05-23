#include "validate.hpp"

#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "network_parameters.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include <utility>

namespace green {

    //
    // Validate
    //
    validate_call::validate_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "validate", {})
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type validate_call::call_impl()
    {
        m_result["errors"] = nlohmann::json::array();
        m_result["is_valid"] = false;
        try {
            if (is_addressees()) {
                addressees_impl();
            } else if (is_liquidex()) {
                liquidex_impl();
            } else {
                throw user_error("Unknown JSON type");
            }
            m_result["is_valid"] = m_result["errors"].empty();
        } catch (const std::exception& e) {
            m_result["errors"].emplace_back(e.what());
        }
        return state_type::done;
    }

    bool validate_call::is_addressees() const { return m_details.contains("addressees"); }
    void validate_call::addressees_impl()
    {
        std::unique_ptr<network_parameters> caller_net_params;
        const bool override_network = m_details.contains("network");
        nlohmann::json::array_t errors;

        if (override_network) {
            // User wants to validate an address for another network
            auto defaults = network_parameters::get(m_details.at("network"));
            caller_net_params = std::make_unique<network_parameters>(defaults);
        }
        const auto& net_params = override_network ? *caller_net_params : m_session->get_network_parameters();
        for (auto& addressee : m_details["addressees"]) {
            nlohmann::json result;
            std::string error = validate_tx_addressee(*m_session, net_params, addressee);
            if (!error.empty()) {
                errors.emplace_back(std::move(error));
            }
        }
        m_result["errors"] = std::move(errors);
        m_result["addressees"] = std::move(m_details["addressees"]);
        if (override_network) {
            m_result.emplace("network", std::move(m_details["network"]));
        }
    }

} // namespace green
