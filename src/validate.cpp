#include "validate.hpp"

#include "containers.hpp"
#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "transaction_utils.hpp"
#include <utility>

namespace ga {
namespace sdk {
    //
    // Validate
    //
    validate_call::validate_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "validate")
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
        nlohmann::json::array_t errors;

        for (auto& addressee : m_details["addressees"]) {
            nlohmann::json result;
            std::string error = validate_tx_addressee(*m_session, addressee);
            if (!error.empty()) {
                errors.emplace_back(std::move(error));
            }
        }
        m_result["errors"] = std::move(errors);
        m_result["addressees"] = std::move(m_details["addressees"]);
    }
} // namespace sdk
} // namespace ga
