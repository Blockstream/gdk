#include "validate.hpp"
#include "ga_auth_handlers.hpp"

namespace ga {
namespace sdk {
    //
    // Validate
    //
    validate_call::validate_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "validate")
        , m_details(details)
    {
    }

    auth_handler::state_type validate_call::call_impl()
    {
        m_result["errors"] = nlohmann::json::array();
        m_result["is_valid"] = false;
        try {
            liquidex_impl();
            m_result["is_valid"] = true;
        } catch (const std::exception& e) {
            m_result["errors"].emplace_back(e.what());
        }
        return state_type::done;
    }
} // namespace sdk
} // namespace ga
