#include "session_impl.hpp"
#include "exception.hpp"
#include "logging.hpp"

namespace ga {
namespace sdk {

    namespace {
        template <typename T>
        static void set_override(nlohmann::json& ret, const std::string& key, const nlohmann::json& src, T default_)
        {
            // Use the users provided value, else the registered value, else `default_`
            ret[key] = src.value(key, ret.value(key, default_));
        }

        static network_parameters get_network_overrides(const nlohmann::json& user_params)
        {
            // Get the registered network parameters the passed in parameters are based on
            auto ret = network_parameters::get(user_params.at("name"));
            // Set override-able settings from the users parameters
            set_override(ret, "electrum_url", user_params, std::string());
            set_override(ret, "log_level", user_params, "none");
            set_override(ret, "spv_cross_validation", user_params, false);
            set_override(ret, "spv_cross_validation_servers", user_params, nlohmann::json::array());
            set_override(ret, "spv_enabled", user_params, false);
            set_override(ret, "tls", user_params, false);
            set_override(ret, "use_tor", user_params, false);
            set_override(ret, "user_agent", user_params, std::string());

            return network_parameters{ ret };
        }
    } // namespace

    session_impl::session_impl(const nlohmann::json& net_params)
        : m_net_params(get_network_overrides(net_params))
    {
    }

    session_impl::~session_impl() {}

} // namespace sdk
} // namespace ga
