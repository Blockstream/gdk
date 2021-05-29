#include "session_impl.hpp"
#include "exception.hpp"
#include "logging.hpp"
#include "session.hpp"

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
            set_override(ret, "electrum_tls", user_params, false);
            set_override(ret, "electrum_url", user_params, std::string());
            set_override(ret, "log_level", user_params, "none");
            set_override(ret, "spv_multi", user_params, false);
            set_override(ret, "spv_servers", user_params, nlohmann::json::array());
            set_override(ret, "spv_enabled", user_params, false);
            set_override(ret, "use_tor", user_params, false);
            set_override(ret, "user_agent", user_params, std::string());
            // FIXME: Remove this by fetching it directly where needed
            const std::string datadir = gdk_config().value("datadir", std::string());
            GDK_RUNTIME_ASSERT(!datadir.empty());
            ret["state_dir"] = datadir + "/state";
            return network_parameters{ ret };
        }

        static void configure_logging(const network_parameters& net_params)
        {
            const auto level = net_params.log_level();
            // Default to fatal logging, i.e. 'none' since we don't log any
            auto severity = log_level::severity_level::fatal;
            if (level == "debug") {
                severity = log_level::severity_level::debug;
            } else if (level == "info") {
                severity = log_level::severity_level::info;
            } else if (level == "warn") {
                severity = log_level::severity_level::warning;
            } else if (level == "error") {
                severity = log_level::severity_level::error;
            }
            boost::log::core::get()->set_filter(log_level::severity >= severity);
        }
    } // namespace

    session_impl::session_impl(const nlohmann::json& net_params)
        : m_net_params(get_network_overrides(net_params))
        , m_debug_logging(m_net_params.log_level() == "debug")
    {
        configure_logging(m_net_params);
    }

    session_impl::~session_impl() {}

} // namespace sdk
} // namespace ga
