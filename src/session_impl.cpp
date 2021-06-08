#include "session_impl.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
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

        static network_parameters get_network_overrides(const nlohmann::json& user_params, nlohmann::json& defaults)
        {
            // Set override-able settings from the users parameters
            set_override(defaults, "electrum_tls", user_params, false);
            set_override(defaults, "electrum_url", user_params, std::string());
            set_override(defaults, "log_level", user_params, "none");
            set_override(defaults, "spv_multi", user_params, false);
            set_override(defaults, "spv_servers", user_params, nlohmann::json::array());
            set_override(defaults, "spv_enabled", user_params, false);
            set_override(defaults, "use_tor", user_params, false);
            set_override(defaults, "user_agent", user_params, std::string());
            return network_parameters{ defaults };
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

    boost::shared_ptr<session_impl> session_impl::create(const nlohmann::json& net_params)
    {
        auto defaults = network_parameters::get(net_params.value("name", std::string()));
        const auto type = net_params.value("server_type", defaults.value("server_type", std::string()));

        if (type == "green") {
            return boost::make_shared<ga_session>(net_params, defaults);
        }
#ifdef BUILD_GDK_RUST
        if (type == "electrum") {
            return boost::make_shared<ga_rust>(net_params, defaults);
        }
#endif
        throw user_error("Unknown server_type");
    }

    session_impl::session_impl(const nlohmann::json& net_params, nlohmann::json& defaults)
        : m_net_params(get_network_overrides(net_params, defaults))
        , m_debug_logging(m_net_params.log_level() == "debug")
    {
        configure_logging(m_net_params);
    }

    session_impl::~session_impl() {}

    void session_impl::register_user(const std::string& /*master_pub_key_hex*/,
        const std::string& /*master_chain_code_hex*/, const std::string& /*gait_path_hex*/, bool /*supports_csv*/)
    {
        // Default impl is a no-op; registration is only meaningful in multisig
    }

    bool session_impl::set_blinding_nonce(
        const std::string& /*pubkey_hex*/, const std::string& /*script_hex*/, const std::string& /*nonce_hex*/)
    {
        return false; // No nonce caching by default, so return 'not updated'
    }

} // namespace sdk
} // namespace ga
