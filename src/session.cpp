#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "session.hpp"

#include "autobahn_wrapper.hpp"
#include "exception.hpp"
#ifdef BUILD_GDK_RUST
#include "ga_rust.hpp"
#endif
#include "ga_session.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "socks_client.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    namespace {

        static std::atomic_bool init_done{ false };
        static nlohmann::json global_config;

        void log_exception(const char* preamble, const std::exception& e)
        {
            try {
                const auto what = e.what();
                GDK_LOG_SEV(log_level::debug) << preamble << what;
            } catch (const std::exception&) {
            }
        }

    } // namespace

    int init(const nlohmann::json& config)
    {
        GDK_RUNTIME_ASSERT(config.is_object());
        GDK_RUNTIME_ASSERT(!init_done);

        global_config = config;

        GDK_VERIFY(wally_init(0));
        auto entropy = get_random_bytes<WALLY_SECP_RANDOMIZE_LEN>();
        GDK_VERIFY(wally_secp_randomize(entropy.data(), entropy.size()));
        wally_bzero(entropy.data(), entropy.size());

#if defined(__ANDROID__) and not defined(NDEBUG)
        start_android_std_outerr_bridge();
#endif
        init_done = true;

        return GA_OK;
    }

    const nlohmann::json& gdk_config() { return global_config; }

    template <typename F, typename... Args> auto session::exception_wrapper(F&& f, Args&&... args)
    {
        try {
            return f(std::forward<Args>(args)...);
        } catch (const autobahn::abort_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const login_error& e) {
            {
                session_ptr p = m_impl.load();
                if (p) {
                    p->on_failed_login();
                }
            }
            std::rethrow_exception(std::current_exception());
        } catch (const autobahn::network_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::no_transport_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::protocol_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::call_error& e) {
            std::pair<std::string, std::string> details;
            try {
                details = get_error_details(e);
                GDK_LOG_SEV(log_level::debug) << "server exception (" << details.first << "):" << details.second;
            } catch (const std::exception&) {
                log_exception("call error:", e);
            }
            if (details.first == "password") {
                // Server sends this response if the PIN is incorrect
                throw login_error(details.second);
            }
            std::rethrow_exception(std::current_exception());
        } catch (const assertion_error& e) {
            // Already logged by the assertion that failed
            std::rethrow_exception(std::current_exception());
        } catch (const user_error& e) {
            log_exception("user error:", e);
            std::rethrow_exception(std::current_exception());
        } catch (const reconnect_error& e) {
            std::rethrow_exception(std::current_exception());
        } catch (const timeout_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const websocketpp::exception& e) {
            reconnect();
            throw reconnect_error();
        } catch (const std::exception& e) {
            log_exception("uncaught exception:", e);
            std::rethrow_exception(std::current_exception());
        }
        __builtin_unreachable();
    }

    void session::connect(const nlohmann::json& net_params)
    {
        try {
            GDK_RUNTIME_ASSERT_MSG(init_done, "You must call GA_init first");

            auto impl = get_impl();
            GDK_RUNTIME_ASSERT_MSG(!impl, "session already connected");

            session_ptr session_p;
            const auto list = ga::sdk::network_parameters::get_all();
            const auto network_name = net_params.value("name", "");

            if (network_name == "") {
                GDK_LOG_SEV(log_level::error) << "network name not provided";
                throw new std::runtime_error("network name not provided");
            }

            auto network = list.at(network_name);

            if (network == nullptr) {
                GDK_LOG_SEV(log_level::error) << "network not found: " << network_name;
                throw new std::runtime_error("network not found");
            }

            // merge with net_params
            network.update(net_params.begin(), net_params.end());

            GDK_RUNTIME_ASSERT_MSG(network.contains("server_type"), "server_type field missing");
            if (network.value("server_type", "") == "green") {
                session_p = boost::make_shared<ga_session>(network);
#ifdef BUILD_GDK_RUST
            } else if (network.value("server_type", "") == "electrum") {
                GDK_RUNTIME_ASSERT(!gdk_config().at("datadir").empty());
                network["state_dir"] = std::string(gdk_config().at("datadir")) + "/state";
                session_p = boost::make_shared<ga_rust>(network);
#endif
            } else {
                GDK_RUNTIME_ASSERT_MSG(false, "server_type field unknown value");
            }

            GDK_RUNTIME_ASSERT(session_p != nullptr);
            boost::weak_ptr<session_common> weak_session = session_p;
            session_p->set_ping_fail_handler([weak_session] {
                if (auto p = weak_session.lock()) {
                    GDK_LOG_SEV(log_level::info) << "ping failure detected. reconnecting...";
                    p->try_reconnect();
                } else {
                    GDK_LOG_SEV(log_level::info) << "ping failure ignored on dead session";
                }
            });
            session_p->set_heartbeat_timeout_handler([weak_session](websocketpp::connection_hdl, const std::string&) {
                if (auto p = weak_session.lock()) {
                    GDK_LOG_SEV(log_level::info) << "pong timeout detected. reconnecting...";
                    p->try_reconnect();
                } else {
                    GDK_LOG_SEV(log_level::info) << "pong timeout ignored on dead session";
                }
            });
            session_p->set_notification_handler(m_notification_handler, m_notification_context);

            session_ptr empty;
            GDK_RUNTIME_ASSERT_MSG(m_impl.compare_exchange_strong(empty, session_p), "unable to allocate session");
            session_p->connect();
        } catch (const std::exception& ex) {
            log_exception("exception on connect:", ex);
            std::rethrow_exception(std::current_exception());
        }
    }

    session::session()
    {
        // Expanded for debugging purposes
    }

    session::~session()
    {
        // Expanded for debugging purposes
        disconnect();
    }

    void session::reconnect()
    {
        auto p = get_impl();
        if (!p) {
            GDK_LOG_SEV(log_level::info) << "null session context. backing off...";
            return;
        }

        p->try_reconnect();
    }

    void session::disconnect()
    {
        GDK_LOG_SEV(log_level::debug) << "session disconnect...";
        auto p = get_impl();
        while (p && !m_impl.compare_exchange_strong(p, session_ptr{})) {
        }
        if (p && p->get_network_parameters().is_electrum()) {
            GDK_LOG_SEV(log_level::debug) << "session is something and we are in electrum. Disconnect";
            p->disconnect();
        }
    }

    void session::reconnect_hint(const nlohmann::json& hint)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();

            // we have an hint for Tor
            if (hint.contains("tor_sleep_hint")) {
                p->tor_sleep_hint(hint["tor_sleep_hint"]);
            }

            // no connection-level hint, exit here
            if (!hint.contains("hint")) {
                return;
            }

            const std::string option = hint["hint"];
            GDK_RUNTIME_ASSERT(option == "now" || option == "disable" || option == "start");

            p->reconnect_hint(option != "disable", option == "now");
            reconnect();
        });
    }

    bool session::check_proxy_connectivity(const nlohmann::json& params)
    {
        boost::asio::io_context io;
        boost::beast::tcp_stream stream{ boost::asio::make_strand(io) };
        stream.expires_after(5s);

        const auto net_params = network_parameters{ network_parameters::get(params.at("name")) };
        const bool use_tor = params.value("use_tor", false);
        const auto server = net_params.get_connection_string(use_tor);
        const std::string proxy = params.at("proxy");

        GDK_LOG_SEV(log_level::info) << "attempting connection to " << server;

        auto client = std::make_shared<socks_client>(io, stream);
        GDK_RUNTIME_ASSERT(client != nullptr);

        auto result = client->run(server, proxy);
        io.run();

        try {
            result.get();
            client->shutdown();
            return true;
        } catch (const std::exception&) {
            throw;
        }

        __builtin_unreachable();
    }

    std::string session::get_tor_socks5()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_tor_socks5();
        });
    }

    nlohmann::json session::http_request(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->http_request(params);
        });
    }

    nlohmann::json session::refresh_assets(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->refresh_assets(params);
        });
    }

    nlohmann::json session::validate_asset_domain_name(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->validate_asset_domain_name(params);
        });
    }

    void session::register_user(const std::string& mnemonic, bool supports_csv)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->register_user(mnemonic, supports_csv);
        });
    }

    void session::register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
        const std::string& gait_path_hex, bool supports_csv)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
        });
    }

    std::string session::get_challenge(const std::string& address)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_challenge(address);
        });
    }

    nlohmann::json session::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->authenticate(sig_der_hex, path_hex, root_xpub_bip32, device_id, hw_device);
        });
    }

    void session::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->register_subaccount_xpubs(bip32_xpubs);
        });
    }

    nlohmann::json session::login(const std::string& mnemonic, const std::string& password)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->login(mnemonic, password);
        });
    }

    nlohmann::json session::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->login_with_pin(pin, pin_data);
        });
    }

    nlohmann::json session::login_watch_only(const std::string& username, const std::string& password)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->login_watch_only(username, password);
        });
    }

    bool session::set_watch_only(const std::string& username, const std::string& password)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_watch_only(username, password);
        });
    }

    std::string session::get_watch_only_username()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_watch_only_username();
        });
    }

    bool session::remove_account(const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->remove_account(twofactor_data);
        });
    }

    nlohmann::json session::create_subaccount(const nlohmann::json& details, uint32_t subaccount)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->create_subaccount(details, subaccount);
        });
    }

    nlohmann::json session::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->create_subaccount(details, subaccount, xpub);
        });
    }

    std::vector<uint32_t> session::get_subaccount_root_path(uint32_t subaccount)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_subaccount_root_path(subaccount);
        });
    }

    std::vector<uint32_t> session::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_subaccount_full_path(subaccount, pointer);
        });
    }

    uint32_t session::get_next_subaccount(const std::string& type)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_next_subaccount(type);
        });
    }

    nlohmann::json session::get_subaccounts()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_subaccounts();
        });
    }

    nlohmann::json session::get_subaccount(uint32_t subaccount)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_subaccount(subaccount);
        });
    }

    void session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->rename_subaccount(subaccount, new_name);
        });
    }

    void session::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_subaccount_hidden(subaccount, is_hidden);
        });
    }

    nlohmann::json session::get_settings()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_settings();
        });
    }

    nlohmann::json session::get_post_login_data()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_post_login_data();
        });
    }

    void session::change_settings(const nlohmann::json& settings)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->change_settings(settings);
        });
    }

    void session::change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->change_settings_limits(limit_details, twofactor_data);
        });
    }

    nlohmann::json session::get_transactions(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_transactions(details);
        });
    }

    void session::set_notification_handler(GA_notification_handler handler, void* context)
    {
        auto p = get_impl();
        GDK_RUNTIME_ASSERT(p == nullptr);
        m_notification_handler = handler;
        m_notification_context = context;
    }

    nlohmann::json session::get_receive_address(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_receive_address(details);
        });
    }

    nlohmann::json session::get_previous_addresses(uint32_t subaccount, uint32_t last_pointer)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_previous_addresses(subaccount, last_pointer);
        });
    }

    void session::set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_local_encryption_keys(public_key, is_hw_wallet);
        });
    }

    nlohmann::json session::get_balance(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_balance(details);
        });
    }

    nlohmann::json session::get_available_currencies()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_available_currencies();
        });
    }

    bool session::is_rbf_enabled()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->is_rbf_enabled();
        });
    }

    bool session::is_watch_only()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->is_watch_only();
        });
    }

    bool session::is_liquid()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_network_parameters().is_liquid();
        });
    }

    nlohmann::json session::get_twofactor_config(bool reset_cached)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_twofactor_config(reset_cached);
        });
    }

    std::vector<std::string> session::get_all_twofactor_methods()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_all_twofactor_methods();
        });
    }

    std::vector<std::string> session::get_enabled_twofactor_methods()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_enabled_twofactor_methods();
        });
    }

    void session::set_email(const std::string& email, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_email(email, twofactor_data);
        });
    }

    void session::activate_email(const std::string& code)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->activate_email(code);
        });
    }

    void session::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->init_enable_twofactor(method, data, twofactor_data);
        });
    }

    void session::enable_twofactor(const std::string& method, const std::string& code)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->enable_twofactor(method, code);
        });
    }

    void session::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->enable_gauth(code, twofactor_data);
        });
    }

    void session::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->disable_twofactor(method, twofactor_data);
        });
    }

    void session::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->auth_handler_request_code(method, action, twofactor_data);
        });
    }

    std::string session::auth_handler_request_proxy_code(
        const std::string& action, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->auth_handler_request_proxy_code(action, twofactor_data);
        });
    }

    nlohmann::json session::request_twofactor_reset(const std::string& email)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->request_twofactor_reset(email);
        });
    }

    nlohmann::json session::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->confirm_twofactor_reset(email, is_dispute, twofactor_data);
        });
    }

    nlohmann::json session::request_undo_twofactor_reset(const std::string& email)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->request_undo_twofactor_reset(email);
        });
    }

    nlohmann::json session::confirm_undo_twofactor_reset(const std::string& email, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->confirm_undo_twofactor_reset(email, twofactor_data);
        });
    }

    nlohmann::json session::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->cancel_twofactor_reset(twofactor_data);
        });
    }

    nlohmann::json session::set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_pin(mnemonic, pin, device_id);
        });
    }

    void session::disable_all_pin_logins()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->disable_all_pin_logins();
        });
    }

    nlohmann::json session::get_unspent_outputs(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_unspent_outputs(details);
        });
    }

    nlohmann::json session::get_blinded_scripts(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_blinded_scripts(details);
        });
    }

    bool session::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->has_blinding_nonce(pubkey, script);
        });
    }

    void session::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_blinding_nonce(pubkey, script, nonce);
        });
    }

    nlohmann::json session::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_unspent_outputs_for_private_key(private_key, password, unused);
        });
    }

    nlohmann::json session::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_unspent_outputs_status(details, twofactor_data);
        });
    }

    nlohmann::json session::create_transaction(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->create_transaction(details);
        });
    }

    nlohmann::json session::sign_transaction(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->sign_transaction(details);
        });
    }

    nlohmann::json session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->send_transaction(details, twofactor_data);
        });
    }

    std::string session::broadcast_transaction(const std::string& tx_hex)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->broadcast_transaction(tx_hex);
        });
    }

    void session::send_nlocktimes()
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->send_nlocktimes();
        });
    }

    nlohmann::json session::get_expired_deposits(const nlohmann::json& deposit_details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_expired_deposits(deposit_details);
        });
    }

    void session::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_csvtime(locktime_details, twofactor_data);
        });
    }

    void session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_nlocktime(locktime_details, twofactor_data);
        });
    }

    void session::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_transaction_memo(txhash_hex, memo);
        });
    }

    void session::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->upload_confidential_addresses(subaccount, confidential_addresses);
        });
    }

    nlohmann::json session::get_transaction_details(const std::string& txhash_hex)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_transaction_details(txhash_hex);
        });
    }

    std::string session::get_system_message()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_system_message();
        });
    }

    nlohmann::json session::get_fee_estimates()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_fee_estimates();
        });
    }

    std::string session::get_mnemonic_passphrase(const std::string& password)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_mnemonic_passphrase(password);
        });
    }

    std::pair<std::string, std::vector<uint32_t>> session::get_system_message_info(const std::string& system_message)
    {
        auto p = get_nonnull_impl();
        return p->get_system_message_info(system_message); // Note no exception wrapper
    }

    void session::ack_system_message(const std::string& system_message)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->ack_system_message(system_message);
        });
    }

    void session::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->ack_system_message(message_hash_hex, sig_der_hex);
        });
    }

    nlohmann::json session::convert_amount(const nlohmann::json& amount_json)
    {
        return exception_wrapper([&] {
            auto p = get_impl();
            if (p) {
                return p->convert_amount(amount_json);
            }
            // The session is not connected. Conversion to fiat will
            // be attempted using any provided fallback fiat values.
            return amount::convert(amount_json, std::string(), std::string());
        });
    }

    amount session::get_min_fee_rate() const
    {
        auto p = get_nonnull_impl();
        return p->get_min_fee_rate(); // Note no exception_wrapper
    }

    amount session::get_default_fee_rate() const
    {
        auto p = get_nonnull_impl();
        return p->get_default_fee_rate(); // Note no exception_wrapper
    }

    uint32_t session::get_block_height() const
    {
        auto p = get_nonnull_impl();
        return p->get_block_height(); // Note no exception_wrapper
    }

    amount session::get_dust_threshold() const
    {
        auto p = get_nonnull_impl();
        return p->get_dust_threshold(); // Note no exception_wrapper
    }

    nlohmann::json session::get_spending_limits() const
    {
        auto p = get_nonnull_impl();
        return p->get_spending_limits(); // Note no exception_wrapper
    }

    bool session::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        auto p = get_nonnull_impl();
        return p->is_spending_limits_decrease(limit_details); // Note no exception_wrapper
    }

    const network_parameters& session::get_network_parameters() const
    {
        auto p = get_nonnull_impl();
        return p->get_network_parameters(); // Note no exception_wrapper
    }

} // namespace sdk
} // namespace ga
