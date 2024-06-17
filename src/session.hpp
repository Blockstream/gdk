#ifndef GDK_SESSION_HPP
#define GDK_SESSION_HPP
#pragma once

#include <memory>
#include <mutex>
#include <nlohmann/json_fwd.hpp>

#include "gdk.h"

#include "ga_wally.hpp"

namespace green {

    class network_parameters;
    class session_impl;
    struct tor_controller;

    int gdk_init(nlohmann::json config);
    const nlohmann::json& gdk_config();
    void gdk_set_tor_controller(std::shared_ptr<struct tor_controller> controller);
    int gdk_shutdown();

    class session {
    public:
        using impl_ptr = std::shared_ptr<session_impl>;

        session();
        ~session();

        session(const session&) = delete;
        session(session&&) = delete;

        session& operator=(const session&) = delete;
        session& operator=(session&&) = delete;

        void connect(const nlohmann::json& net_params);
        void reconnect_hint(const nlohmann::json& hint);

        nlohmann::json get_proxy_settings();

        nlohmann::json http_request(const nlohmann::json& params);
        void refresh_assets(const nlohmann::json& params);
        nlohmann::json get_assets(const nlohmann::json& params);
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        std::string get_watch_only_username();

        void set_notification_handler(GA_notification_handler handler, void* context);

        nlohmann::json get_available_currencies();

        nlohmann::json get_settings();
        nlohmann::json get_twofactor_config(bool reset_cached = false);

        nlohmann::json encrypt_with_pin(const nlohmann::json& details);
        nlohmann::json decrypt_with_pin(const nlohmann::json& details);
        void disable_all_pin_logins();

        nlohmann::json get_transaction_details(const std::string& txhash_hex);

        std::string broadcast_transaction(const std::string& tx_hex);

        void send_nlocktimes();

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo);

        nlohmann::json get_fee_estimates();

        std::string get_system_message();

        nlohmann::json convert_amount(const nlohmann::json& amount_json);

        const network_parameters& get_network_parameters() const;

        impl_ptr get_nonnull_impl() const;

        void exception_handler(std::exception_ptr ex_p);

    private:
        using locker_t = std::unique_lock<std::mutex>;

        template <typename F, typename... Args> auto exception_wrapper(F&& f, Args&&... args);

        void signal_reconnect_and_throw();

        impl_ptr get_impl() const;

        mutable std::mutex m_mutex;
        impl_ptr m_impl;

        GA_notification_handler m_notification_handler;
        void* m_notification_context;
    };

} // namespace green

#endif
