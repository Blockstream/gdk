#include <boost/thread/tss.hpp>
#include <initializer_list>
#include <type_traits>

#include "amount.hpp"
#include "assertion.hpp"
#include "autobahn_wrapper.hpp"
#include "bcur_auth_handlers.hpp"
#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "gdk.h"
#include "json_utils.hpp"
#include "network_parameters.hpp"
#include "redeposit_auth_handlers.hpp"
#include "session.hpp"
#include "swap_auth_handlers.hpp"
#include "utils.hpp"
#include "validate.hpp"

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif

namespace {

    static boost::thread_specific_ptr<nlohmann::json> g_thread_error;

    static void set_thread_error(const char* what)
    {
        g_thread_error.reset(new nlohmann::json({ { "details", what } }));
    }

    template <typename Arg>
    static typename std::enable_if_t<!std::is_pointer<Arg>::value> assert_pointer_arg(
        const char* /*func*/, const Arg& /*arg*/)
    {
    }

    template <typename Arg>
    static typename std::enable_if_t<std::is_pointer<Arg>::value> assert_pointer_arg(const char* func, const Arg& arg)
    {
        if (!arg) {
            GDK_RUNTIME_ASSERT_MSG(false, std::string("null argument calling ") + func);
        }
    }

    template <typename... Args> static void assert_invoke_args(const char* func, Args&&... args)
    {
        (void)std::initializer_list<int>{ (assert_pointer_arg(func, std::forward<Args>(args)), 0)... };
    }

    template <typename F, typename... Args> static auto c_invoke(const char* func, F&& f, Args&&... args)
    {
        try {
            g_thread_error.reset();
            assert_invoke_args(func, std::forward<Args>(args)...);
            f(std::forward<Args>(args)...);
            g_thread_error.reset();
            return GA_OK;
        } catch (const green::login_error& e) {
            set_thread_error(e.what());
            return GA_NOT_AUTHORIZED;
        } catch (const autobahn::no_session_error& e) {
            set_thread_error(e.what());
            return GA_SESSION_LOST;
        } catch (const green::reconnect_error& e) {
            set_thread_error(e.what());
            return GA_RECONNECT;
        } catch (const green::timeout_error& e) {
            set_thread_error(e.what());
            return GA_TIMEOUT;
        } catch (const std::exception& e) {
            set_thread_error(e.what());
            return GA_ERROR;
        }
        __builtin_unreachable();
    }

    static char* to_c_string(const std::string& s)
    {
        char* str = static_cast<char*>(malloc(s.size() + 1));
        std::copy(s.begin(), s.end(), str);
        *(str + s.size()) = 0;
        return str;
    }

    static nlohmann::json* json_cast(GA_json* json) { return reinterpret_cast<nlohmann::json*>(json); }

    static const nlohmann::json* json_cast(const GA_json* json)
    {
        return reinterpret_cast<const nlohmann::json*>(json);
    }

    static nlohmann::json** json_cast(GA_json** json) { return reinterpret_cast<nlohmann::json**>(json); }

    static nlohmann::json&& json_move(GA_json* json) { return std::move(*json_cast(json)); }

    static struct GA_auth_handler* auth_cast(green::auth_handler* call)
    {
        return reinterpret_cast<struct GA_auth_handler*>(call);
    }

    static green::auth_handler* auth_cast(struct GA_auth_handler* call)
    {
        return reinterpret_cast<struct green::auth_handler*>(call);
    }

    // Returns the passed call handler wrapped in an auto_auth_handler
    static struct GA_auth_handler* make_call(green::auth_handler* call_impl)
    {
        std::unique_ptr<green::auth_handler> tmp(call_impl);
        std::unique_ptr<green::auto_auth_handler> wrapped(new green::auto_auth_handler(tmp.get()));
        tmp.release();
        wrapped->advance();
        return auth_cast(wrapped.release());
    }

    struct call_timer {
#if 0
    call_timer(const char* func)
        : m_func(func)
    {
        GDK_LOG(info) << "CALL: " << m_func;
    }
    ~call_timer() { GDK_LOG(info) << "RETN: " << m_func; }
    const char* m_func;
#else
        call_timer(const char* /*func*/) {}
#endif
    };

} // namespace

struct GA_session final : public green::session {
};

#define GDK_DEFINE_C_FUNCTION_1(NAME, T1, A1, BODY)                                                                    \
    int NAME(T1 A1)                                                                                                    \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1) { BODY }, A1);                                                                            \
    }

#define GDK_DEFINE_C_FUNCTION_2(NAME, T1, A1, T2, A2, BODY)                                                            \
    int NAME(T1 A1, T2 A2)                                                                                             \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2) { BODY }, A1, A2);                                                                 \
    }

#define GDK_DEFINE_C_FUNCTION_3(NAME, T1, A1, T2, A2, T3, A3, BODY)                                                    \
    int NAME(T1 A1, T2 A2, T3 A3)                                                                                      \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3) { BODY }, A1, A2, A3);                                                      \
    }

#define GDK_DEFINE_C_FUNCTION_4(NAME, T1, A1, T2, A2, T3, A3, T4, A4, BODY)                                            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4)                                                                               \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4) { BODY }, A1, A2, A3, A4);                                           \
    }

#define GDK_DEFINE_C_FUNCTION_5(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, BODY)                                    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5)                                                                        \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5) { BODY }, A1, A2, A3, A4, A5);                                \
    }

#define GDK_DEFINE_C_FUNCTION_6(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, BODY)                            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6)                                                                 \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6) { BODY }, A1, A2, A3, A4, A5, A6);                     \
    }

#define GDK_DEFINE_C_FUNCTION_7(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, BODY)                    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7)                                                          \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7) { BODY }, A1, A2, A3, A4, A5, A6, A7);          \
    }

#define GDK_DEFINE_C_FUNCTION_8(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, BODY)            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8)                                                   \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8) { BODY }, A1, A2, A3, A4, A5, A6, A7,    \
            A8);                                                                                                       \
    }

#define GDK_DEFINE_C_FUNCTION_9(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, T9, A9, BODY)    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9)                                            \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9) { BODY }, A1, A2, A3, A4, A5, A6, \
            A7, A8, A9);                                                                                               \
    }

#define GDK_DEFINE_C_FUNCTION_10(                                                                                      \
    NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, T9, A9, T10, A10, BODY)                      \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9, T10 A10)                                   \
    {                                                                                                                  \
        call_timer ct(#NAME);                                                                                          \
        return c_invoke(                                                                                               \
            #NAME, [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9, T10 A10) { BODY }, A1, A2, A3,    \
            A4, A5, A6, A7, A8, A9, A10);                                                                              \
    }

int GA_init(const GA_json* config)
{
    try {
        GDK_RUNTIME_ASSERT(config);
        return green::gdk_init(*json_cast(config));
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

int GA_shutdown()
{
    try {
        return green::gdk_shutdown();
    } catch (const std::exception& e) {
        using namespace green;
        GDK_LOG(warning) << "GA_shutdown: " << e.what();
    }
    return GA_OK;
}

int GA_get_thread_error_details(GA_json** output)
{
    try {
        GDK_RUNTIME_ASSERT(output);
        nlohmann::json* p = g_thread_error.get();
        *json_cast(output) = p ? new nlohmann::json(*p) : new nlohmann::json();
        return GA_OK;
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

int GA_create_session(struct GA_session** session)
{
    call_timer ct("GA_create_session");
    try {
        GDK_RUNTIME_ASSERT(session);
        *session = new GA_session();
        return GA_OK;
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

int GA_destroy_session(struct GA_session* session)
{
    call_timer ct("GA_destroy_session");
    delete session;
    return GA_OK;
}

int GA_destroy_json(GA_json* json)
{
    delete json_cast(json);
    return GA_OK;
}

GDK_DEFINE_C_FUNCTION_2(
    GA_connect, struct GA_session*, session, const GA_json*, net_params, { session->connect(*json_cast(net_params)); })

GDK_DEFINE_C_FUNCTION_2(GA_reconnect_hint, struct GA_session*, session, const GA_json*, hint,
    { session->reconnect_hint(*json_cast(hint)); })

GDK_DEFINE_C_FUNCTION_2(GA_get_proxy_settings, struct GA_session*, session, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(session->get_proxy_settings()); })

GDK_DEFINE_C_FUNCTION_3(
    GA_get_wallet_identifier, const GA_json*, net_params, const GA_json*, params, GA_json**, output, {
        *json_cast(output) = new nlohmann::json(green::get_wallet_hash_ids(*json_cast(net_params), *json_cast(params)));
    })

GDK_DEFINE_C_FUNCTION_3(GA_cache_control, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::cache_control_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_http_request, struct GA_session*, session, const GA_json*, params, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(session->http_request(*json_cast(params))); })

GDK_DEFINE_C_FUNCTION_2(GA_refresh_assets, struct GA_session*, session, const GA_json*, params,
    { session->refresh_assets(*json_cast(params)); })

GDK_DEFINE_C_FUNCTION_3(GA_get_assets, struct GA_session*, session, const GA_json*, params, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(session->get_assets(*json_cast(params))); })

GDK_DEFINE_C_FUNCTION_3(GA_validate_asset_domain_name, struct GA_session*, session, const GA_json*, params, GA_json**,
    output, { *json_cast(output) = new nlohmann::json(session->validate_asset_domain_name(*json_cast(params))); })

GDK_DEFINE_C_FUNCTION_3(GA_validate, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::validate_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_4(GA_register_user, struct GA_session*, session, GA_json*, hw_device, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::register_call(*session, json_move(hw_device), json_move(details))); })

GDK_DEFINE_C_FUNCTION_4(GA_login_user, struct GA_session*, session, GA_json*, hw_device, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::login_user_call(*session, json_move(hw_device), json_move(details))); })

GDK_DEFINE_C_FUNCTION_2(GA_get_watch_only_username, struct GA_session*, session, char**, username,
    { *username = to_c_string(session->get_watch_only_username()); })

GDK_DEFINE_C_FUNCTION_2(GA_get_fee_estimates, struct GA_session*, session, GA_json**, estimates,
    { *json_cast(estimates) = new nlohmann::json(session->get_fee_estimates()); })

GDK_DEFINE_C_FUNCTION_3(GA_get_credentials, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::get_credentials_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_2(GA_get_system_message, struct GA_session*, session, char**, message_text,
    { *message_text = to_c_string(session->get_system_message()); })

GDK_DEFINE_C_FUNCTION_3(GA_ack_system_message, struct GA_session*, session, const char*, message_text,
    struct GA_auth_handler**, call, { *call = make_call(new green::ack_system_message_call(*session, message_text)); })

GDK_DEFINE_C_FUNCTION_2(GA_get_twofactor_config, struct GA_session*, session, GA_json**, config,
    { *json_cast(config) = new nlohmann::json(session->get_twofactor_config()); })

GDK_DEFINE_C_FUNCTION_3(GA_create_transaction, struct GA_session*, session, GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::create_transaction_call(*session, json_move(transaction_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_blind_transaction, struct GA_session*, session, GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::blind_transaction_call(*session, json_move(transaction_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_sign_transaction, struct GA_session*, session, GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::sign_transaction_call(*session, json_move(transaction_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_create_swap_transaction, struct GA_session*, session, const GA_json*, swap_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::create_swap_transaction_call(*session, *json_cast(swap_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_complete_swap_transaction, struct GA_session*, session, const GA_json*, swap_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::complete_swap_transaction_call(*session, *json_cast(swap_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_create_redeposit_transaction, struct GA_session*, session, const GA_json*, redeposit_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::create_redeposit_transaction_call(*session, *json_cast(redeposit_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_psbt_sign, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::psbt_sign_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_psbt_from_json, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::psbt_from_json_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_psbt_get_details, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::psbt_get_details_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_1(GA_send_nlocktimes, struct GA_session*, session, { session->send_nlocktimes(); })

GDK_DEFINE_C_FUNCTION_3(
    GA_set_csvtime, struct GA_session*, session, GA_json*, locktime_details, struct GA_auth_handler**, call, {
        constexpr bool is_csv = true;
        *call = make_call(new green::locktime_call(*session, json_move(locktime_details), is_csv));
    })

GDK_DEFINE_C_FUNCTION_3(
    GA_set_nlocktime, struct GA_session*, session, const GA_json*, locktime_details, struct GA_auth_handler**, call, {
        constexpr bool is_csv = false;
        *call = make_call(new green::locktime_call(*session, *json_cast(locktime_details), is_csv));
    })

GDK_DEFINE_C_FUNCTION_4(GA_set_transaction_memo, struct GA_session*, session, const char*, txhash_hex, const char*,
    memo, uint32_t, memo_type, {
        GDK_RUNTIME_ASSERT(memo_type == 0);
        session->set_transaction_memo(txhash_hex, memo);
    })

int GA_set_notification_handler(struct GA_session* session, GA_notification_handler handler, void* context)
{
    try {
        GDK_RUNTIME_ASSERT_MSG(session, "null argument calling GA_set_notification_handler");
        session->set_notification_handler(handler, context);
    } catch (const std::exception& e) {
        set_thread_error(e.what());
        return GA_ERROR;
    }
    g_thread_error.reset();
    return GA_OK;
}

GDK_DEFINE_C_FUNCTION_2(GA_remove_account, struct GA_session*, session, struct GA_auth_handler**, call,
    { *call = make_call(new green::remove_account_call(*session)); })

GDK_DEFINE_C_FUNCTION_3(GA_create_subaccount, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::create_subaccount_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_subaccounts, struct GA_session*, session, const GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::get_subaccounts_call(*session, *json_cast(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_subaccount, struct GA_session*, session, uint32_t, subaccount, struct GA_auth_handler**,
    call, { *call = make_call(new green::get_subaccount_call(*session, subaccount)); })

GDK_DEFINE_C_FUNCTION_3(GA_update_subaccount, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::update_subaccount_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_transactions, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::get_transactions_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_receive_address, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::get_receive_address_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_previous_addresses, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::get_previous_addresses_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_balance, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::get_balance_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_unspent_outputs, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::get_unspent_outputs_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_unspent_outputs_for_private_key, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::get_unspent_outputs_for_private_key_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_set_unspent_outputs_status, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::set_unspent_outputs_status_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_get_transaction_details, struct GA_session*, session, const char*, txhash_hex, GA_json**,
    transaction, { *json_cast(transaction) = new nlohmann::json(session->get_transaction_details(txhash_hex)); })

GDK_DEFINE_C_FUNCTION_2(GA_get_available_currencies, struct GA_session*, session, GA_json**, currencies,
    { *json_cast(currencies) = new nlohmann::json(session->get_available_currencies()); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_amount, struct GA_session*, session, const GA_json*, value_details, GA_json**,
    output, { *json_cast(output) = new nlohmann::json(session->convert_amount(*json_cast(value_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_encrypt_with_pin, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::encrypt_with_pin_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_decrypt_with_pin, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::decrypt_with_pin_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_1(GA_disable_all_pin_logins, struct GA_session*, session, { session->disable_all_pin_logins(); })

GDK_DEFINE_C_FUNCTION_3(GA_rsa_verify, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::rsa_verify(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_2(GA_convert_string_to_json, const char*, input, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(green::json_parse(input)); })

GDK_DEFINE_C_FUNCTION_2(GA_convert_json_to_string, const GA_json*, json, char**, output,
    { *output = to_c_string(json_cast(json)->dump()); })

GDK_DEFINE_C_FUNCTION_2(GA_register_network, const char*, name, const GA_json*, network_details,
    { green::network_parameters::add(name, *json_cast(network_details)); })

GDK_DEFINE_C_FUNCTION_1(GA_get_networks, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(green::network_parameters::get_all()); })

GDK_DEFINE_C_FUNCTION_2(GA_get_uniform_uint32_t, uint32_t, upper_bound, uint32_t*, output,
    { *output = green::get_uniform_uint32_t(upper_bound); })

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_request_code, struct GA_auth_handler*, call, const char*, method,
    { auth_cast(call)->request_code(method); })

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_resolve_code, struct GA_auth_handler*, call, const char*, code,
    { auth_cast(call)->resolve_code(code); })

GDK_DEFINE_C_FUNCTION_1(GA_auth_handler_call, struct GA_auth_handler*, call, { auth_cast(call)->operator()(); })

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_get_status, struct GA_auth_handler*, call, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(auth_cast(call)->get_status()); })

GDK_DEFINE_C_FUNCTION_1(GA_destroy_auth_handler, struct GA_auth_handler*, call, { delete auth_cast(call); })

GDK_DEFINE_C_FUNCTION_2(GA_get_settings, struct GA_session*, session, struct GA_json**, settings,
    { *json_cast(settings) = new nlohmann::json(session->get_settings()); })

GDK_DEFINE_C_FUNCTION_3(GA_change_settings, struct GA_session*, session, GA_json*, settings, struct GA_auth_handler**,
    call, { *call = make_call(new green::change_settings_call(*session, json_move(settings))); })

GDK_DEFINE_C_FUNCTION_4(GA_change_settings_twofactor, struct GA_session*, session, const char*, method, GA_json*,
    twofactor_details, struct GA_auth_handler**, call,
    { *call = make_call(new green::change_settings_twofactor_call(*session, method, json_move(twofactor_details))); })

GDK_DEFINE_C_FUNCTION_4(GA_twofactor_reset, struct GA_session*, session, const char*, email, uint32_t, is_dispute,
    struct GA_auth_handler**, call, {
        constexpr bool is_undo = false;
        *call = make_call(new green::twofactor_reset_call(*session, email, is_dispute != GA_FALSE, is_undo));
    })

GDK_DEFINE_C_FUNCTION_3(
    GA_twofactor_undo_reset, struct GA_session*, session, const char*, email, struct GA_auth_handler**, call, {
        constexpr bool is_dispute = false; // Irrelevant for undo
        constexpr bool is_undo = true;
        *call = make_call(new green::twofactor_reset_call(*session, email, is_dispute, is_undo));
    })

GDK_DEFINE_C_FUNCTION_2(GA_twofactor_cancel_reset, struct GA_session*, session, struct GA_auth_handler**, call,
    { *call = make_call(new green::twofactor_cancel_reset_call(*session)); })

GDK_DEFINE_C_FUNCTION_3(GA_broadcast_transaction, struct GA_session*, session, GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::broadcast_transaction_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_send_transaction, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**,
    call, { *call = make_call(new green::send_transaction_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_sign_message, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::sign_message_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_twofactor_change_limits, struct GA_session*, session, GA_json*, limit_details,
    struct GA_auth_handler**, call,
    { *call = make_call(new green::change_limits_call(*session, json_move(limit_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_bcur_encode, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::bcur_encoder_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_bcur_decode, struct GA_session*, session, GA_json*, details, struct GA_auth_handler**, call,
    { *call = make_call(new green::bcur_decoder_call(*session, json_move(details))); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_bool, const GA_json*, json, const char*, path, uint32_t*, output, {
    *output = GA_FALSE;
    const bool v = ::green::j_bool_or_false(*json_cast(json), path);
    *output = v ? GA_TRUE : GA_FALSE;
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_string, const GA_json*, json, const char*, path, char**, output, {
    *output = nullptr;
    const auto v = ::green::j_str_or_empty(*json_cast(json), path);
    *output = to_c_string(v);
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_uint32, const GA_json*, json, const char*, path, uint32_t*, output, {
    *output = 0;
    *output = ::green::j_uint32_or_zero(*json_cast(json), path);
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_uint64, const GA_json*, json, const char*, path, uint64_t*, output, {
    *output = 0;
    *output = ::green::j_amount_or_zero(*json_cast(json), path).value();
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_json, const GA_json*, json, const char*, path, GA_json**, output, {
    *output = nullptr;
    const auto& v = json_cast(json)->at(path);
    *json_cast(output) = new nlohmann::json(v);
})

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
