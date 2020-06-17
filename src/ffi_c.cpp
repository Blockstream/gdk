#include <initializer_list>
#include <type_traits>

#include "amount.hpp"
#include "assertion.hpp"
#include "exception.hpp"
#include "ga_auth_handlers.hpp"
#include "include/gdk.h"
#include "network_parameters.hpp"
#include "session.hpp"
#include "utils.hpp"

namespace {

template <typename Arg>
static typename std::enable_if_t<!std::is_pointer<Arg>::value> assert_pointer_args(
    const Arg& arg __attribute__((unused)))
{
}

template <typename Arg>
static typename std::enable_if_t<std::is_pointer<Arg>::value> assert_pointer_args(const Arg& arg)
{
    GDK_RUNTIME_ASSERT(arg);
}

template <typename... Args> static void assert_invoke_args(Args&&... args)
{
    (void)std::initializer_list<int>{ (assert_pointer_args(std::forward<Args>(args)), 0)... };
}

template <typename F, typename... Args> static auto c_invoke(F&& f, Args&&... args)
{
    try {
        assert_invoke_args(std::forward<Args>(args)...);
        f(std::forward<Args>(args)...);
        return GA_OK;
    } catch (const ga::sdk::login_error& e) {
        return GA_NOT_AUTHORIZED;
    } catch (const autobahn::no_session_error& e) {
        return GA_SESSION_LOST;
    } catch (const ga::sdk::reconnect_error& e) {
        return GA_RECONNECT;
    } catch (const ga::sdk::timeout_error& e) {
        return GA_TIMEOUT;
    } catch (const std::exception& e) {
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

static const nlohmann::json* json_cast(const GA_json* json) { return reinterpret_cast<const nlohmann::json*>(json); }

static nlohmann::json** json_cast(GA_json** json) { return reinterpret_cast<nlohmann::json**>(json); }

template <typename T> static void json_convert(const nlohmann::json& json, const char* path, T* value)
{
    GDK_RUNTIME_ASSERT(path);
    GDK_RUNTIME_ASSERT(value);
    const auto v = json[path];
    if (v.is_null()) {
        *value = T();
    } else {
        *value = v;
    }
}

static struct GA_auth_handler* auth_cast(ga::sdk::auth_handler* call)
{
    return reinterpret_cast<struct GA_auth_handler*>(call);
}

static ga::sdk::auth_handler* auth_cast(struct GA_auth_handler* call)
{
    return reinterpret_cast<struct ga::sdk::auth_handler*>(call);
}

} // namespace

struct GA_session final : public ga::sdk::session {
};

#define GDK_DEFINE_C_FUNCTION_1(NAME, T1, A1, BODY)                                                                    \
    int NAME(T1 A1) { return c_invoke([](T1 A1) BODY, A1); }

#define GDK_DEFINE_C_FUNCTION_2(NAME, T1, A1, T2, A2, BODY)                                                            \
    int NAME(T1 A1, T2 A2) { return c_invoke([](T1 A1, T2 A2) BODY, A1, A2); }

#define GDK_DEFINE_C_FUNCTION_3(NAME, T1, A1, T2, A2, T3, A3, BODY)                                                    \
    int NAME(T1 A1, T2 A2, T3 A3) { return c_invoke([](T1 A1, T2 A2, T3 A3) BODY, A1, A2, A3); }

#define GDK_DEFINE_C_FUNCTION_4(NAME, T1, A1, T2, A2, T3, A3, T4, A4, BODY)                                            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4) { return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4) BODY, A1, A2, A3, A4); }

#define GDK_DEFINE_C_FUNCTION_5(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, BODY)                                    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5)                                                                        \
    {                                                                                                                  \
        return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5) BODY, A1, A2, A3, A4, A5);                               \
    }

#define GDK_DEFINE_C_FUNCTION_6(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, BODY)                            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6)                                                                 \
    {                                                                                                                  \
        return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6) BODY, A1, A2, A3, A4, A5, A6);                    \
    }

#define GDK_DEFINE_C_FUNCTION_7(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, BODY)                    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7)                                                          \
    {                                                                                                                  \
        return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7) BODY, A1, A2, A3, A4, A5, A6, A7);         \
    }

#define GDK_DEFINE_C_FUNCTION_8(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, BODY)            \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8)                                                   \
    {                                                                                                                  \
        return c_invoke(                                                                                               \
            [](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8) BODY, A1, A2, A3, A4, A5, A6, A7, A8);          \
    }

#define GDK_DEFINE_C_FUNCTION_9(NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, T9, A9, BODY)    \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9)                                            \
    {                                                                                                                  \
        return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9) BODY, A1, A2, A3, A4, A5,    \
            A6, A7, A8, A9);                                                                                           \
    }

#define GDK_DEFINE_C_FUNCTION_10(                                                                                      \
    NAME, T1, A1, T2, A2, T3, A3, T4, A4, T5, A5, T6, A6, T7, A7, T8, A8, T9, A9, T10, A10, BODY)                      \
    int NAME(T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9, T10 A10)                                   \
    {                                                                                                                  \
        return c_invoke([](T1 A1, T2 A2, T3 A3, T4 A4, T5 A5, T6 A6, T7 A7, T8 A8, T9 A9, T10 A10) BODY, A1, A2, A3,   \
            A4, A5, A6, A7, A8, A9, A10);                                                                              \
    }

int GA_init(const GA_json* config)
{
    try {
        GDK_RUNTIME_ASSERT(config);
        return ga::sdk::init(*json_cast(config));
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

int GA_create_session(struct GA_session** session)
{
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
    delete session;
    return GA_OK;
}

int GA_destroy_json(GA_json* json)
{
    delete json_cast(json);
    return GA_OK;
}

GDK_DEFINE_C_FUNCTION_2(
    GA_connect, struct GA_session*, session, const GA_json*, net_params, { session->connect(*json_cast(net_params)); });

GDK_DEFINE_C_FUNCTION_1(GA_disconnect, struct GA_session*, session, { session->disconnect(); })

GDK_DEFINE_C_FUNCTION_2(GA_reconnect_hint, struct GA_session*, session, const GA_json*, hint,
    { session->reconnect_hint(*json_cast(hint)); });

GDK_DEFINE_C_FUNCTION_1(GA_check_proxy_connectivity, const GA_json*, params,
    { ga::sdk::session::check_proxy_connectivity(*json_cast(params)); });

GDK_DEFINE_C_FUNCTION_2(GA_get_tor_socks5, struct GA_session*, session, char**, socks5,
    { *socks5 = to_c_string(session->get_tor_socks5()); })

GDK_DEFINE_C_FUNCTION_3(GA_http_request, struct GA_session*, session, const GA_json*, params, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(session->http_request(*json_cast((params)))); });

GDK_DEFINE_C_FUNCTION_3(GA_refresh_assets, struct GA_session*, session, const GA_json*, params, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(session->refresh_assets(*json_cast(params))); });

GDK_DEFINE_C_FUNCTION_3(GA_validate_asset_domain_name, struct GA_session*, session, const GA_json*, params, GA_json**,
    output, { *json_cast(output) = new nlohmann::json(session->validate_asset_domain_name(*json_cast((params)))); });

GDK_DEFINE_C_FUNCTION_4(GA_register_user, struct GA_session*, session, const GA_json*, hw_device, const char*, mnemonic,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::register_call(*session, *json_cast(hw_device), mnemonic)); })

GDK_DEFINE_C_FUNCTION_5(GA_login, struct GA_session*, session, const GA_json*, hw_device, const char*, mnemonic,
    const char*, password, struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::login_call(*session, *json_cast(hw_device), mnemonic, password)); })

GDK_DEFINE_C_FUNCTION_4(GA_login_with_pin, struct GA_session*, session, const char*, pin, const GA_json*, pin_data,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::login_with_pin_call(*session, pin, *json_cast(pin_data))); })

GDK_DEFINE_C_FUNCTION_3(GA_login_watch_only, struct GA_session*, session, const char*, username, const char*, password,
    { session->login_watch_only(username, password); })

GDK_DEFINE_C_FUNCTION_3(GA_set_watch_only, struct GA_session*, session, const char*, username, const char*, password,
    { session->set_watch_only(username, password); })

GDK_DEFINE_C_FUNCTION_2(GA_get_watch_only_username, struct GA_session*, session, char**, username,
    { *username = to_c_string(session->get_watch_only_username()); })

GDK_DEFINE_C_FUNCTION_2(GA_get_fee_estimates, struct GA_session*, session, GA_json**, estimates,
    { *json_cast(estimates) = new nlohmann::json(session->get_fee_estimates()); })

GDK_DEFINE_C_FUNCTION_3(GA_get_mnemonic_passphrase, struct GA_session*, session, const char*, password, char**,
    mnemonic, { *mnemonic = to_c_string(session->get_mnemonic_passphrase(password ? password : std::string())); })

GDK_DEFINE_C_FUNCTION_2(GA_get_system_message, struct GA_session*, session, char**, message_text,
    { *message_text = to_c_string(session->get_system_message()); })

GDK_DEFINE_C_FUNCTION_3(GA_ack_system_message, struct GA_session*, session, const char*, message_text,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::ack_system_message_call(*session, message_text)); });

GDK_DEFINE_C_FUNCTION_2(GA_get_twofactor_config, struct GA_session*, session, GA_json**, config,
    { *json_cast(config) = new nlohmann::json(session->get_twofactor_config()); })

GDK_DEFINE_C_FUNCTION_3(GA_create_transaction, struct GA_session*, session, const GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::create_transaction_call(*session, *json_cast(transaction_details))); });

GDK_DEFINE_C_FUNCTION_3(GA_sign_transaction, struct GA_session*, session, const GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::sign_transaction_call(*session, *json_cast(transaction_details))); });

GDK_DEFINE_C_FUNCTION_1(GA_send_nlocktimes, struct GA_session*, session, { session->send_nlocktimes(); })

GDK_DEFINE_C_FUNCTION_3(GA_get_expired_deposits, struct GA_session*, session, const GA_json*, deposit_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::get_expired_deposits_call(*session, *json_cast(deposit_details))); });

GDK_DEFINE_C_FUNCTION_3(GA_set_csvtime, struct GA_session*, session, const GA_json*, locktime_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::csv_time_call(*session, *json_cast(locktime_details))); });

GDK_DEFINE_C_FUNCTION_3(GA_set_nlocktime, struct GA_session*, session, const GA_json*, locktime_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::nlocktime_call(*session, *json_cast(locktime_details))); });

GDK_DEFINE_C_FUNCTION_4(GA_set_transaction_memo, struct GA_session*, session, const char*, txhash_hex, const char*,
    memo, uint32_t, memo_type, {
        GDK_RUNTIME_ASSERT(memo_type == GA_MEMO_USER || memo_type == GA_MEMO_BIP70);
        const std::string memo_type_str = memo_type == GA_MEMO_USER ? "user" : "payreq";
        session->set_transaction_memo(txhash_hex, memo, memo_type_str);
    })

GDK_DEFINE_C_FUNCTION_3(
    GA_set_notification_handler, struct GA_session*, session, GA_notification_handler, handler, void*, context, {
        GDK_RUNTIME_ASSERT(handler);
        session->set_notification_handler(handler, context);
    })

GDK_DEFINE_C_FUNCTION_2(GA_remove_account, struct GA_session*, session, struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::remove_account_call(*session)); });

GDK_DEFINE_C_FUNCTION_3(GA_create_subaccount, struct GA_session*, session, const GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::create_subaccount_call(*session, *json_cast(details))); })

GDK_DEFINE_C_FUNCTION_2(GA_get_subaccounts, struct GA_session*, session, struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::get_subaccounts_call(*session)); });

GDK_DEFINE_C_FUNCTION_3(GA_get_subaccount, struct GA_session*, session, uint32_t, subaccount, struct GA_auth_handler**,
    call, { *call = auth_cast(new ga::sdk::get_subaccount_call(*session, subaccount)); });

GDK_DEFINE_C_FUNCTION_3(GA_rename_subaccount, struct GA_session*, session, uint32_t, subaccount, const char*, new_name,
    { session->rename_subaccount(subaccount, new_name); })

GDK_DEFINE_C_FUNCTION_3(GA_get_transactions, struct GA_session*, session, const GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::get_transactions_call(*session, *json_cast(details))); });

GDK_DEFINE_C_FUNCTION_3(GA_get_receive_address, struct GA_session*, session, const GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::get_receive_address_call(*session, *json_cast(details))); });

GDK_DEFINE_C_FUNCTION_3(GA_get_balance, struct GA_session*, session, const GA_json*, details, struct GA_auth_handler**,
    call, { *call = auth_cast(new ga::sdk::get_balance_call(*session, *json_cast(details))); });

GDK_DEFINE_C_FUNCTION_3(GA_get_unspent_outputs, struct GA_session*, session, const GA_json*, details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::get_unspent_outputs_call(*session, *json_cast(details))); });

GDK_DEFINE_C_FUNCTION_5(GA_get_unspent_outputs_for_private_key, struct GA_session*, session, const char*, private_key,
    const char*, password, uint32_t, unused, GA_json**, utxos, {
        *json_cast(utxos)
            = new nlohmann::json(session->get_unspent_outputs_for_private_key(private_key, password, unused));
    })

GDK_DEFINE_C_FUNCTION_3(GA_get_transaction_details, struct GA_session*, session, const char*, txhash_hex, GA_json**,
    transaction, { *json_cast(transaction) = new nlohmann::json(session->get_transaction_details(txhash_hex)); })

GDK_DEFINE_C_FUNCTION_2(GA_get_available_currencies, struct GA_session*, session, GA_json**, currencies,
    { *json_cast(currencies) = new nlohmann::json(session->get_available_currencies()); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_amount, struct GA_session*, session, const GA_json*, value_details, GA_json**,
    output, { *json_cast(output) = new nlohmann::json(session->convert_amount(*json_cast(value_details))); })

GDK_DEFINE_C_FUNCTION_5(GA_set_pin, struct GA_session*, session, const char*, mnemonic, const char*, pin, const char*,
    device_id, GA_json**, pin_data,
    { *json_cast(pin_data) = new nlohmann::json(session->set_pin(mnemonic, pin, device_id)); })

GDK_DEFINE_C_FUNCTION_1(GA_disable_all_pin_logins, struct GA_session*, session, { session->disable_all_pin_logins(); })

GDK_DEFINE_C_FUNCTION_2(GA_convert_string_to_json, const char*, input, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(nlohmann::json::parse(input)); });

GDK_DEFINE_C_FUNCTION_2(GA_convert_json_to_string, const GA_json*, json, char**, output,
    { *output = to_c_string(json_cast(json)->dump()); });

GDK_DEFINE_C_FUNCTION_2(GA_register_network, const char*, name, const GA_json*, network_details,
    { ga::sdk::network_parameters::add(name, *json_cast(network_details)); });

GDK_DEFINE_C_FUNCTION_1(GA_get_networks, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(ga::sdk::network_parameters::get_all()); });

GDK_DEFINE_C_FUNCTION_2(GA_get_uniform_uint32_t, uint32_t, upper_bound, uint32_t*, output,
    { *output = ga::sdk::get_uniform_uint32_t(upper_bound); });

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_request_code, struct GA_auth_handler*, call, const char*, method,
    { auth_cast(call)->request_code(method); });

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_resolve_code, struct GA_auth_handler*, call, const char*, code,
    { auth_cast(call)->resolve_code(code); });

GDK_DEFINE_C_FUNCTION_1(GA_auth_handler_call, struct GA_auth_handler*, call, { auth_cast(call)->operator()(); });

GDK_DEFINE_C_FUNCTION_2(GA_auth_handler_get_status, struct GA_auth_handler*, call, GA_json**, output,
    { *json_cast(output) = new nlohmann::json(auth_cast(call)->get_status()); });

GDK_DEFINE_C_FUNCTION_1(GA_destroy_auth_handler, struct GA_auth_handler*, call, { delete auth_cast(call); });

GDK_DEFINE_C_FUNCTION_2(GA_get_settings, struct GA_session*, session, struct GA_json**, settings,
    { *json_cast(settings) = new nlohmann::json(session->get_settings()); })

GDK_DEFINE_C_FUNCTION_3(GA_change_settings, struct GA_session*, session, const GA_json*, settings,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::change_settings_call(*session, *json_cast(settings))); })

GDK_DEFINE_C_FUNCTION_4(GA_change_settings_twofactor, struct GA_session*, session, const char*, method, const GA_json*,
    twofactor_details, struct GA_auth_handler**, call, {
        *call = auth_cast(new ga::sdk::change_settings_twofactor_call(*session, method, *json_cast(twofactor_details)));
    })

GDK_DEFINE_C_FUNCTION_4(GA_twofactor_reset, struct GA_session*, session, const char*, email, uint32_t, is_dispute,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::twofactor_reset_call(*session, email, is_dispute != GA_FALSE)); });

GDK_DEFINE_C_FUNCTION_2(GA_twofactor_cancel_reset, struct GA_session*, session, struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::twofactor_cancel_reset_call(*session)); });

GDK_DEFINE_C_FUNCTION_3(GA_broadcast_transaction, struct GA_session*, session, const char*, transaction_hex, char**,
    tx_hash, { *tx_hash = to_c_string(session->broadcast_transaction(transaction_hex)); });

GDK_DEFINE_C_FUNCTION_3(GA_send_transaction, struct GA_session*, session, const GA_json*, transaction_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::send_transaction_call(*session, *json_cast(transaction_details))); });

GDK_DEFINE_C_FUNCTION_3(GA_twofactor_change_limits, struct GA_session*, session, const GA_json*, limit_details,
    struct GA_auth_handler**, call,
    { *call = auth_cast(new ga::sdk::change_limits_call(*session, *json_cast(limit_details))); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_bool, const GA_json*, json, const char*, path, uint32_t*, output, {
    bool v;
    json_convert(*json_cast(json), path, &v);
    *output = v ? GA_TRUE : GA_FALSE;
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_string, const GA_json*, json, const char*, path, char**, output, {
    std::string v;
    json_convert(*json_cast(json), path, &v);
    *output = to_c_string(v);
})

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_uint32, const GA_json*, json, const char*, path, uint32_t*, output,
    { json_convert(*json_cast(json), path, output); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_uint64, const GA_json*, json, const char*, path, uint64_t*, output,
    { json_convert(*json_cast(json), path, output); })

GDK_DEFINE_C_FUNCTION_3(GA_convert_json_value_to_json, const GA_json*, json, const char*, path, GA_json**, output, {
    nlohmann::json* v = new nlohmann::json();
    json_convert(*json_cast(json), path, v);
    *json_cast(output) = v;
})
