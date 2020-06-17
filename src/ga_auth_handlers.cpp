#include "ga_auth_handlers.hpp"

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "logging.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    namespace {
        // Server gives 3 attempts to get the twofactor code right before it's invalidated
        static const uint32_t TWO_FACTOR_ATTEMPTS = 3;
        static const std::string CHALLENGE_PREFIX("greenaddress.it      login ");
        // Addresses uploaded after creation of 2of2_no_recovery subaccounts
        static const uint32_t INITIAL_UPLOAD_CA = 5;

        static bool is_twofactor_invalid_code_error(const std::string& msg)
        {
            return msg == "Invalid Two Factor Authentication Code";
        }

        static auto get_xpub(const std::string& bip32_xpub_str)
        {
            const auto hdkey = bip32_public_key_from_bip32_xpub(bip32_xpub_str);
            return make_xpub(hdkey.get());
        }

        static auto get_paths_json(bool include_root = true)
        {
            std::vector<nlohmann::json> paths;
            if (include_root) {
                paths.emplace_back(std::vector<uint32_t>());
            }
            return paths;
        }
    } // namespace

    //
    // Common auth handling
    //
    auth_handler::auth_handler(session& session, const std::string& action, const nlohmann::json& hw_device)
        : m_session(session)
        , m_action(action)
        , m_attempts_remaining(TWO_FACTOR_ATTEMPTS)
    {
        try {
            init(hw_device.empty() ? hw_device : hw_device.at("device"), true);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler::auth_handler(session& session, const std::string& action)
        : m_session(session)
        , m_action(action)
        , m_attempts_remaining(TWO_FACTOR_ATTEMPTS)
    {
        try {
            init(m_session.get_hw_device(), false);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void auth_handler::init(const nlohmann::json& hw_device, bool is_pre_login)
    {
        if (m_action == "get_xpubs" || m_action == "sign_message" || m_action == "sign_tx"
            || m_action == "get_receive_address" || m_action == "create_transaction" || m_action == "get_balance"
            || m_action == "get_subaccounts" || m_action == "get_subaccount" || m_action == "get_transactions"
            || m_action == "get_unspent_outputs" || m_action == "get_expired_deposits") {
            // Hardware action, so provide the caller with the device information
            m_hw_device = hw_device;
        }
        if (!is_pre_login && !m_session.is_watch_only()) {
            m_methods = m_session.get_enabled_twofactor_methods();
        }
        m_state = m_methods.empty() ? state_type::make_call : state_type::request_code;
    }

    void auth_handler::set_error(const std::string& error_message)
    {
        GDK_LOG_SEV(log_level::debug) << m_action << " call exception: " << error_message;
        m_state = state_type::error;
        m_error = error_message;
    }

    void auth_handler::request_code(const std::string& method)
    {
        request_code_impl(method);
        m_attempts_remaining = TWO_FACTOR_ATTEMPTS;
    }

    void auth_handler::request_code_impl(const std::string& method)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::request_code);

        // For gauth request code is a no-op
        if (method != "gauth") {
            m_session.auth_handler_request_code(method, m_action, m_twofactor_data);
        }

        m_method = method;
        m_state = state_type::resolve_code;
    }

    void auth_handler::resolve_code(const std::string& code)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::resolve_code);
        m_code = code;
        m_state = state_type::make_call;
    }

    void auth_handler::set_data(const std::string& action)
    {
        m_action = action;
        m_twofactor_data = { { "action", m_action }, { "device", m_hw_device } };
    }

    void auth_handler::operator()()
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::make_call);
        try {
            if (m_code.empty() || m_method.empty()) {
                if (!m_twofactor_data.empty()) {
                    // Remove any previous auth attempts
                    m_twofactor_data.erase("method");
                    m_twofactor_data.erase("code");
                }
            } else {
                m_twofactor_data["method"] = m_method;
                m_twofactor_data["code"] = m_code;
            }
            m_state = call_impl();
        } catch (const autobahn::call_error& e) {
            auto details = get_error_details(e);
            if (is_twofactor_invalid_code_error(details.second)) {
                // The caller entered the wrong code
                // FIXME: Error if the methods time limit is up or we are rate limited
                if (m_method != "gauth" && --m_attempts_remaining == 0) {
                    // No more attempts left, caller should try the action again
                    set_error(res::id_invalid_twofactor_code);
                } else {
                    // Caller should try entering the code again
                    m_state = state_type::resolve_code;
                }
            } else {
                details = remap_ga_server_error(details);
                set_error(details.second.empty() ? std::string(e.what()) : details.second);
            }
        } catch (const std::exception& e) {
            set_error(m_action + std::string(" exception:") + e.what());
        }
    }

    nlohmann::json auth_handler::get_status() const
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::error || m_error.empty());
        const bool is_hw_action = !m_hw_device.empty();

        std::string status_str;
        nlohmann::json status;

        switch (m_state) {
        case state_type::request_code:
            GDK_RUNTIME_ASSERT(!is_hw_action);

            // Caller should ask the user to pick 2fa and request a code
            status_str = "request_code";
            status["methods"] = m_methods;
            break;
        case state_type::resolve_code:
            status_str = "resolve_code";
            if (is_hw_action) {
                // Caller must interact with the hardware and return
                // the returning data to us
                status["method"] = m_hw_device.at("name");
                status["required_data"] = m_twofactor_data;
            } else {
                // Caller should resolve the code the user has entered
                status["method"] = m_method;
                if (m_method != "gauth") {
                    status["attempts_remaining"] = m_attempts_remaining;
                }
            }
            break;
        case state_type::make_call:
            // Caller should make the call
            status_str = "call";
            break;
        case state_type::done:
            // Caller should destroy the call and continue
            status_str = "done";
            status["result"] = m_result;
            break;
        case state_type::error:
            // Caller should handle the error
            status_str = "error";
            status["error"] = m_error;
            break;
        }
        GDK_RUNTIME_ASSERT(!status_str.empty());
        status["status"] = status_str;
        status["action"] = m_action;
        status["device"] = m_hw_device;
        return status;
    }

    //
    // Register
    //
    register_call::register_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic)
        : auth_handler(session, "get_xpubs", hw_device)
        , m_mnemonic(mnemonic)
    {
        if (m_state == state_type::error) {
            return;
        }

        if (m_hw_device.empty()) {
            m_state = state_type::make_call;
        } else {
            // To register, we need the master xpub to identify the wallet,
            // and the registration xpub to compute the gait_path.
            m_state = state_type::resolve_code;
            m_twofactor_data = { { "action", m_action }, { "device", m_hw_device } };
            auto paths = get_paths_json();
            paths.emplace_back(std::vector<uint32_t>{ harden(0x4741) });
            m_twofactor_data["paths"] = paths;
        }
    }

    auth_handler::state_type register_call::call_impl()
    {
        if (m_hw_device.empty()) {
            constexpr bool supports_csv = true;
            m_session.register_user(m_mnemonic, supports_csv);
        } else {
            const nlohmann::json args = nlohmann::json::parse(m_code);
            const std::vector<std::string> xpubs = args.at("xpubs");
            const auto master_xpub = get_xpub(xpubs.at(0));

            const auto master_chain_code_hex = b2h(master_xpub.first);
            const auto master_pub_key_hex = b2h(master_xpub.second);

            // Get our gait path xpub and compute gait_path from it
            const auto gait_xpub = get_xpub(xpubs.at(1));
            const auto gait_path_hex = b2h(ga_pubkeys::get_gait_path_bytes(gait_xpub));

            const bool supports_csv = json_get_value(m_hw_device, "supports_arbitrary_scripts", false);
            m_session.register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
        }
        return state_type::done;
    }

    //
    // Login
    //
    login_call::login_call(
        session& session, const nlohmann::json& hw_device, const std::string& mnemonic, const std::string& password)
        : auth_handler(session, "get_xpubs", hw_device)
        , m_mnemonic(mnemonic)
        , m_password(password)
    {
        if (m_state == state_type::error) {
            return;
        }

        if (m_hw_device.empty()) {
            m_state = state_type::make_call;
        } else {
            // We first need the challenge, so ask the caller for the master pubkey.
            m_state = state_type::resolve_code;
            set_data("get_xpubs");
            auto paths = get_paths_json();
            paths.emplace_back(PASSWORD_PATH);
            m_twofactor_data["paths"] = paths;
        }
    }

    auth_handler::state_type login_call::call_impl()
    {
        if (m_hw_device.empty()) {
            if (m_action == "get_receive_address") {
                for (const uint32_t subaccount : m_ca_reqs) {
                    const auto address = m_session.get_receive_address({ { "subaccount", subaccount } });
                    const auto blinding_key = m_session.get_blinding_key_for_script(address["blinding_script_hash"]);

                    const std::string blinded_addr = m_session.blind_address(address["address"], blinding_key);
                    m_ca_addrs[subaccount].emplace_back(blinded_addr);
                }
            } else {
                m_session.login(m_mnemonic, m_password);
            }

            // fall-through down to check for/upload confidential addresses requests
        } else {
            const nlohmann::json args = nlohmann::json::parse(m_code);

            if (m_action == "get_receive_address") {
                // Blind the address
                const std::string blinded_addr
                    = m_session.blind_address(m_twofactor_data["address"]["address"], args["blinding_key"]);

                // save it and pop the request
                m_ca_addrs[m_ca_reqs.back()].emplace_back(blinded_addr);
                m_ca_reqs.pop_back();

                // prepare the next one
                if (!m_ca_reqs.empty()) {
                    m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_ca_reqs.back() } });
                    return state_type::resolve_code;
                }

                // fall-through down to upload them
            } else if (m_action == "get_xpubs") {
                const std::vector<std::string> xpubs = args.at("xpubs");

                if (m_challenge.empty()) {
                    // Compute the challenge with the master pubkey
                    const auto master_xpub = get_xpub(xpubs.at(0));
                    const auto btc_version = m_session.get_network_parameters().btc_version();
                    m_challenge = m_session.get_challenge(address_from_xpub(btc_version, master_xpub));

                    const auto local_key = pbkdf2_hmac_sha512(get_xpub(xpubs.at(1)).second, PASSWORD_SALT);
                    m_session.set_local_encryption_key(local_key);

                    // Ask the caller to sign the challenge
                    set_data("sign_message");
                    m_twofactor_data["message"] = CHALLENGE_PREFIX + m_challenge;
                    m_twofactor_data["path"] = std::vector<uint32_t>{ 0x4741b11e };
                    return state_type::resolve_code;
                }
                // Register the xpub for each of our subaccounts
                m_session.register_subaccount_xpubs(xpubs);

                // fall through to the required_ca check down there...
            } else if (m_action == "sign_message") {
                // Log in and set up the session
                m_session.authenticate(args.at("signature"), "GA", std::string(), m_hw_device);

                // Ask the caller for the xpubs for each subaccount
                std::vector<nlohmann::json> paths;
                for (const auto sa : m_session.get_subaccounts()) {
                    paths.emplace_back(ga_user_pubkeys::get_subaccount_path(sa["pointer"]));
                }
                set_data("get_xpubs");
                m_twofactor_data["paths"] = paths;
                return state_type::resolve_code;
            }
        }

        if (!m_ca_addrs.empty()) {
            // done, upload and exit
            for (auto const& entry : m_ca_addrs) {
                m_session.upload_confidential_addresses(entry.first, entry.second);
            }

            return state_type::done;
        }

        // Check whether the backend asked for some conf addrs (only 2of2_no_recovery) on some subaccount
        for (const auto& sa : m_session.get_subaccounts()) {
            if (sa["required_ca"] > 0) {
                // add the subaccount number (`pointer`) repeated `required_ca` times. we will pop them one at a time
                // and then resolve their blinding keys
                m_ca_reqs.insert(m_ca_reqs.end(), sa["required_ca"], sa["pointer"]);
            }
        }

        if (m_ca_reqs.size() > 0) {
            // prepare the first request
            set_data("get_receive_address");
            m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_ca_reqs.back() } });

            return state_type::resolve_code;
        }

        return state_type::done;
    }

    //
    // Login_with_pin
    //
    login_with_pin_call::login_with_pin_call(session& session, const std::string& pin, const nlohmann::json& pin_data)
        : auth_handler(session, "get_xpubs", nlohmann::json::object())
        , m_pin(pin)
        , m_pin_data(pin_data)
    {
    }

    auth_handler::state_type login_with_pin_call::call_impl()
    {
        m_session.login_with_pin(m_pin, m_pin_data);

        if (m_session.is_liquid()) {
            // when logged in with pin, the wallet software signer is available, thus the session is able to obtain
            // blinding key without interacting with the caller
            for (const auto& sa : m_session.get_subaccounts()) {
                std::vector<std::string> conf_addresses;

                for (size_t i = 0; i < sa["required_ca"]; ++i) {
                    const auto address = m_session.get_receive_address({ { "subaccount", sa["pointer"] } });
                    const auto blinding_key = m_session.get_blinding_key_for_script(address["blinding_script_hash"]);
                    const std::string blinded_addr = m_session.blind_address(address["address"], blinding_key);
                    conf_addresses.emplace_back(blinded_addr);
                }

                if (!conf_addresses.empty()) {
                    m_session.upload_confidential_addresses(sa["pointer"], conf_addresses);
                }
            }
        }

        return state_type::done;
    }

    //
    // Create subaccount
    //
    create_subaccount_call::create_subaccount_call(session& session, const nlohmann::json& details)
        : auth_handler(session, "get_xpubs")
        , m_details(details)
        , m_subaccount(0)
        , m_remaining_ca_addrs(0)
    {
        if (m_state == state_type::error) {
            return;
        }

        // also check if we need to upload a few confidential addrs
        if (m_session.is_liquid() && details.at("type") == "2of2_no_recovery") {
            m_remaining_ca_addrs = INITIAL_UPLOAD_CA;
        }

        if (m_hw_device.empty()) {
            m_state = state_type::make_call;
        } else {
            try {
                m_state = state_type::resolve_code;
                m_subaccount = session.get_next_subaccount();
                m_twofactor_data = { { "action", m_action }, { "device", m_hw_device } };

                std::vector<nlohmann::json> paths;
                paths.emplace_back(ga_user_pubkeys::get_subaccount_path(m_subaccount));
                m_twofactor_data["paths"] = paths;
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type create_subaccount_call::call_impl()
    {
        if (m_hw_device.empty()) {
            m_result = m_session.create_subaccount(m_details);

            // generate the conf addrs if required
            while (m_remaining_ca_addrs > 0) {
                const auto address = m_session.get_receive_address({ { "subaccount", m_result["pointer"] } });
                const auto blinding_key = m_session.get_blinding_key_for_script(address["blinding_script_hash"]);

                m_ca_addrs.emplace_back(m_session.blind_address(address["address"], blinding_key));

                m_remaining_ca_addrs--;
            }
        } else {
            if (m_action == "get_xpubs") {
                const nlohmann::json args = nlohmann::json::parse(m_code);
                m_result = m_session.create_subaccount(m_details, m_subaccount, args.at("xpubs").at(0));
            } else if (m_action == "get_receive_address") {
                const nlohmann::json args = nlohmann::json::parse(m_code);
                const auto pub_blinding_key = args["blinding_key"];

                m_ca_addrs.emplace_back(
                    m_session.blind_address(m_twofactor_data["address"]["address"], pub_blinding_key));

                m_remaining_ca_addrs--;
            }

            if (m_remaining_ca_addrs > 0) {
                set_data("get_receive_address");
                m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_result["pointer"] } });

                return state_type::resolve_code;
            }
        }

        // we prepared a few addresses, upload them to the backend
        if (m_ca_addrs.size() > 0) {
            m_session.upload_confidential_addresses(m_result["pointer"], m_ca_addrs);
        }

        return state_type::done;
    }

    ack_system_message_call::ack_system_message_call(session& session, const std::string& msg)
        : auth_handler(session, "sign_message")
        , m_message(msg)
    {
        if (m_state == state_type::error) {
            return;
        }

        if (m_hw_device.empty()) {
            m_state = state_type::make_call;
        } else {
            try {
                m_message_info = m_session.get_system_message_info(msg);
                m_state = state_type::resolve_code;
                m_twofactor_data = { { "action", m_action }, { "device", m_hw_device } };
                m_twofactor_data["paths"] = m_message_info.second;
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type ack_system_message_call::call_impl()
    {
        if (m_hw_device.empty()) {
            m_session.ack_system_message(m_message);
        } else {
            const nlohmann::json args = nlohmann::json::parse(m_code);
            m_session.ack_system_message(m_message_info.first, args.at("signature"));
        }
        return state_type::done;
    }

    //
    // Sign tx
    //
    sign_transaction_call::sign_transaction_call(session& session, const nlohmann::json& tx_details)
        : auth_handler(session, "sign_tx")
        , m_tx_details(tx_details)
    {
        if (m_state == state_type::error) {
            return;
        }

        if (m_hw_device.empty() || json_get_value(tx_details, "is_sweep", false)) {
            // TODO: Once tx aggregation is implemented, merge the sweep logic
            // with general tx construction to allow HW devices to sign individual
            // inputs (currently HW expects to sign all tx inputs)
            m_state = state_type::make_call;
        } else {
            try {
                // Compute the data we need for the hardware to sign the transaction
                m_state = state_type::resolve_code;

                m_twofactor_data = { { "action", m_action }, { "device", m_hw_device }, { "transaction", tx_details } };

                // We need the inputs, augmented with types, scripts and paths
                const auto signing_inputs = get_ga_signing_inputs(tx_details);
                std::set<std::string> addr_types;
                nlohmann::json prev_txs;
                for (const auto& input : signing_inputs) {
                    const auto& addr_type = input.at("address_type");
                    GDK_RUNTIME_ASSERT(!addr_type.empty()); // Must be spendable by us
                    addr_types.insert(addr_type.get<std::string>());
                }
                if (addr_types.find(address_type::p2pkh) != addr_types.end()) {
                    // TODO: Support mixed/batched sweep transactions with non-sweep inputs
                    GDK_RUNTIME_ASSERT(false);
                }

                // When signing btc, we always pass the prior transactions creating the utxos we are spending,
                // so the hw wallet can verify the amounts.  In theory this is not required when the current
                // txn is spending a single segwit utxo - but we will not make that optimisation at this time
                // - the caller can always choose to ignore the passed txn if so desired in that case.
                // NOTE: this is not required for liquid where the attack is not possible, and the fee is an
                // explicit output.
                if (!m_session.get_network_parameters().liquid()) {
                    for (const auto& input : signing_inputs) {
                        const std::string txhash = input.at("txhash");
                        if (prev_txs.find(txhash) == prev_txs.end()) {
                            prev_txs.emplace(txhash, session.get_transaction_details(txhash).at("transaction"));
                        }
                    }
                }
                m_twofactor_data["signing_address_types"]
                    = std::vector<std::string>(addr_types.begin(), addr_types.end());
                m_twofactor_data["signing_inputs"] = signing_inputs;
                m_twofactor_data["signing_transactions"] = prev_txs;
                m_twofactor_data["transaction_outputs"] = tx_details["transaction_outputs"];
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type sign_transaction_call::call_impl()
    {
        if (m_hw_device.empty() || json_get_value(m_tx_details, "is_sweep", false)) {
            m_result = m_session.sign_transaction(m_tx_details);
        } else {
            const nlohmann::json args = nlohmann::json::parse(m_code);
            const auto& signatures = args.at("signatures");
            const auto& inputs = m_twofactor_data["signing_inputs"];
            const auto& outputs = m_twofactor_data["transaction_outputs"];
            const uint32_t flags = m_session.get_network_parameters().liquid()
                ? (WALLY_TX_FLAG_USE_WITNESS | WALLY_TX_FLAG_USE_ELEMENTS)
                : 0;
            const auto tx = tx_from_hex(m_twofactor_data["transaction"].at("transaction"), flags);

            GDK_RUNTIME_ASSERT(signatures.is_array() && signatures.size() == inputs.size());

            if (m_session.get_network_parameters().liquid()) {
                GDK_RUNTIME_ASSERT(
                    args.at("asset_commitments").is_array() && args.at("asset_commitments").size() == outputs.size());
                GDK_RUNTIME_ASSERT(
                    args.at("value_commitments").is_array() && args.at("value_commitments").size() == outputs.size());
                GDK_RUNTIME_ASSERT(args.at("abfs").is_array() && args.at("abfs").size() == outputs.size());
                GDK_RUNTIME_ASSERT(args.at("vbfs").is_array() && args.at("vbfs").size() == outputs.size());

                const auto& asset_commitments = args.at("asset_commitments");
                const auto& value_commitments = args.at("value_commitments");
                const auto& abfs = args.at("abfs");
                const auto& vbfs = args.at("vbfs");

                size_t i = 0;
                for (const auto& out : outputs) {
                    if (!out.at("is_fee")) {
                        m_session.blind_output(m_twofactor_data["transaction"], tx, i, out, asset_commitments[i],
                            value_commitments[i], abfs[i], vbfs[i]);
                    }
                    ++i;
                }
            }

            size_t i = 0;
            for (const auto& utxo : inputs) {
                m_session.sign_input(tx, i, utxo, signatures[i]);
                ++i;
            }

            std::swap(m_result, m_twofactor_data["transaction"]);
            m_result["user_signed"] = true;
            m_result["blinded"] = true;
            update_tx_info(tx, m_result);
        }
        return state_type::done;
    }

    //
    // Get receive address
    //
    get_receive_address_call::get_receive_address_call(session& session, const nlohmann::json& details)
        : auth_handler(session, "get_receive_address")
        , m_details(details)
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            nlohmann::json address = m_session.get_receive_address(details);
            m_twofactor_data = { { "action", m_action }, { "device", m_hw_device }, { "address", address } };
        } catch (const std::exception& e) {
            set_error(e.what());
            return;
        }

        // If there's no HW, OR we are on Bitcoin then there's no need to poll the HW, and we are ready for the call
        m_state = (m_hw_device.empty() || !m_session.is_liquid()) ? state_type::make_call : state_type::resolve_code;
    }

    auth_handler::state_type get_receive_address_call::call_impl()
    {
        // initially our result is what we generated earlier
        m_result = m_twofactor_data["address"];

        // if we are on liquid blind the address
        if (m_session.is_liquid()) {
            std::string pub_blinding_key;

            if (m_hw_device.empty()) {
                // Get the key from our signer
                pub_blinding_key = m_session.get_blinding_key_for_script(m_result["blinding_script_hash"]);
            } else {
                // Use the response from the HW
                const nlohmann::json args = nlohmann::json::parse(m_code);
                pub_blinding_key = args.at("blinding_key");
            }

            // Blind the address
            m_result["address"] = m_session.blind_address(m_result["address"], pub_blinding_key);
        }

        return state_type::done;
    }

    static bool cache_nonces(session& session, const nlohmann::json& blinded_scripts, const nlohmann::json& nonces)
    {
        GDK_RUNTIME_ASSERT(blinded_scripts.size() == nonces.size());

        size_t i = 0;
        bool updated = false;

        for (const auto& nonce : nonces) {
            const std::string& pubkey = blinded_scripts.at(i).at("pubkey");
            const std::string& script = blinded_scripts.at(i).at("script");

            if (!session.has_blinding_nonce(pubkey, script)) {
                session.set_blinding_nonce(pubkey, script, nonce);
                updated = true;
            }

            ++i;
        }

        return updated;
    }

    //
    // Create transaction
    //
    create_transaction_call::create_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler(session, "create_transaction")
        , m_details(details)
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            m_tx = m_session.create_transaction(details);
            m_twofactor_data = { { "action", m_action }, { "device", m_hw_device }, { "transaction", m_tx } };
            if (m_session.is_liquid()) {
                m_twofactor_data["blinded_scripts"] = m_session.get_blinded_scripts(details);
            }
        } catch (const std::exception& e) {
            GDK_LOG_SEV(log_level::info) << "exception in create_transaction_call::create_transaction_call()";
            set_error(e.what());
            return;
        }

        // If there's no HW, OR we are on Bitcoin then there's no need to poll the HW, and we are ready for the call
        m_state = (m_hw_device.empty() || !m_session.is_liquid()) ? state_type::make_call : state_type::resolve_code;
    }

    auth_handler::state_type create_transaction_call::call_impl()
    {
        if (!m_session.is_liquid()) {
            m_result = m_tx; // no need to do much here
            return state_type::done;
        }

        // TODO: we might also need to blind other kind of addresses, in case of sweep etc
        if (m_tx.find("change_address") == m_tx.end()) {
            m_result = m_tx;
            return state_type::done;
        }

        nlohmann::json args;
        if (!m_hw_device.empty()) {
            args = nlohmann::json::parse(m_code);

            if (args.contains("nonces")) {
                if (cache_nonces(m_session, m_twofactor_data["blinded_scripts"], args["nonces"])) {
                    if (m_tx["utxos"].contains("error")) {
                        // In the case where the blinding nonces were not available the first time
                        // create_transaction was called they will have been added under 'error'
                        // Clear the utxos here to force the next call to create_transaction to
                        // reload them.
                        // This is not really ideal as it involves another server call and throws
                        // away any non-error utxos as well but any better fix will require more
                        // extensive refactoring
                        m_tx.erase("utxos");
                    }
                }
            }
        }

        for (const auto& it : m_tx.at("change_address").items()) {
            // already done, skip it
            if (it.value().value("is_blinded", false)) {
                continue;
            }

            const std::string asset_tag = it.key();

            std::string pub_blinding_key;
            if (m_hw_device.empty()) {
                // Get the key from our signer
                pub_blinding_key = m_session.get_blinding_key_for_script(it.value().at("blinding_script_hash"));
            } else {
                // Use the response from the HW
                pub_blinding_key = args.at("blinding_keys").at(asset_tag);
            }

            const std::string& unconf_addr = m_session.extract_confidential_address(it.value().at("address"));
            m_tx["change_address"][asset_tag]["address"] = m_session.blind_address(unconf_addr, pub_blinding_key);
            m_tx["change_address"][asset_tag]["is_blinded"] = true;
        }

        // Update the transaction
        m_result = m_session.create_transaction(m_tx);

        return state_type::done;
    }

    // Generic parent for all the other calls that needs the unblinded transactions in order to do their job
    needs_unblind_call::needs_unblind_call(const std::string& name, session& session, const nlohmann::json& details)
        : auth_handler(session, name)
        , m_details(details)
    {
        if (m_state == state_type::error) {
            return;
        }

        if (!m_session.is_liquid() || m_session.hw_liquid_support() == liquid_support_level::full) {
            m_state = state_type::make_call;
        } else if (m_session.hw_liquid_support() == liquid_support_level::lite) {
            try {
                m_state = state_type::resolve_code;

                const nlohmann::json blinded_scripts = m_session.get_blinded_scripts(details);
                m_twofactor_data
                    = { { "action", m_action }, { "device", m_hw_device }, { "blinded_scripts", blinded_scripts } };
            } catch (const std::exception& e) {
                set_error(std::string("exception in needs_unblind_call constructor:") + e.what());
            }
        } else if (m_session.hw_liquid_support() == liquid_support_level::none) {
            set_error("id_the_hardware_wallet_you_are");
        } else {
            // should be unreachable
            GDK_RUNTIME_ASSERT(false);
        }
    }

    auth_handler::state_type needs_unblind_call::call_impl()
    {
        set_nonces(); // parse and set the nonces we got back
        return wrapped_call_impl(); // run the actual wrapped call
    }

    void needs_unblind_call::set_nonces()
    {
        // Bitcoin or HW with full support
        if (!m_session.is_liquid() || m_session.hw_liquid_support() == liquid_support_level::full) {
            return;
        }

        const nlohmann::json args = nlohmann::json::parse(m_code);
        cache_nonces(m_session, m_twofactor_data["blinded_scripts"], args["nonces"]);
    }

    //
    // Get balance
    //
    get_balance_call::get_balance_call(session& session, const nlohmann::json& details)
        : needs_unblind_call("get_balance", session, details)
    {
    }

    auth_handler::state_type get_balance_call::wrapped_call_impl()
    {
        m_result = m_session.get_balance(m_details);
        return state_type::done;
    }

    //
    // Get subaccounts
    //
    get_subaccounts_call::get_subaccounts_call(session& session)
        : needs_unblind_call("get_subaccounts", session, nlohmann::json::object())
    {
    }

    auth_handler::state_type get_subaccounts_call::wrapped_call_impl()
    {
        m_result = nlohmann::json({ { "subaccounts", m_session.get_subaccounts() } });
        return state_type::done;
    }

    //
    // Get subaccount
    //
    get_subaccount_call::get_subaccount_call(session& session, uint32_t subaccount)
        : needs_unblind_call("get_subaccount", session, nlohmann::json({ { "index", subaccount } }))
    {
    }

    auth_handler::state_type get_subaccount_call::wrapped_call_impl()
    {
        m_result = m_session.get_subaccount(m_details["index"]);
        return state_type::done;
    }

    //
    // Get transactions
    //
    get_transactions_call::get_transactions_call(session& session, const nlohmann::json& details)
        : needs_unblind_call("get_transactions", session, details)
    {
    }

    auth_handler::state_type get_transactions_call::wrapped_call_impl()
    {
        m_result = { { "transactions", m_session.get_transactions(m_details) } };
        return state_type::done;
    }

    //
    // Get unspent outputs
    //
    get_unspent_outputs_call::get_unspent_outputs_call(session& session, const nlohmann::json& details)
        : needs_unblind_call("get_unspent_outputs", session, details)
    {
    }

    auth_handler::state_type get_unspent_outputs_call::wrapped_call_impl()
    {
        m_result = { { "unspent_outputs", m_session.get_unspent_outputs(m_details) } };
        return state_type::done;
    }

    //
    // Get expired deposits
    //
    get_expired_deposits_call::get_expired_deposits_call(session& session, const nlohmann::json& details)
        : needs_unblind_call("get_expired_deposits", session, details)
    {
    }

    auth_handler::state_type get_expired_deposits_call::wrapped_call_impl()
    {
        m_result = m_session.get_expired_deposits(m_details);
        return state_type::done;
    }

    //
    // Change settings
    //
    change_settings_call::change_settings_call(session& session, const nlohmann::json& settings)
        : auth_handler(session, std::string())
        , m_settings(settings)
    {
        if (m_state == state_type::error) {
            return;
        }

        m_state = state_type::make_call;

        const auto nlocktime_p = settings.find("nlocktime");
        if (nlocktime_p != settings.end()) {
            const uint64_t new_nlocktime = nlocktime_p->get<uint64_t>();
            const uint64_t current_nlocktime = m_session.get_settings()["nlocktime"];
            if (new_nlocktime != current_nlocktime) {
                m_nlocktime_value = { { "value", new_nlocktime } };

                // If 2fa enabled trigger resolution for set_nlocktime
                if (!m_methods.empty()) {
                    m_action = "set_nlocktime";
                    m_state = state_type::request_code;
                    m_twofactor_data = m_nlocktime_value;
                }
            }
        }
    }

    auth_handler::state_type change_settings_call::call_impl()
    {
        m_session.change_settings(m_settings);
        if (!m_nlocktime_value.is_null()) {
            m_session.set_nlocktime(m_nlocktime_value, m_twofactor_data);
        }
        return state_type::done;
    }

    //
    // Enable 2FA
    //
    change_settings_twofactor_call::change_settings_twofactor_call(
        session& session, const std::string& method_to_update, const nlohmann::json& details)
        : auth_handler(session, "enable_2fa")
        , m_method_to_update(method_to_update)
        , m_details(details)
        , m_enabling(m_details.value("enabled", true))
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            m_current_config = session.get_twofactor_config();
            GDK_RUNTIME_ASSERT(m_current_config.find(method_to_update) != m_current_config.end());

            const auto& current_subconfig = m_current_config[method_to_update];

            const bool set_email = !m_enabling && method_to_update == "email" && m_details.value("confirmed", false)
                && !current_subconfig.value("confirmed", false);

            if (!set_email && current_subconfig.value("enabled", !m_enabling) == m_enabling) {
                // Caller is attempting to enable or disable when thats already the current state
                set_error(method_to_update + " is already " + (m_enabling ? "enabled" : "disabled"));
                return;
            }

            // The data associated with method_to_update e.g. email, phone etc
            const std::string data = json_get_value(m_details, "data");

            if (m_enabling) {
                if (method_to_update == "gauth") {
                    // For gauth the user must pass in the current seed returned by the
                    // server.
                    // FIXME: Allow the user to specify their own seed in the future.
                    if (data != json_get_value(current_subconfig, "data")) {
                        set_error(res::id_inconsistent_data_provided_for);
                        return;
                    }
                }
                m_twofactor_data = { { "method", m_method_to_update } };
            } else {
                if (set_email) {
                    // The caller set confirmed=true but enabled=false: they only want
                    // to set the email associated with twofactor but not enable it for 2fa.
                    // This is useful since notifications and 2fa currently share the
                    // same 2fa email address.
                    m_action = "set_email";
                    m_twofactor_data = { { "address", data } };
                } else {
                    m_action = "disable_2fa";
                    m_twofactor_data = { { "method", method_to_update } };
                }
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler::state_type change_settings_twofactor_call::on_init_done(const std::string& new_action)
    {
        // The user has either:
        // 1) Skipped entering any 2fa so far because they have none enabled, OR
        // 2) Entered the 2fa details of another method to allow the new method to be enabled
        // So, we now request the user enters the code for the method they are enabling
        // (which means restricting their 2fa choice for entering the code to this method)
        m_method = m_method_to_update;
        m_action = new_action + m_method;
        m_methods = { { m_method_to_update } };
        // Move to prompt the user for the code for the method they are enabling
        m_gauth_data = m_twofactor_data;
        m_twofactor_data = nlohmann::json::object();
        return state_type::resolve_code;
    }

    auth_handler::state_type change_settings_twofactor_call::call_impl()
    {
        if (m_action == "set_email") {
            const std::string data = json_get_value(m_details, "data");
            m_session.set_email(data, m_twofactor_data);
            // Move to activate email
            return on_init_done("activate_");
        }
        if (m_action == "activate_email") {
            const std::string data = json_get_value(m_details, "data");
            m_session.activate_email(m_code);
            return state_type::done;
        }
        if (m_action == "enable_2fa") {
            if (m_method_to_update != "gauth") {
                // gauth doesn't have an init_enable step
                const std::string data = json_get_value(m_details, "data");
                m_session.init_enable_twofactor(m_method_to_update, data, m_twofactor_data);
            }
            // Move to enable the 2fa method
            return on_init_done("enable_");
        }
        if (boost::algorithm::starts_with(m_action, "enable_")) {
            // The user has authorized enabling 2fa (if required), so enable the
            // method using its code (which proves the user got a code from the
            // method being enabled)
            if (m_method_to_update == "gauth") {
                try {
                    m_session.enable_gauth(m_code, m_gauth_data);
                } catch (const autobahn::call_error& e) {
                    const auto details = get_error_details(e);
                    if (is_twofactor_invalid_code_error(details.second)) {
                        // The caller entered the wrong code
                        // We can't know if they entered the wrong gauth code
                        // or the wrong initial 2fa code to enable gauth (unless
                        // they dont have any two factor methods enabled yet),
                        // so if they have other 2fa, send them back to the
                        // initial state
                        const auto methods = m_session.get_enabled_twofactor_methods();
                        if (!methods.empty()) {
                            m_action = "enable_2fa";
                            m_methods = methods;
                            m_twofactor_data = { { "method", m_method_to_update } };
                            return state_type::request_code;
                        }
                    }
                    throw;
                }
            } else {
                m_session.enable_twofactor(m_method_to_update, m_code);
            }
            return state_type::done;
        }
        if (m_action == "disable_2fa") {
            m_session.disable_twofactor(m_method_to_update, m_twofactor_data);
            // For gauth, we must reset the sessions 2fa data since once it is
            // disabled, the server must create a new secret (which it only
            // does on fetching 2fa config). Without this a subsequent re-enable
            // will fail.
            // FIXME: The server should return the new secret/the user should be
            // able to supply their own
            const bool reset_cached = m_method_to_update == "gauth";
            m_result = m_session.get_twofactor_config(reset_cached).at(m_method_to_update);
            return state_type::done;
        }
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    //
    // Change limits
    //
    change_limits_call::change_limits_call(session& session, const nlohmann::json& details)
        : auth_handler(session, "change_tx_limits")
        , m_limit_details(details)
        , m_is_decrease(m_methods.empty() ? false : m_session.is_spending_limits_decrease(details))
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            // Transform the details json that is passed in into the json that the api expects
            // The api expects {is_fiat: bool, total: in satoshis, per_tx: not really used}
            // This function takes a full amount json, e.g. {'BTC': 1234}
            const bool is_fiat = details.at("is_fiat").get<bool>();
            GDK_RUNTIME_ASSERT(is_fiat == (details.find("fiat") != details.end()));
            m_limit_details = { { "is_fiat", is_fiat }, { "per_tx", 0 } };
            if (is_fiat) {
                m_limit_details["total"] = amount::get_fiat_cents(details["fiat"]);
            } else {
                m_limit_details["total"] = session.convert_amount(details)["satoshi"];
            }

            if (m_is_decrease) {
                m_state = state_type::make_call; // Limit decreases do not require 2fa
            } else {
                m_twofactor_data = m_limit_details;
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void change_limits_call::request_code(const std::string& method)
    {
        // If we are requesting a code, then our limits changed elsewhere and
        // this is not a limit decrease
        m_is_decrease = false;
        auth_handler::request_code(method);
    }

    auth_handler::state_type change_limits_call::call_impl()
    {
        m_session.change_settings_limits(m_limit_details, m_twofactor_data);
        m_result = m_session.get_spending_limits();
        return state_type::done;
    }

    //
    // Remove account
    //
    remove_account_call::remove_account_call(session& session)
        : auth_handler(session, "remove_account")
    {
    }

    auth_handler::state_type remove_account_call::call_impl()
    {
        m_session.remove_account(m_twofactor_data);
        return state_type::done;
    }

    //
    // Send transaction
    //
    send_transaction_call::send_transaction_call(session& session, const nlohmann::json& tx_details)
        : auth_handler(session, "send_raw_tx")
        , m_tx_details(tx_details)
        , m_twofactor_required(!m_methods.empty())
        , m_under_limit(false)
    {
        if (m_state == state_type::error) {
            return;
        }

        const bool is_liquid = m_session.get_network_parameters().liquid();

        try {
            if (!is_liquid) {
                const uint64_t limit
                    = m_twofactor_required ? session.get_spending_limits()["satoshi"].get<uint64_t>() : 0;
                const uint64_t satoshi = m_tx_details["satoshi"];
                const uint64_t fee = m_tx_details["fee"];
                const uint32_t change_index = m_tx_details["change_index"]["btc"];

                m_limit_details = { { "asset", "BTC" }, { "amount", satoshi + fee }, { "fee", fee },
                    { "change_idx", change_index == NO_CHANGE_INDEX ? -1 : static_cast<int>(change_index) } };

                // If this transaction has a previous transaction, i.e. it is replacing a previous transaction
                // for example by RBF, then define m_bump_amount as the additional cost of this transaction
                // compared to the original
                const auto previous_transaction = tx_details.find("previous_transaction");
                if (previous_transaction != tx_details.end()) {
                    const auto previous_fee = previous_transaction->at("fee").get<uint64_t>();
                    GDK_RUNTIME_ASSERT(previous_fee < fee);
                    m_bump_amount = fee - previous_fee;
                }

                // limit_delta is the amount to deduct from the current spending limit for this tx
                // For a fee bump (RBF) it is just the bump amount, i.e. the additional fee, because the
                // previous fee and tx amount has already been deducted from the limits
                const uint64_t limit_delta = m_bump_amount != 0u ? m_bump_amount : satoshi + fee;

                if (limit != 0 && limit_delta <= limit) {
                    // 2fa is enabled and we have a spending limit, but this tx is under it.
                    m_under_limit = true;
                    m_state = state_type::make_call;
                }
            }

            if (m_state == state_type::make_call) {
                // We are ready to call, so make the required twofactor data
                create_twofactor_data();
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void send_transaction_call::request_code(const std::string& method)
    {
        // If we are requesting a code, either:
        // 1) Caller has 2FA configured and the tx is not under limits, OR
        // 2) Tx was thought to be under limits but limits have now changed
        // Prevent the call from trying to send using the limit next time through the state machine
        m_under_limit = false;
        try {
            create_twofactor_data();
            auth_handler::request_code(method);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void send_transaction_call::create_twofactor_data()
    {
        const bool is_liquid = m_session.get_network_parameters().liquid();
        m_twofactor_data = nlohmann::json::object();
        if (m_twofactor_required && !is_liquid) {
            if (m_bump_amount != 0u) {
                m_action = "bump_fee";
                const auto amount_key = m_under_limit ? "try_under_limits_bump" : "amount";
                m_twofactor_data[amount_key] = m_bump_amount;
            } else {
                if (m_under_limit) {
                    // Tx is under the limit and a send hasn't previously failed causing
                    // the user to enter a code. Try sending without 2fa as an under limits spend
                    m_twofactor_data["try_under_limits_spend"] = m_limit_details;
                } else {
                    // 2FA is provided or not configured. Add the send details
                    m_twofactor_data["amount"] = m_limit_details["amount"];
                    m_twofactor_data["fee"] = m_limit_details["fee"];
                    m_twofactor_data["change_idx"] = m_limit_details["change_idx"];
                    // TODO: Add the recipient to twofactor_data for more server verification
                }
            }
        }
    }

    auth_handler::state_type send_transaction_call::call_impl()
    {
        const bool is_liquid = m_session.get_network_parameters().liquid();
        if (!is_liquid) {
            // The api requires the request and action data to differ, which is non-optimal
            json_rename_key(m_twofactor_data, "fee", "send_raw_tx_fee");
            json_rename_key(m_twofactor_data, "change_idx", "send_raw_tx_change_idx");

            const char* amount_key = m_bump_amount != 0u ? "bump_fee_amount" : "send_raw_tx_amount";
            json_rename_key(m_twofactor_data, "amount", amount_key);
        }

        // TODO: Add the recipient to twofactor_data for more server verification
        m_result = m_session.send_transaction(m_tx_details, m_twofactor_data);
        return state_type::done;
    }

    //
    // Request 2fa reset
    //
    twofactor_reset_call::twofactor_reset_call(session& session, const std::string& email, bool is_dispute)
        : auth_handler(session, "request_reset")
        , m_reset_email(email)
        , m_is_dispute(is_dispute)
        , m_confirming(false)
    {
        if (m_state != state_type::error) {
            m_state = state_type::make_call;
        }
    }

    auth_handler::state_type twofactor_reset_call::call_impl()
    {
        if (!m_confirming) {
            // Request the reset
            m_result = m_session.reset_twofactor(m_reset_email);
            // Move on to confirming the reset email address
            m_confirming = true;
            m_methods = { { "email" } };
            m_method = "email";
            return state_type::resolve_code;
        }
        // Confirm the reset
        m_result = m_session.confirm_twofactor_reset(m_reset_email, m_is_dispute, m_twofactor_data);
        return state_type::done;
    }

    //
    // Cancel 2fa reset
    //
    twofactor_cancel_reset_call::twofactor_cancel_reset_call(session& session)
        : auth_handler(session, "cancel_reset")
    {
    }

    auth_handler::state_type twofactor_cancel_reset_call::call_impl()
    {
        m_result = m_session.cancel_twofactor_reset(m_twofactor_data);
        return state_type::done;
    }

    //
    // Set CSV time
    //
    csv_time_call::csv_time_call(session& session, const nlohmann::json& params)
        : auth_handler(session, "set_csvtime")
        , m_params(params)
    {
        if (m_state == state_type::error) {
            return;
        }

        m_twofactor_data = { { "value", m_params.at("value") } };
    }

    auth_handler::state_type csv_time_call::call_impl()
    {
        m_session.set_csvtime(m_params, m_twofactor_data);
        return state_type::done;
    }

    //
    // Set nlocktime time
    //
    nlocktime_call::nlocktime_call(session& session, const nlohmann::json& params)
        : auth_handler(session, "set_nlocktime")
        , m_params(params)
    {
        if (m_state == state_type::error) {
            return;
        }

        m_twofactor_data = { { "value", m_params.at("value") } };
    }

    auth_handler::state_type nlocktime_call::call_impl()
    {
        m_session.set_nlocktime(m_params, m_twofactor_data);
        return state_type::done;
    }
} // namespace sdk
} // namespace ga
