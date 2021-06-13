#include "ga_auth_handlers.hpp"

#include "assertion.hpp"
#include "boost_wrapper.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    namespace {
        static const std::string CHALLENGE_PREFIX("greenaddress.it      login ");
        // Addresses uploaded after creation of 2of2_no_recovery subaccounts
        static const uint32_t INITIAL_UPLOAD_CA = 5;

        static auto get_xpub(const std::string& bip32_xpub_str)
        {
            const auto hdkey = bip32_public_key_from_bip32_xpub(bip32_xpub_str);
            return make_xpub(hdkey.get());
        }

        static std::string blind_address(
            const session& session, const std::string& addr, const std::string& blinding_key_hex)
        {
            const auto blinded_prefix = session.get_network_parameters().blinded_prefix();
            const auto blinding_key = h2b(blinding_key_hex);
            return confidential_addr_from_addr(addr, blinded_prefix, blinding_key);
        }

        static std::string get_blinded_address(const session& session, const nlohmann::json& addr)
        {
            std::string blinding_key_hex;
            if (addr.contains("blinding_key")) {
                // Use the blinding key provided by the hardware
                blinding_key_hex = addr.at("blinding_key");
            } else {
                // Derive the blinding key from the blinding_script_hash
                auto signer = session.get_nonnull_impl()->get_signer();
                const auto script_hash = h2b(addr.at("blinding_script_hash"));
                blinding_key_hex = b2h(signer->get_blinding_pubkey_from_script(script_hash));
            }
            return blind_address(session, addr["address"], blinding_key_hex);
        }

        static auto get_paths_json(bool include_root = true)
        {
            std::vector<nlohmann::json> paths;
            if (include_root) {
                paths.emplace_back(std::vector<uint32_t>());
            }
            return paths;
        }

        static const auto& get_sized_array(const nlohmann::json& json, const char* key, size_t size)
        {
            const auto& value = json.at(key);
            GDK_RUNTIME_ASSERT(value.is_array() && value.size() == size);
            return value;
        }

        // Add anti-exfil protocol host-entropy and host-commitment to the passed json
        static void add_ae_host_data(nlohmann::json& data)
        {
            // TODO: These values should be identical/re-used if the same data
            // is being signed repeatedly (eg. being re-tried following a failure).
            const auto host_entropy = get_random_bytes<WALLY_S2C_DATA_LEN>();
            const auto host_commitment = ae_host_commit_from_bytes(host_entropy);
            data["ae_host_entropy"] = b2h(host_entropy);
            data["ae_host_commitment"] = b2h(host_commitment);
        }

        // If the hww is populated and supports the AE signing protocol, add
        // the host-entropy and host-commitment fields to the passed json.
        static bool add_required_ae_data(const std::shared_ptr<signer>& signer, nlohmann::json& data)
        {
            const bool using_ae_protocol = signer->get_ae_protocol_support() != ae_protocol_support_level::none;
            data["use_ae_protocol"] = using_ae_protocol;
            if (using_ae_protocol) {
                add_ae_host_data(data);
            }
            return using_ae_protocol;
        }

        // Make a temporary signer for login and register calls
        static std::shared_ptr<signer> make_login_signer(
            const network_parameters& net_params, const nlohmann::json& hw_device, const std::string& mnemonic)
        {
            std::shared_ptr<signer> ret;
            if (hw_device.empty() || hw_device.value("device", nlohmann::json::object()).empty()) {
                ret = std::make_shared<software_signer>(net_params, mnemonic);
            } else {
                const auto& device = hw_device.at("device");
                if (device.value("name", std::string()).empty()) {
                    throw user_error("Hardware device JSON requires a non-empty 'name' element");
                }
                ret = std::make_shared<hardware_signer>(net_params, device);
            }
            if (net_params.is_liquid() && ret->get_liquid_support() == liquid_support_level::none) {
                throw user_error(res::id_the_hardware_wallet_you_are);
            }
            return ret;
        }
    } // namespace

    //
    // Register
    //
    register_call::register_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic)
        : auth_handler_impl(
              session, "get_xpubs", make_login_signer(session.get_network_parameters(), hw_device, mnemonic))
        , m_mnemonic(mnemonic)
    {
        if (m_state != state_type::error) {
            if (m_session.get_network_parameters().is_electrum()) {
                // Register is a no-op for electrum sessions
                m_state = state_type::done;
            } else {
                // To register, we need the master xpub to identify the wallet,
                // and the registration xpub to compute the gait_path.
                m_state = state_type::resolve_code;
                set_data();
                auto paths = get_paths_json();
                paths.emplace_back(std::vector<uint32_t>{ harden(0x4741) });
                m_twofactor_data["paths"] = paths;
            }
        }
    }

    auth_handler::state_type register_call::call_impl()
    {
        const nlohmann::json args = nlohmann::json::parse(m_code);
        const std::vector<std::string> xpubs = args.at("xpubs");
        const auto master_xpub = get_xpub(xpubs.at(0));

        const auto master_chain_code_hex = b2h(master_xpub.first);
        const auto master_pub_key_hex = b2h(master_xpub.second);

        // Get our gait path xpub and compute gait_path from it
        const auto gait_xpub = get_xpub(xpubs.at(1));
        const auto gait_path_hex = b2h(ga_pubkeys::get_gait_path_bytes(gait_xpub));

        const bool supports_csv = m_signer->supports_arbitrary_scripts();
        m_session.register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
        return state_type::done;
    }

    //
    // Login
    //
    class login_call : public auth_handler_impl {
    public:
        login_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic,
            const std::string& password);

    private:
        state_type call_impl() override;

        std::string m_challenge;
        std::string m_master_xpub_bip32;

        // used for 2of2_no_recovery
        std::unordered_map<uint32_t, std::vector<std::string>> m_ca_addrs;
        std::vector<uint32_t> m_ca_reqs;
    };

    login_call::login_call(
        session& session, const nlohmann::json& hw_device, const std::string& mnemonic, const std::string& password)
        : auth_handler_impl(session, "get_xpubs",
              make_login_signer(session.get_network_parameters(), hw_device, decrypt_mnemonic(mnemonic, password)))
    {
        if (m_state != state_type::error) {
            if (m_session.get_network_parameters().is_electrum()) {
                // Electrum sessions do not use a challenge
                m_state = state_type::make_call;
            } else {
                // We first need the challenge, so ask the caller for the master pubkey.
                m_state = state_type::resolve_code;
                set_action("get_xpubs");
                set_data();
                auto paths = get_paths_json();
                paths.emplace_back(signer::CLIENT_SECRET_PATH);
                m_twofactor_data["paths"] = paths;
            }
        }
    }

    auth_handler::state_type login_call::call_impl()
    {
        if (m_action == "get_receive_address") {
            // Blind the address
            auto& addr = m_twofactor_data["address"];
            addr["blinding_key"] = nlohmann::json::parse(m_code).at("blinding_key");

            // save it and pop the request
            m_ca_addrs[m_ca_reqs.back()].emplace_back(get_blinded_address(m_session, addr));
            m_ca_reqs.pop_back();

            // prepare the next one
            if (!m_ca_reqs.empty()) {
                m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_ca_reqs.back() } });
                return state_type::resolve_code;
            }

            // fall-through down to upload them
        } else if (m_action == "get_xpubs") {
            if (m_session.get_network_parameters().is_electrum()) {
                // FIXME: Implement rust login via authenticate()
                m_result = m_session.get_nonnull_impl()->login(m_signer->get_mnemonic(std::string()));
            } else {
                const std::vector<std::string> xpubs = nlohmann::json::parse(m_code).at("xpubs");

                if (m_challenge.empty()) {
                    // Compute the challenge with the master pubkey
                    m_master_xpub_bip32 = xpubs.at(0);
                    const auto btc_version = m_session.get_network_parameters().btc_version();
                    const auto public_key = get_xpub(m_master_xpub_bip32).second;
                    m_challenge = m_session.get_challenge(public_key_to_p2pkh_addr(btc_version, public_key));

                    const auto local_xpub = get_xpub(xpubs.at(1));
                    const bool is_hw_wallet = !m_signer->get_hw_device().empty();
                    m_session.set_local_encryption_keys(local_xpub.second, is_hw_wallet);

                    // Ask the caller to sign the challenge
                    set_action("sign_message");
                    set_data();
                    m_twofactor_data["message"] = CHALLENGE_PREFIX + m_challenge;
                    m_twofactor_data["path"] = signer::LOGIN_PATH;
                    m_use_anti_exfil = add_required_ae_data(m_signer, m_twofactor_data);
                    return state_type::resolve_code;
                }
                // Register the xpub for each of our subaccounts
                m_session.register_subaccount_xpubs(xpubs);
            }
            // fall through to the required_ca check down there...
        } else if (m_action == "sign_message") {
            // If we are using the Anti-Exfil protocol we verify the signature
            const nlohmann::json args = nlohmann::json::parse(m_code);
            if (m_use_anti_exfil) {
                verify_ae_signature(m_twofactor_data["message"], m_master_xpub_bip32, signer::LOGIN_PATH,
                    m_twofactor_data["ae_host_entropy"], args.at("signer_commitment"), args.at("signature"));
            }

            // Log in and set up the session
            m_result = m_session.authenticate(args.at("signature"), "GA", m_master_xpub_bip32, std::string(), m_signer);

            // Ask the caller for the xpubs for each subaccount
            std::vector<nlohmann::json> paths;
            for (const auto& sa : m_session.get_subaccounts()) {
                paths.emplace_back(m_session.get_subaccount_root_path(sa["pointer"]));
            }
            set_action("get_xpubs");
            set_data();
            m_twofactor_data["paths"] = paths;
            return state_type::resolve_code;
        }

        if (m_session.get_network_parameters().is_electrum()) {
            // Skip checking for 2of2_no_recovery confidential address upload
            return state_type::done;
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
            const uint32_t required_ca = sa.value("required_ca", 0);
            if (required_ca > 0) {
                // add the subaccount number (`pointer`) repeated `required_ca` times. we will pop them one at a time
                // and then resolve their blinding keys
                m_ca_reqs.insert(m_ca_reqs.end(), required_ca, sa["pointer"]);
            }
        }

        if (m_ca_reqs.size() > 0) {
            // prepare the first request
            set_action("get_receive_address");
            set_data();
            m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_ca_reqs.back() } });

            return m_session.is_liquid() ? state_type::resolve_code : state_type::make_call;
        }

        return state_type::done;
    }

    //
    // Watch-only login
    //
    class watch_only_login_call : public auth_handler_impl {
    public:
        watch_only_login_call(session& session, const nlohmann::json& credential_data)
            : auth_handler_impl(session, std::string(), std::shared_ptr<signer>())
            , m_credential_data(credential_data)
        {
        }

    private:
        state_type call_impl() override
        {
            try {
                const auto username = m_credential_data.at("username");
                const auto password = m_credential_data.at("password");
                m_result = m_session.login_watch_only(username, password);
            } catch (const std::exception& ex) {
                set_error(res::id_username);
                return state_type::error;
            }
            return state_type::done;
        }

        nlohmann::json m_credential_data;
    };

    //
    // Return a suitable auth handler for all supported login types
    //
    auth_handler* get_login_call(
        session& session, const nlohmann::json& hw_device, const nlohmann::json& credential_data)
    {
        auth_handler* impl;
        if (!hw_device.empty() || credential_data.contains("mnemonic")) {
            const auto mnemonic = json_get_value(credential_data, "mnemonic");
            const auto password = json_get_value(credential_data, "password");
            // FIXME: Allow a "bip39_passphrase" element to enable bip39 logins
            impl = new login_call(session, hw_device, mnemonic, password);
        } else if (credential_data.contains("pin")) {
            const auto pin = credential_data.at("pin");
            const auto pin_data = credential_data.at("pin_data");
            const auto mnemonic = session.mnemonic_from_pin_data(pin, pin_data);
            const auto password = std::string();
            impl = new login_call(session, hw_device, mnemonic, password);
        } else {
            // Assume watch-only
            impl = new watch_only_login_call(session, credential_data);
        }
        return new ga::sdk::auto_auth_handler(impl);
    }

    //
    // Create subaccount
    //
    create_subaccount_call::create_subaccount_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_xpubs")
        , m_details(details)
        , m_subaccount(0)
        , m_remaining_ca_addrs(0)
    {
        if (m_state != state_type::error) {
            try {
                const std::string type = details.at("type");
                m_remaining_ca_addrs = type == "2of2_no_recovery" ? INITIAL_UPLOAD_CA : 0;
                m_subaccount = session.get_next_subaccount(type);
                m_state = state_type::resolve_code;
                set_data();
                auto paths = get_paths_json();
                paths.emplace_back(session.get_subaccount_root_path(m_subaccount));
                m_twofactor_data["paths"] = paths;
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type create_subaccount_call::call_impl()
    {
        const std::string type = m_details.at("type");
        std::string recovery_mnemonic = json_get_value(m_details, "recovery_mnemonic");
        std::string recovery_bip32_xpub = json_get_value(m_details, "recovery_xpub");

        if (type == "2of3") {
            // The user can provide a recovery mnemonic or bip32 xpub; if not,
            // we generate and return a mnemonic for them.
            if (recovery_bip32_xpub.empty()) {
                if (recovery_mnemonic.empty()) {
                    recovery_mnemonic = bip39_mnemonic_from_bytes(get_random_bytes<32>());
                }

                software_signer subsigner(m_session.get_network_parameters(), recovery_mnemonic);
                const uint32_t mnemonic_path[2] = { harden(3), harden(m_subaccount) };
                recovery_bip32_xpub = subsigner.get_bip32_xpub(mnemonic_path);

                m_details["recovery_mnemonic"] = recovery_mnemonic;
                m_details["recovery_xpub"] = recovery_bip32_xpub;
            }
        }

        const nlohmann::json args = nlohmann::json::parse(m_code);
        if (m_action == "get_xpubs") {
            m_master_xpub_bip32 = args.at("xpubs").at(0);
            m_subaccount_xpub = args.at("xpubs").at(1);
            if (type == "2of3") {
                // ask the caller to sign recovery key with login key
                set_action("sign_message");
                set_data();
                m_twofactor_data["message"] = format_recovery_key_message(recovery_bip32_xpub, m_subaccount);
                m_twofactor_data["path"] = signer::LOGIN_PATH;
                m_use_anti_exfil = add_required_ae_data(m_signer, m_twofactor_data);
                return state_type::resolve_code;
            }
            m_result = m_session.create_subaccount(m_details, m_subaccount, m_subaccount_xpub);
        } else if (m_action == "sign_message") {
            // If we are using the Anti-Exfil protocol we verify the signature
            if (m_use_anti_exfil) {
                verify_ae_signature(m_twofactor_data["message"], m_master_xpub_bip32, signer::LOGIN_PATH,
                    m_twofactor_data["ae_host_entropy"], args.at("signer_commitment"), args.at("signature"));
            }

            m_details["recovery_key_sig"] = b2h(ec_sig_from_der(h2b(args.at("signature")), false));
            m_result = m_session.create_subaccount(m_details, m_subaccount, m_subaccount_xpub);
        } else if (m_action == "get_receive_address") {
            auto& addr = m_twofactor_data["address"];
            addr["blinding_key"] = args["blinding_key"];
            m_ca_addrs.emplace_back(get_blinded_address(m_session, addr));
            m_remaining_ca_addrs--;
        }

        if (m_remaining_ca_addrs > 0) {
            set_action("get_receive_address");
            set_data();
            m_twofactor_data["address"] = m_session.get_receive_address({ { "subaccount", m_result["pointer"] } });

            return state_type::resolve_code;
        }

        // we prepared a few addresses, upload them to the backend
        if (m_ca_addrs.size() > 0) {
            m_session.upload_confidential_addresses(m_result["pointer"], m_ca_addrs);
        }

        return state_type::done;
    }

    ack_system_message_call::ack_system_message_call(session& session, const std::string& msg)
        : auth_handler_impl(session, "sign_message")
        , m_message(msg)
    {
        if (m_state != state_type::error) {
            try {
                m_message_info = m_session.get_system_message_info(msg);
                m_use_anti_exfil = m_signer->get_ae_protocol_support() != ae_protocol_support_level::none;
                m_state = state_type::resolve_code;

                // If using Anti-Exfil protocol we need to get the root xpub
                // Otherwise just sign the message
                if (m_use_anti_exfil) {
                    set_action("get_xpubs");
                    set_data();
                    auto paths = get_paths_json();
                    m_twofactor_data["paths"] = paths;
                } else {
                    set_action("sign_message");
                    set_data();
                    m_twofactor_data["message"] = m_message_info.first;
                    m_twofactor_data["path"] = m_message_info.second;
                    add_required_ae_data(m_signer, m_twofactor_data);
                }
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type ack_system_message_call::call_impl()
    {
        const nlohmann::json args = nlohmann::json::parse(m_code);
        if (m_action == "get_xpubs") {
            m_master_xpub_bip32 = args.at("xpubs").at(0);

            set_action("sign_message");
            set_data();
            m_twofactor_data["message"] = m_message_info.first;
            m_twofactor_data["path"] = m_message_info.second;
            add_required_ae_data(m_signer, m_twofactor_data);
            return state_type::resolve_code;
        } else if (m_action == "sign_message") {
            // If we are using the Anti-Exfil protocol we verify the signature
            if (m_use_anti_exfil) {
                verify_ae_signature(m_twofactor_data["message"], m_master_xpub_bip32, m_message_info.second,
                    m_twofactor_data["ae_host_entropy"], args.at("signer_commitment"), args.at("signature"));
            }
            m_session.ack_system_message(m_message_info.first, args.at("signature"));
        }
        return state_type::done;
    }

    //
    // Sign tx
    //
    sign_transaction_call::sign_transaction_call(session& session, const nlohmann::json& tx_details)
        : auth_handler_impl(session, "sign_tx")
    {
        if (m_state == state_type::error) {
            return;
        }
        const auto& net_params = m_session.get_network_parameters();

        try {
            if (json_get_value(tx_details, "is_sweep", false) || net_params.is_electrum()) {
                // TODO: Once tx aggregation is implemented, merge the sweep logic
                // with general tx construction to allow HW devices to sign individual
                // inputs (currently HW expects to sign all tx inputs)
                // FIXME: Sign rust txs using the standard code path
                m_result = m_session.sign_transaction(tx_details);
                m_state = state_type::done;
            } else {
                // Compute the data we need for the hardware to sign the transaction
                m_tx_details = tx_details;
                m_state = state_type::resolve_code;
                set_data();
                m_twofactor_data["transaction"] = tx_details;

                // We use the Anti-Exfil protocol if the hw supports it
                m_use_anti_exfil = get_signer()->get_ae_protocol_support() != ae_protocol_support_level::none;
                m_twofactor_data["use_ae_protocol"] = m_use_anti_exfil;

                // We need the inputs, augmented with types, scripts and paths
                auto signing_inputs = get_ga_signing_inputs(tx_details);
                std::set<std::string> addr_types;
                nlohmann::json prev_txs;
                for (auto& input : signing_inputs) {
                    const auto& addr_type = input.at("address_type");
                    GDK_RUNTIME_ASSERT(!addr_type.empty()); // Must be spendable by us
                    addr_types.insert(addr_type.get<std::string>());

                    // Add host-entropy and host-commitment to each input if using the anti-exfil protocol
                    if (m_use_anti_exfil) {
                        add_ae_host_data(input);
                    }
                }
                if (addr_types.find(address_type::p2pkh) != addr_types.end()) {
                    // TODO: Support mixed/batched sweep transactions with non-sweep inputs
                    GDK_RUNTIME_ASSERT(false);
                }

                if (!net_params.is_liquid()) {
                    // BTC: Provide the previous txs data for validation, even
                    // for segwit, in order to mitigate the segwit fee attack.
                    // (Liquid txs are segwit+explicit fee and so not affected)
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
                // FIXME: Do not duplicate the transaction_outputs in required_data
                m_twofactor_data["transaction_outputs"] = tx_details["transaction_outputs"];
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler::state_type sign_transaction_call::call_impl()
    {
        auto impl = m_session.get_nonnull_impl();

        const auto& net_params = m_session.get_network_parameters();
        const nlohmann::json args = nlohmann::json::parse(m_code);
        const auto& inputs = m_twofactor_data["signing_inputs"];
        const auto& signatures = get_sized_array(args, "signatures", inputs.size());
        const auto& outputs = m_twofactor_data["transaction_outputs"];
        const auto& transaction_details = m_twofactor_data["transaction"];
        const bool is_liquid = net_params.is_liquid();
        const auto tx = tx_from_hex(transaction_details.at("transaction"), tx_flags(is_liquid));

        if (is_liquid) {
            const auto& asset_commitments = get_sized_array(args, "asset_commitments", outputs.size());
            const auto& value_commitments = get_sized_array(args, "value_commitments", outputs.size());
            const auto& abfs = get_sized_array(args, "assetblinders", outputs.size());
            const auto& vbfs = get_sized_array(args, "amountblinders", outputs.size());

            size_t i = 0;
            for (const auto& out : outputs) {
                if (!out.at("is_fee")) {
                    blind_output(*impl, transaction_details, tx, i, out, h2b<33>(asset_commitments[i]),
                        h2b<33>(value_commitments[i]), h2b_rev<32>(abfs[i]), h2b_rev<32>(vbfs[i]));
                }
                ++i;
            }
        }

        // If we are using the Anti-Exfil protocol we verify the signatures
        // TODO: the signer-commitments should be verified as being the same for the
        // same input data and host-entropy (eg. if retrying following failure).
        if (m_use_anti_exfil) {
            // FIXME: User pubkeys is not threadsafe if adding a subaccount
            // at the same time (this cant happen yet but should be allowed
            // in the future).
            auto& user_pubkeys = impl->get_user_pubkeys();
            size_t i = 0;
            const auto& signer_commitments = get_sized_array(args, "signer_commitments", inputs.size());
            for (const auto& utxo : inputs) {
                const auto pubkey = user_pubkeys.derive(utxo.at("subaccount"), utxo.at("pointer"));
                verify_ae_signature(net_params, pubkey, tx, i, utxo, signer_commitments[i], signatures[i]);
                ++i;
            }
        }

        const bool is_low_r = get_signer()->supports_low_r();
        size_t i = 0;
        for (const auto& utxo : inputs) {
            add_input_signature(tx, i, utxo, signatures[i], is_low_r);
            ++i;
        }

        m_result.swap(m_twofactor_data["transaction"]);
        m_result["user_signed"] = true;
        m_result["blinded"] = true;
        update_tx_size_info(tx, m_result);
        return state_type::done;
    }

    //
    // Get receive address
    //
    get_receive_address_call::get_receive_address_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_receive_address")
        , m_details(details)
    {
        if (m_state != state_type::error) {
            try {
                nlohmann::json address = m_session.get_receive_address(details);
                set_data();
                m_twofactor_data["address"] = address;

                // Make the call directly unless we are Liquid and so need to blind
                m_state = m_session.is_liquid() ? state_type::resolve_code : state_type::make_call;
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type get_receive_address_call::call_impl()
    {
        // initially our result is what we generated earlier
        m_result = m_twofactor_data["address"];

        if (m_session.is_liquid() && !m_session.get_network_parameters().is_electrum()) {
            // Liquid: blind the address using the blinding key from the HW
            m_result["blinding_key"] = nlohmann::json::parse(m_code).at("blinding_key");
            m_result["address"] = get_blinded_address(m_session, m_result);
        }

        return state_type::done;
    }

    //
    // Get previous addresses
    //
    get_previous_addresses_call::get_previous_addresses_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_receive_address")
        , m_details(details)
        , m_index(0)
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            const uint32_t subaccount = json_get_value(details, "subaccount", 0);
            const uint32_t last_pointer = json_get_value(details, "last_pointer", 0);
            if (last_pointer == 1) {
                // Prevent a server call if the user iterates until empty results
                m_result = { { "subaccount", subaccount }, { "list", nlohmann::json::array() }, { "last_pointer", 1 } };
                m_state = state_type::done;
                return; // Nothing further to do
            }
            // Fetch the list of previous addresses from the server
            m_result = m_session.get_previous_addresses(subaccount, last_pointer);
            if (!m_session.is_liquid() || m_result["list"].empty()) {
                if (m_result["list"].empty()) {
                    // FIXME: The server returns 0 if there are no addresses generated
                    m_result["last_pointer"] = 1;
                }
                m_state = state_type::done;
                return; // Nothing further to do
            }
            // Otherwise, start iterating to get the blinding keys for each address
            m_state = set_address_to_blind();
        } catch (const std::exception& e) {
            set_error(e.what());
            return;
        }
    }

    auth_handler::state_type get_previous_addresses_call::set_address_to_blind()
    {
        const auto& current = m_result["list"][m_index];
        set_data();
        m_twofactor_data["address"] = current;
        // Ask the HW to provide the blinding key
        return state_type::resolve_code;
    }

    auth_handler::state_type get_previous_addresses_call::call_impl()
    {
        auto& current = m_result["list"][m_index];

        // Liquid: blind the address Using the blinding key from the HW
        current["blinding_key"] = nlohmann::json::parse(m_code).at("blinding_key");
        current["address"] = get_blinded_address(m_session, current);

        ++m_index; // Move to the next address
        if (m_index == m_result["list"].size()) {
            // All addresses have been blinded
            return state_type::done;
        }
        return set_address_to_blind();
    }

    static bool has_unblinded_change(const nlohmann::json& tx)
    {
        for (const auto& it : tx.at("change_address").items()) {
            if (!it.value().value("is_blinded", false)) {
                return true; // At least one change output is unblinded
            }
        }
        return false; // All change ouputs are blinded
    }

    //
    // Create transaction
    //
    create_transaction_call::create_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_transaction")
        , m_details(details)
    {
        if (m_state != state_type::error) {
            try {
                auto tx = m_session.create_transaction(details);
                if (!tx.contains("change_address") || !m_session.is_liquid() || !has_unblinded_change(tx)) {
                    m_result.swap(tx);
                    m_state = state_type::done; // No blinding needed
                } else {
                    // Ask the HW to blind the change address(es)
                    m_state = state_type::resolve_code;
                    set_data();
                    m_twofactor_data["transaction"].swap(tx);
                }
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type create_transaction_call::call_impl()
    {
        const auto blinded_prefix = m_session.get_network_parameters().blinded_prefix();
        const nlohmann::json args = nlohmann::json::parse(m_code);

        // Blind the change addresses
        auto& tx = m_twofactor_data["transaction"];
        for (auto& it : tx.at("change_address").items()) {
            auto& addr = it.value();
            if (!addr.value("is_blinded", false)) {
                addr["blinding_key"] = args.at("blinding_keys").at(it.key());

                auto& address = addr.at("address");
                address = confidential_addr_to_addr(address, blinded_prefix);
                address = get_blinded_address(m_session, addr);
                addr["is_blinded"] = true;
            }
        }

        // Update the transaction
        m_result = m_session.create_transaction(tx);
        return state_type::done;
    }

    //
    // Generic parent for all the other calls that needs the unblinded transactions in order to do their job
    //
    needs_unblind_call::needs_unblind_call(const std::string& name, session& session, const nlohmann::json& details)
        : auth_handler_impl(session, name)
        , m_details(details)
    {
        if (m_state != state_type::error) {
            try {
                if (m_session.is_liquid()) {
                    m_state = state_type::resolve_code;
                    set_data();
                    m_twofactor_data["blinded_scripts"] = m_session.get_blinded_scripts(details);
                } else {
                    m_state = state_type::make_call;
                }
            } catch (const std::exception& e) {
                set_error(e.what());
            }
        }
    }

    auth_handler::state_type needs_unblind_call::call_impl()
    {
        if (m_session.is_liquid()) {
            // Parse and set the nonces we got back
            const nlohmann::json args = nlohmann::json::parse(m_code);
            const auto& blinded_scripts = m_twofactor_data.at("blinded_scripts");
            const auto& nonces = args.at("nonces");
            GDK_RUNTIME_ASSERT(blinded_scripts.size() == nonces.size());

            for (size_t i = 0; i < blinded_scripts.size(); ++i) {
                const auto& it = blinded_scripts[i];
                m_session.set_blinding_nonce(it.at("pubkey"), it.at("script"), nonces[i]);
            }
        }

        return wrapped_call_impl(); // run the actual wrapped call
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
    // Set unspent outputs status
    //
    set_unspent_outputs_status_call::set_unspent_outputs_status_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "set_utxo_status")
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            GDK_RUNTIME_ASSERT(details["list"].is_array());

            nlohmann::json args = details;
            bool seen_frozen = false;

            for (auto& item : args["list"]) {
                auto& status = item["user_status"];
                if (status == "default") {
                    status = 0;
                } else if (status == "frozen") {
                    status = 1;
                    seen_frozen = true;
                } else {
                    GDK_RUNTIME_ASSERT_MSG(false, "Unknown UTXO status");
                }
            }

            m_details = args;

            if (m_state == state_type::request_code) {
                if (!seen_frozen) {
                    // No 2FA needed to un-freeze a UTXO
                    m_state = state_type::make_call;
                } else {
                    m_twofactor_data = { { "list", args["list"] } };
                }
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler::state_type set_unspent_outputs_status_call::call_impl()
    {
        m_result = m_session.set_unspent_outputs_status(m_details, m_twofactor_data);
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
        : auth_handler_impl(session, std::string())
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
                    set_action("set_nlocktime");
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
        : auth_handler_impl(session, "enable_2fa")
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
                    set_action("set_email");
                    m_twofactor_data = { { "address", data } };
                } else {
                    set_action("disable_2fa");
                    if (m_methods.size() > 1) {
                        // If disabling 'method_to_update' will leave other methods enabled, insist
                        // the disable action is confirmed using one of the remaining methods to
                        // prevent the user accidentally leaving the wallet with 2fa enabled that they
                        // can't access
                        const auto being_disabled = std::find(m_methods.begin(), m_methods.end(), method_to_update);
                        GDK_RUNTIME_ASSERT(being_disabled != m_methods.end());
                        m_methods.erase(being_disabled);
                    }
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
        set_action(new_action + m_method);
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
            } else {
                const std::string proxy_code = m_session.auth_handler_request_proxy_code("gauth", m_twofactor_data);
                m_twofactor_data = { { "method", "proxy" }, { "code", proxy_code } };
            }
            // Move to enable the 2fa method
            return on_init_done("enable_");
        }
        if (boost::algorithm::starts_with(m_action, "enable_")) {
            // The user has authorized enabling 2fa (if required), so enable the
            // method using its code (which proves the user got a code from the
            // method being enabled)
            if (m_method_to_update == "gauth") {
                m_session.enable_gauth(m_code, m_gauth_data);
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
    // Update subaccount
    //
    update_subaccount_call::update_subaccount_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "update_subaccount")
        , m_details(details)
    {
        if (m_state != state_type::error) {
            m_state = state_type::make_call;
        }
    }

    auth_handler::state_type update_subaccount_call::call_impl()
    {
        nlohmann::json::const_iterator p;
        const uint32_t subaccount = m_details.value("subaccount", 0);
        if ((p = m_details.find("name")) != m_details.end()) {
            m_session.rename_subaccount(subaccount, p.value());
        }
        if ((p = m_details.find("hidden")) != m_details.end()) {
            m_session.set_subaccount_hidden(subaccount, p.value());
        }
        return state_type::done;
    }

    //
    // Change limits
    //
    change_limits_call::change_limits_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "change_tx_limits")
        , m_limit_details(details)
        , m_is_decrease(m_methods.empty() ? false : m_session.is_spending_limits_decrease(details))
    {
        if (m_state == state_type::error) {
            return;
        }

        try {
            // Transform the details json that is passed in into the json that the api expects
            // The api expects {is_fiat: bool, total: in satoshis, per_tx: not really used}
            // This function takes a full amount json, e.g. {'btc': 1234}
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
        auth_handler_impl::request_code(method);
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
        : auth_handler_impl(session, "remove_account")
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
        : auth_handler_impl(session, "send_raw_tx")
        , m_tx_details(tx_details)
        , m_twofactor_required(!m_methods.empty())
        , m_under_limit(false)
    {
        if (m_state == state_type::error) {
            return;
        }

        const auto& net_params = m_session.get_network_parameters();
        const bool is_liquid = net_params.is_liquid();
        const bool is_electrum = net_params.is_electrum();

        try {
            if (!is_liquid && !is_electrum) {
                const uint64_t limit
                    = m_twofactor_required ? session.get_spending_limits()["satoshi"].get<uint64_t>() : 0;
                const uint64_t satoshi = m_tx_details["satoshi"]["btc"];
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
            auth_handler_impl::request_code(method);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void send_transaction_call::create_twofactor_data()
    {
        const bool is_liquid = m_session.get_network_parameters().is_liquid();
        m_twofactor_data = nlohmann::json::object();
        if (m_twofactor_required && !is_liquid) {
            if (m_bump_amount != 0u) {
                set_action("bump_fee");
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
        const bool is_liquid = m_session.get_network_parameters().is_liquid();
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
    // Request or undo a 2fa reset
    //
    twofactor_reset_call::twofactor_reset_call(
        session& session, const std::string& email, bool is_dispute, bool is_undo)
        : auth_handler_impl(session, is_undo ? "request_undo_reset" : "request_reset")
        , m_reset_email(email)
        , m_is_dispute(is_dispute)
        , m_is_undo(is_undo)
        , m_confirming(false)
    {
        if (m_state != state_type::error) {
            m_state = state_type::make_call;
        }
    }

    auth_handler::state_type twofactor_reset_call::call_impl()
    {
        if (!m_confirming) {
            // Request the reset or undo
            if (m_is_undo) {
                m_result = m_session.request_undo_twofactor_reset(m_reset_email);
            } else {
                m_result = m_session.request_twofactor_reset(m_reset_email);
            }
            // Move on to confirming the reset or undo
            m_confirming = true;
            m_methods = { { "email" } };
            m_method = "email";
            return state_type::resolve_code;
        }
        // Confirm the reset or undo
        if (m_is_undo) {
            m_result = m_session.confirm_undo_twofactor_reset(m_reset_email, m_twofactor_data);
        } else {
            m_result = m_session.confirm_twofactor_reset(m_reset_email, m_is_dispute, m_twofactor_data);
        }
        return state_type::done;
    }

    //
    // Cancel 2fa reset
    //
    twofactor_cancel_reset_call::twofactor_cancel_reset_call(session& session)
        : auth_handler_impl(session, "cancel_reset")
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
        : auth_handler_impl(session, "set_csvtime")
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
        : auth_handler_impl(session, "set_nlocktime")
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
