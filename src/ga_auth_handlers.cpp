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
        // Addresses uploaded after creation of 2of2_no_recovery subaccounts.
        // Note that this is deliberately less than the server default (25) so
        // that the code path to upload on login is always executed/doesn't bitrot.
        static const uint32_t INITIAL_UPLOAD_CA = 20;

        static std::string get_confidential_address(
            const std::string& address, uint32_t prefix, const std::string& blinding_key_hex)
        {
            return confidential_addr_from_addr(address, prefix, h2b(blinding_key_hex));
        }

        static void blind_address(nlohmann::json& addr, uint32_t prefix, const std::string& blinding_key_hex)
        {
            addr["blinding_key"] = blinding_key_hex;
            auto& address = addr.at("address");
            address = get_confidential_address(address, prefix, blinding_key_hex);
            addr["is_blinded"] = true;
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

        static void verify_ae_message(const nlohmann::json& twofactor_data, const std::string& root_bip32_xpub,
            uint32_span_t path, const nlohmann::json& hw_reply)
        {
            const std::string message = twofactor_data.at("message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));

            // Note that you must pass a non-hardened path here; root_bip32_xpub should be
            // the root or last hardened key for this public bip32 derivation to work.
            wally_ext_key_ptr parent = bip32_public_key_from_bip32_xpub(root_bip32_xpub);
            pub_key_t pubkey;
            if (path.empty()) {
                memcpy(pubkey.begin(), parent->pub_key, pubkey.size());
            } else {
                ext_key derived = bip32_public_key_from_parent_path(*parent, path);
                memcpy(pubkey.begin(), derived.pub_key, pubkey.size());
            }

            constexpr bool has_sighash = false;
            verify_ae_signature(pubkey, message_hash, twofactor_data.at("ae_host_entropy"),
                hw_reply.at("signer_commitment"), hw_reply.at("signature"), has_sighash);
        }

        static void encache_blinding_nonces(
            session_impl& session, nlohmann::json& twofactor_data, const nlohmann::json& hw_reply)
        {
            const auto& scripts = twofactor_data.at("scripts");
            const auto& public_keys = twofactor_data.at("public_keys");
            const auto& nonces = hw_reply.at("nonces");

            // Encache the blinding nonces we got back
            bool updated = false;
            for (size_t i = 0; i < scripts.size(); ++i) {
                if (!nonces.at(i).empty()) {
                    updated |= session.set_blinding_nonce(public_keys.at(i), scripts.at(i), nonces.at(i));
                }
            }
            if (updated) {
                session.save_cache();
            }
        }
    } // namespace

    //
    // Register
    //
    register_call::register_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic)
        : auth_handler_impl(session, "register_user", std::shared_ptr<signer>())
        , m_hw_device(hw_device)
        , m_credential_data(mnemonic.empty() ? nlohmann::json() : nlohmann::json({ { "mnemonic", mnemonic } }))
    {
    }

    auth_handler::state_type register_call::call_impl()
    {
        if (!m_signer) {
            // Create our signer
            m_signer = std::make_shared<signer>(m_net_params, m_hw_device, m_credential_data);

            signal_hw_request(hw_request::get_xpubs);
            auto& paths = m_twofactor_data["paths"];
            // We need the master xpub to identify the wallet
            paths.emplace_back(signer::EMPTY_PATH);
            if (!m_net_params.is_electrum()) {
                // For multisig, we need the registration xpub to compute our gait path
                paths.emplace_back(signer::REGISTER_PATH);
            }
            return m_state;
        }

        // We have received our xpubs reply
        const std::vector<std::string> xpubs = get_hw_reply().at("xpubs");

        // Get the master chain code and pubkey
        const auto master_xpub = make_xpub(xpubs.at(0));
        const auto master_chain_code_hex = b2h(master_xpub.first);
        const auto master_pub_key_hex = b2h(master_xpub.second);

        std::string gait_path_hex;
        if (!m_net_params.is_electrum()) {
            // Get our gait path xpub and compute gait_path from it
            const auto gait_xpub = make_xpub(xpubs.at(1));
            gait_path_hex = b2h(ga_pubkeys::get_gait_path_bytes(gait_xpub));
        }

        const bool supports_csv = m_signer->supports_arbitrary_scripts();
        // register_user is actually a no-op for rust sessions, but we call
        // it anyway, to return the wallet_hash_id
        m_result = m_session->register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
        return state_type::done;
    }

    //
    // Login User
    //
    login_user_call::login_user_call(
        session& session, const nlohmann::json& hw_device, const nlohmann::json& credential_data)
        : auth_handler_impl(session, "login_user", std::shared_ptr<signer>())
        , m_hw_device(hw_device)
        , m_credential_data(credential_data)
    {
    }

    auth_handler::state_type login_user_call::call_impl()
    {
        if (!m_signer) {
            if (m_credential_data.contains("pin")) {
                // Login with PIN. Fetch the mnemonic from the pin and pin data
                m_credential_data = { { "mnemonic", m_session->mnemonic_from_pin_data(m_credential_data) } };
            }

            // Create our signer
            auto session_signer = m_session->get_signer();
            decltype(m_signer) new_signer;
            if (m_hw_device.empty() && m_credential_data.empty()) {
                // Request to re-log in with existing credentials
                new_signer = session_signer;
            } else {
                // Initial login, or re-login with credentials given
                new_signer = std::make_shared<signer>(m_net_params, m_hw_device, m_credential_data);
            }

            if (session_signer && session_signer.get() != new_signer.get()) {
                // Re-login: ensure we are doing so with the same login details and HW/SW device
                if (!session_signer->is_compatible_with(new_signer)) {
                    throw user_error("Cannot re-login with different hardware or credentials");
                }
                new_signer = session_signer; // Use the existing, compatible session signer
            } else if (!new_signer) {
                // Re-login: Attempting to re-use credentials without a previous login
                throw user_error("Cannot re-use credentials without a previous login");
            }

            if (new_signer->is_watch_only()) {
                m_result = m_session->login_watch_only(new_signer);
                m_signer = new_signer;
                return state_type::done;
            }

            if (m_net_params.is_electrum()) {
                // FIXME: Implement rust login via authenticate()
                m_result = m_session->login(new_signer);
                m_signer = new_signer;
                return state_type::done;
            }

            // We need master pubkey for the challenge, client secret pubkey for login
            try {
                m_signer = new_signer;
                signal_hw_request(hw_request::get_xpubs);
                auto& paths = m_twofactor_data["paths"];
                paths.emplace_back(signer::EMPTY_PATH);
                paths.emplace_back(signer::CLIENT_SECRET_PATH);
            } catch (const std::exception&) {
                m_signer.reset(); // Allow this code path to re-run if the above throws
                throw;
            }
            return m_state;
        }

        if (m_hw_request == hw_request::get_xpubs && m_challenge.empty()) {
            // We have a result from our first get_xpubs request for the challenge.
            // Compute the challenge with the master pubkey
            const std::vector<std::string> xpubs = get_hw_reply().at("xpubs");

            m_master_bip32_xpub = xpubs.at(0);
            const auto public_key = make_xpub(m_master_bip32_xpub).second;
            m_challenge = m_session->get_challenge(public_key);

            const auto local_xpub = make_xpub(xpubs.at(1));
            m_session->set_local_encryption_keys(local_xpub.second, m_signer);

            // Ask the caller to sign the challenge
            signal_hw_request(hw_request::sign_message);
            m_twofactor_data["message"] = CHALLENGE_PREFIX + m_challenge;
            m_twofactor_data["path"] = signer::LOGIN_PATH;
            m_use_anti_exfil = add_required_ae_data(m_signer, m_twofactor_data);
            return m_state;
        } else if (m_hw_request == hw_request::sign_message) {
            // Caller has signed the challenge
            const auto& hw_reply = get_hw_reply();
            if (m_use_anti_exfil) {
                // Anti-Exfil protocol: verify the signature
                const auto login_bip32_xpub = m_signer->get_bip32_xpub(make_vector(signer::LOGIN_PATH));
                verify_ae_message(m_twofactor_data, login_bip32_xpub, signer::EMPTY_PATH, hw_reply);
            }

            // Log in and set up the session
            m_result = m_session->authenticate(hw_reply.at("signature"), "GA", m_master_bip32_xpub, m_signer);

            // Ask the caller for the xpubs for each subaccount
            std::vector<nlohmann::json> paths;
            for (const auto& sa : m_session->get_subaccounts()) {
                paths.emplace_back(m_session->get_subaccount_root_path(sa["pointer"]));
            }
            signal_hw_request(hw_request::get_xpubs);
            m_twofactor_data["paths"] = paths;
            return m_state;
        } else if (m_hw_request == hw_request::get_xpubs) {
            // Caller has provided the xpubs for each subaccount
            m_session->register_subaccount_xpubs(get_hw_reply().at("xpubs"));

            if (m_signer->is_liquid() && m_signer->supports_host_unblinding()) {
                // Ask the HW device to provide the master blinding key.
                // If we are a software wallet, we already have it, but we
                // use the HW interface to ensure we exercise the same
                // fetching and caching logic.
                signal_hw_request(hw_request::get_master_blinding_key);
                return m_state;
            }
            //
            // Completed Login. FALL THROUGH to check for confidential address upload below
            //
        } else if (m_hw_request == hw_request::get_master_blinding_key) {
            // We either had the master blinding key cached, have fetched it
            // from the HWW, or the user has denied the request (if its blank).
            // Tell the session to cache the key or denial, and add it to
            // our signer if present to allow host unblinding.
            const std::string key_hex = get_hw_reply().at("master_blinding_key");
            m_session->set_cached_master_blinding_key(key_hex);
            //
            // Completed Login. FALL THROUGH to check for confidential address upload below
            //
        } else if (m_hw_request == hw_request::get_blinding_public_keys) {
            // AMP: Caller has provided the blinding keys for confidential address uploading.
            // Blind them and upload the blinded addresses to the server
            const auto prefix = m_net_params.blinded_prefix();
            const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");
            std::map<uint32_t, std::vector<std::string>> addresses_by_subaccount;
            size_t i = 0;
            for (const auto& it : m_addresses) {
                auto address = get_confidential_address(it.at("address"), prefix, public_keys.at(i));
                addresses_by_subaccount[it.at("subaccount")].emplace_back(address);
                ++i;
            }
            for (auto& it : addresses_by_subaccount) {
                m_session->upload_confidential_addresses(it.first, it.second);
            }
            return state_type::done;
        }

        // We are logged in,
        // Check whether we need to upload confidential addresses.
        auto scripts = nlohmann::json::array();
        for (const auto& sa : m_session->get_subaccounts()) {
            const uint32_t required_ca = sa.value("required_ca", 0);
            for (size_t i = 0; i < required_ca; ++i) {
                m_addresses.push_back(m_session->get_receive_address({ { "subaccount", sa["pointer"] } }));
                scripts.push_back(m_addresses.back().at("blinding_script"));
            }
        }
        if (scripts.empty()) {
            // No addresses to upload, so we are done
            return state_type::done;
        }

        // Ask the caller to provide the blinding keys
        signal_hw_request(hw_request::get_blinding_public_keys);
        m_twofactor_data["scripts"] = std::move(scripts);
        return m_state;
    }

    //
    // Create subaccount
    //
    create_subaccount_call::create_subaccount_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_subaccount")
        , m_details(details)
        , m_subaccount(0)
        , m_initialized(false)
    {
    }

    void create_subaccount_call::initialize()
    {
        const std::string type = m_details.at("type");
        m_subaccount = m_session->get_next_subaccount(type);

        if (type == "2of3") {
            // The user can provide a recovery mnemonic or bip32 xpub, but not both
            const std::string recovery_mnemonic = json_get_value(m_details, "recovery_mnemonic");
            const std::string recovery_xpub = json_get_value(m_details, "recovery_xpub");
            if (!(recovery_xpub.empty() ^ recovery_mnemonic.empty())) {
                throw user_error("2of3 accounts require either recovery_mnemonic or recovery_xpub");
            }

            if (recovery_xpub.empty()) {
                const std::vector<uint32_t> mnemonic_path{ harden(3), harden(m_subaccount) };
                const nlohmann::json credentials = { { "mnemonic", recovery_mnemonic } };
                m_details["recovery_xpub"] = signer{ m_net_params, {}, credentials }.get_bip32_xpub(mnemonic_path);
                m_details.erase("recovery_mnemonic");
            }
        }

        signal_hw_request(hw_request::get_xpubs);
        auto& paths = m_twofactor_data["paths"];
        paths.emplace_back(m_session->get_subaccount_root_path(m_subaccount));
    }

    auth_handler::state_type create_subaccount_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        if (m_hw_request == hw_request::get_xpubs) {
            // Caller has provided the xpubs for the new subaccount
            const auto& hw_reply = get_hw_reply();
            m_subaccount_xpub = hw_reply.at("xpubs").at(0);
            if (m_details.at("type") == "2of3") {
                // Ask the caller to sign the recovery key with the login key
                signal_hw_request(hw_request::sign_message);
                m_twofactor_data["message"] = format_recovery_key_message(m_details["recovery_xpub"], m_subaccount);
                m_twofactor_data["path"] = signer::LOGIN_PATH;
                m_use_anti_exfil = add_required_ae_data(m_signer, m_twofactor_data);
                return m_state;
            }
            // Fall through to create the subaccount
        } else if (m_hw_request == hw_request::sign_message) {
            // 2of3 subaccount: Caller has signed the recovery key
            const auto& hw_reply = get_hw_reply();
            if (m_use_anti_exfil) {
                // Anti-Exfil protocol: verify the signature
                auto login_bip32_xpub = m_signer->get_bip32_xpub(make_vector(signer::LOGIN_PATH));
                verify_ae_message(m_twofactor_data, login_bip32_xpub, signer::EMPTY_PATH, hw_reply);
            }

            m_details["recovery_key_sig"] = b2h(ec_sig_from_der(h2b(hw_reply.at("signature")), false));
            // Fall through to create the subaccount
        } else if (m_hw_request == hw_request::get_blinding_public_keys) {
            // AMP: Caller has provided the blinding keys for confidential address uploading: blind them
            const auto prefix = m_net_params.blinded_prefix();
            const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");
            std::vector<std::string> addresses;
            size_t i = 0;
            for (const auto& it : m_addresses) {
                auto address = get_confidential_address(it.at("address"), prefix, public_keys.at(i));
                addresses.emplace_back(std::move(address));
            }
            // Upload the blinded addresses to the server
            m_session->upload_confidential_addresses(m_subaccount, addresses);
            return state_type::done;
        }

        // Create the subaccount
        m_result = m_session->create_subaccount(m_details, m_subaccount, m_subaccount_xpub);
        // Ensure the server created the subaccount number we expected
        GDK_RUNTIME_ASSERT(m_subaccount == m_result.at("pointer"));

        if (m_details.at("type") == "2of2_no_recovery") {
            // AMP: We need to upload confidential addresses, get the keys for blinding
            // TODO: Server support for returning multiple addresses for AMP subaccounts
            auto scripts = nlohmann::json::array();
            for (size_t i = 0; i < INITIAL_UPLOAD_CA; ++i) {
                m_addresses.push_back(m_session->get_receive_address({ { "subaccount", m_subaccount } }));
                scripts.push_back(m_addresses.back().at("blinding_script"));
            }
            signal_hw_request(hw_request::get_blinding_public_keys);
            m_twofactor_data["scripts"] = std::move(scripts);
            return m_state;
        }
        return state_type::done;
    }

    ack_system_message_call::ack_system_message_call(session& session, const std::string& msg)
        : auth_handler_impl(session, "ack_system_message")
        , m_msg(msg)
        , m_initialized(false)
    {
    }

    void ack_system_message_call::initialize()
    {
        m_message_info = m_session->get_system_message_info(m_msg);
        m_use_anti_exfil = m_signer->get_ae_protocol_support() != ae_protocol_support_level::none;

        signal_hw_request(hw_request::sign_message);
        m_twofactor_data["message"] = m_message_info.first;
        m_twofactor_data["path"] = m_message_info.second;
        add_required_ae_data(m_signer, m_twofactor_data);
    }

    auth_handler::state_type ack_system_message_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        const auto& hw_reply = get_hw_reply();
        if (m_use_anti_exfil) {
            const auto master_bip32_xpub = m_signer->get_bip32_xpub(make_vector(signer::EMPTY_PATH));
            verify_ae_message(m_twofactor_data, master_bip32_xpub, m_message_info.second, hw_reply);
        }
        m_session->ack_system_message(m_message_info.first, hw_reply.at("signature"));
        return state_type::done;
    }

    //
    // Sign tx
    //
    sign_transaction_call::sign_transaction_call(session& session, const nlohmann::json& tx_details)
        : auth_handler_impl(session, "sign_transaction")
        , m_tx_details(tx_details)
        , m_initialized(false)
    {
    }

    void sign_transaction_call::initialize()
    {
        if (json_get_value(m_tx_details, "is_sweep", false) || m_net_params.is_electrum()) {
            // TODO: Once tx aggregation is implemented, merge the sweep logic
            // with general tx construction to allow HW devices to sign individual
            // inputs (currently HW expects to sign all tx inputs)
            // FIXME: Sign rust txs using the standard code path
            m_result = m_session->sign_transaction(m_tx_details);
            m_state = state_type::done;
        } else {
            // Compute the data we need for the hardware to sign the transaction
            // We use the Anti-Exfil protocol if the hw supports it
            m_use_anti_exfil = get_signer()->get_ae_protocol_support() != ae_protocol_support_level::none;
            signal_hw_request(hw_request::sign_tx);
            m_twofactor_data["transaction"] = m_tx_details;
            m_twofactor_data["use_ae_protocol"] = m_use_anti_exfil;

            // We need the inputs, augmented with types, scripts and paths
            auto signing_inputs = get_ga_signing_inputs(m_tx_details);
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

            if (!m_net_params.is_liquid()) {
                // BTC: Provide the previous txs data for validation, even
                // for segwit, in order to mitigate the segwit fee attack.
                // (Liquid txs are segwit+explicit fee and so not affected)
                for (const auto& input : signing_inputs) {
                    const std::string txhash = input.at("txhash");
                    if (prev_txs.find(txhash) == prev_txs.end()) {
                        prev_txs.emplace(txhash, m_session->get_transaction_details(txhash).at("transaction"));
                    }
                }
            }
            m_twofactor_data["signing_address_types"] = std::vector<std::string>(addr_types.begin(), addr_types.end());
            m_twofactor_data["signing_inputs"] = signing_inputs;
            m_twofactor_data["signing_transactions"] = prev_txs;
            // FIXME: Do not duplicate the transaction_outputs in required_data
            m_twofactor_data["transaction_outputs"] = m_tx_details["transaction_outputs"];
        }
    }

    auth_handler::state_type sign_transaction_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        const auto& hw_reply = get_hw_reply();
        const auto& inputs = m_twofactor_data["signing_inputs"];
        const auto& signatures = get_sized_array(hw_reply, "signatures", inputs.size());
        const auto& outputs = m_twofactor_data["transaction_outputs"];
        const auto& transaction_details = m_twofactor_data["transaction"];
        const bool is_liquid = m_net_params.is_liquid();
        const auto tx = tx_from_hex(transaction_details.at("transaction"), tx_flags(is_liquid));

        if (is_liquid && get_signer()->is_hardware()) {
            // FIMXE: We skip re-blinding for the internal software signer here,
            // since we have already done it. It should be possible to avoid blinding
            // the tx twice in the general HWW case.
            const auto& asset_commitments = get_sized_array(hw_reply, "asset_commitments", outputs.size());
            const auto& value_commitments = get_sized_array(hw_reply, "value_commitments", outputs.size());
            const auto& abfs = get_sized_array(hw_reply, "assetblinders", outputs.size());
            const auto& vbfs = get_sized_array(hw_reply, "amountblinders", outputs.size());

            size_t i = 0;
            for (const auto& out : outputs) {
                if (!out.at("is_fee")) {
                    blind_output(*m_session, transaction_details, tx, i, out, h2b<33>(asset_commitments[i]),
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
            auto& user_pubkeys = m_session->get_user_pubkeys();
            size_t i = 0;
            const auto& signer_commitments = get_sized_array(hw_reply, "signer_commitments", inputs.size());
            for (const auto& utxo : inputs) {
                const auto pubkey = user_pubkeys.derive(utxo.at("subaccount"), utxo.at("pointer"));
                const auto script_hash = get_script_hash(m_net_params, utxo, tx, i);
                constexpr bool has_sighash = true;
                verify_ae_signature(
                    pubkey, script_hash, utxo.at("ae_host_entropy"), signer_commitments[i], signatures[i], has_sighash);
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
        update_tx_size_info(m_net_params, tx, m_result);
        return state_type::done;
    }

    //
    // Get receive address
    //
    get_receive_address_call::get_receive_address_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_receive_address")
        , m_details(details)
        , m_initialized(false)
    {
    }

    void get_receive_address_call::initialize()
    {
        m_result = m_session->get_receive_address(m_details);

        if (m_net_params.is_liquid() && !m_net_params.is_electrum()) {
            // Ask the caller to provide the blinding key
            signal_hw_request(hw_request::get_blinding_public_keys);
            m_twofactor_data["scripts"].push_back(m_result.at("blinding_script"));
        } else {
            // We are done
            m_state = state_type::done;
        }
    }

    auth_handler::state_type get_receive_address_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // Liquid: blind the address using the blinding key from the caller
        const auto prefix = m_net_params.blinded_prefix();
        blind_address(m_result, prefix, get_hw_reply().at("public_keys").at(0));
        return state_type::done;
    }

    //
    // Get previous addresses
    //
    get_previous_addresses_call::get_previous_addresses_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_previous_addresses")
        , m_details(details)
        , m_initialized(false)
    {
    }

    void get_previous_addresses_call::initialize()
    {
        const uint32_t subaccount = json_get_value(m_details, "subaccount", 0);
        const uint32_t last_pointer = json_get_value(m_details, "last_pointer", 0);
        if (last_pointer == 1) {
            // Prevent a server call if the user iterates until empty results
            m_result = { { "subaccount", subaccount }, { "list", nlohmann::json::array() }, { "last_pointer", 1 } };
            m_state = state_type::done;
            return; // Nothing further to do
        }
        // Fetch the list of previous addresses from the server
        m_result = m_session->get_previous_addresses(subaccount, last_pointer);
        if (!m_net_params.is_liquid() || m_result["list"].empty()) {
            if (m_result["list"].empty()) {
                // FIXME: The server returns 0 if there are no addresses generated
                m_result["last_pointer"] = 1;
            }
            m_state = state_type::done;
            return; // Nothing further to do
        }
        // Otherwise, request the the blinding keys for each address
        signal_hw_request(hw_request::get_blinding_public_keys);
        auto& scripts = m_twofactor_data["scripts"];
        for (const auto& it : m_result.at("list")) {
            scripts.push_back(it.at("blinding_script"));
        }
    }

    auth_handler::state_type get_previous_addresses_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // Liquid: blind the addresses using the blinding key from the HW
        const auto prefix = m_net_params.blinded_prefix();
        const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");
        size_t i = 0;
        for (auto& it : m_result.at("list")) {
            blind_address(it, prefix, public_keys.at(i));
            ++i;
        }
        return state_type::done;
    }

    //
    // Create transaction
    //
    create_transaction_call::create_transaction_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_transaction")
        , m_details(details)
    {
    }

    auth_handler::state_type create_transaction_call::call_impl()
    {
        if (m_result.empty()) {
            // Initial call: Create the transaction from the provided details
            m_result = m_session->create_transaction(m_details);
            return check_change_outputs();
        }

        // Otherwise, we have been called after resolving our blinding keys
        const auto prefix = m_net_params.blinded_prefix();
        const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");

        // Blind any unblinded change addresseses
        size_t i = 0;
        for (auto& it : m_result.at("change_address").items()) {
            auto& addr = it.value();
            if (!addr.value("is_blinded", false)) {
                auto& address = addr.at("address");
                address = confidential_addr_to_addr(address, prefix); // Remove fake blinding
                blind_address(addr, prefix, public_keys.at(i));
                ++i;
            }
        }

        // Update the transaction
        m_result = m_session->create_transaction(m_result);
        return check_change_outputs();
    }

    auth_handler::state_type create_transaction_call::check_change_outputs()
    {
        auto scripts = nlohmann::json::array();

        if (m_net_params.is_liquid()) {
            // Check whether we have any unblinded change outputs
            const auto change_addresses_p = m_result.find("change_address");
            if (change_addresses_p != m_result.end()) {
                for (auto& it : change_addresses_p->items()) {
                    if (!it.value().value("is_blinded", false)) {
                        scripts.push_back(it.value().at("blinding_script"));
                    }
                }
            }
        }

        if (scripts.empty()) {
            // All change outputs are blinded, so we are done
            return state_type::done;
        }
        // We have unblinded change outputs, request the blinding keys
        signal_hw_request(hw_request::get_blinding_public_keys);
        m_twofactor_data.emplace("scripts", std::move(scripts));
        return m_state;
    }

    //
    // Create PSET
    //
    create_pset_call::create_pset_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "create_pset")
        , m_details(details)
    {
    }

    auth_handler::state_type create_pset_call::call_impl()
    {
        if (m_result.empty()) {
            // Initial call: Create PSET from the provided details
            m_result = m_session->create_pset(m_details);
            m_state = state_type::done;
        }

        return m_state;
    }

    //
    // Sign PSET
    //
    sign_pset_call::sign_pset_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "sign_pset")
        , m_details(details)
    {
    }

    auth_handler::state_type sign_pset_call::call_impl()
    {
        if (m_result.empty()) {
            // Initial call: Sign the PSET from the provided details
            m_result = m_session->sign_pset(m_details);
            m_state = state_type::done;
        }

        return m_state;
    }

    //
    // Get subaccounts
    //
    get_subaccounts_call::get_subaccounts_call(session& session)
        : auth_handler_impl(session, "get_subaccounts")
    {
    }

    auth_handler::state_type get_subaccounts_call::call_impl()
    {
        m_result = { { "subaccounts", m_session->get_subaccounts() } };
        return state_type::done;
    }

    //
    // Get subaccount
    //
    get_subaccount_call::get_subaccount_call(session& session, uint32_t subaccount)
        : auth_handler_impl(session, "get_subaccount")
        , m_subaccount(subaccount)
    {
    }

    auth_handler::state_type get_subaccount_call::call_impl()
    {
        m_result = m_session->get_subaccount(m_subaccount);
        return state_type::done;
    }

    //
    // Get transactions
    //
    get_transactions_call::get_transactions_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_transactions")
        , m_details(details)
    {
    }

    auth_handler::state_type get_transactions_call::call_impl()
    {
        if (m_hw_request == hw_request::none && m_net_params.is_liquid() && !m_net_params.is_electrum()) {
            // FIXME: We should not need to fetch all txs before every call
            // TODO: Electrum is skipped here as it does its own unblinding
            nlohmann::json twofactor_data;
            if (m_session->get_uncached_blinding_nonces(m_details, twofactor_data)) {
                // We have missing nonces we need to fetch, request them
                signal_hw_request(hw_request::get_blinding_nonces);
                m_twofactor_data["scripts"].swap(twofactor_data["scripts"]);
                m_twofactor_data["public_keys"].swap(twofactor_data["public_keys"]);
                return m_state;
            }
        }

        if (m_hw_request == hw_request::get_blinding_nonces) {
            // Parse and cache the nonces we got back
            encache_blinding_nonces(*m_session, m_twofactor_data, get_hw_reply());
        }

        m_result = { { "transactions", m_session->get_transactions(m_details) } };
        return state_type::done;
    }

    //
    // Get unspent outputs
    //
    get_unspent_outputs_call::get_unspent_outputs_call(
        session& session, const nlohmann::json& details, const std::string& name)
        : auth_handler_impl(session, name.empty() ? "get_unspent_outputs" : name)
        , m_details(details)
        , m_initialized(false)
    {
    }

    void get_unspent_outputs_call::initialize()
    {
        const uint32_t num_confs = m_details.value("num_confs", 0xff);
        if (num_confs != 0 && num_confs != 1u) {
            set_error("num_confs must be set to 0 or 1");
            return;
        }
        auto p = m_session->get_cached_utxos(m_details.at("subaccount"), num_confs);
        if (p) {
            // Return the cached result, after filtering it
            m_result = *p;
            filter_result(false);
            m_state = state_type::done;
            return;
        }
        unique_pubkeys_and_scripts_t missing;
        auto utxos = m_session->get_unspent_outputs(m_details, missing);
        if (missing.empty()) {
            // All results are unblinded/Don't need unblinding.
            // Encache and return them
            m_session->process_unspent_outputs(utxos);
            m_result["unspent_outputs"].swap(utxos);
            filter_result(true);
            m_state = state_type::done;
            return;
        }
        // Some utxos need unblinding; ask the caller to resolve them
        m_result.swap(utxos);
        signal_hw_request(hw_request::get_blinding_nonces);
        auto& scripts = m_twofactor_data["scripts"];
        auto& public_keys = m_twofactor_data["public_keys"];
        for (const auto& m : missing) {
            public_keys.emplace_back(b2h(m.first));
            scripts.emplace_back(b2h(m.second));
        }
    }

    auth_handler::state_type get_unspent_outputs_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // Parse and cache the nonces we got back
        encache_blinding_nonces(*m_session, m_twofactor_data, get_hw_reply());

        // Unblind the remaining blinded outputs we have nonces for
        // and encache the result
        nlohmann::json utxos;
        m_result.swap(utxos);
        m_session->process_unspent_outputs(utxos);
        m_result["unspent_outputs"].swap(utxos);
        filter_result(true);
        return state_type::done;
    }

    template <typename T> static void filter_utxos(nlohmann::json& outputs, T&& filter)
    {
        for (auto& asset : outputs.items()) {
            if (asset.key() != "error") {
                auto& utxos = asset.value();
                utxos.erase(std::remove_if(utxos.begin(), utxos.end(), filter), utxos.end());
            }
        }
    }

    void get_unspent_outputs_call::filter_result(bool encache)
    {
        if (encache) {
            // Encache the unfiltered results, and set our result to a copy
            // for filtering.
            auto p = m_session->set_cached_utxos(m_details.at("subaccount"), m_details.at("num_confs"), m_result);
            m_result = *p;
        }

        const bool is_liquid = m_net_params.is_liquid();
        auto& outputs = m_result.at("unspent_outputs");
        if (outputs.is_null() || outputs.empty()) {
            // Nothing to filter, return an empty json object
            outputs = nlohmann::json::object();
            return;
        }

        if (is_liquid && m_details.value("confidential", false)) {
            // The user wants only confidential UTXOs, filter out non-confidential
            filter_utxos(outputs, [](const auto& u) { return !u.value("confidential", false); });
        }

        if (m_details.contains("expired_at")) {
            // Return only UTXOs that have expired as at block number 'expired_at'.
            // A UTXO is expired if its nlocktime has been reached; i.e. its
            // nlocktime is less than or equal to the block number in
            // 'expired_at'. Therefore we filter out UTXOs where nlocktime
            // is greater than 'expired_at', or not present (i.e. non-expiring UTXOs)
            const uint32_t at = m_details.at("expired_at");
            constexpr uint32_t max_ = 0xffffffff; // 81716 years from genesis
            filter_utxos(outputs, [at, max_](const auto& u) { return u.value("expiry_height", max_) > at; });
        }

        const amount::value_type dust_limit = m_details.value("dust_limit", 0);
        if (dust_limit != 0) {
            // The user passed a dust limit, filter UTXOs that are below it
            filter_utxos(outputs, [dust_limit](const auto& u) { return u.at("satoshi") <= dust_limit; });
        }

        // Remove any keys that have become empty
        auto&& filter = [](const auto& assets) { return assets.empty(); };
        outputs.erase(std::remove_if(outputs.begin(), outputs.end(), filter), outputs.end());
    }

    //
    // Get balance
    //
    get_balance_call::get_balance_call(session& session, const nlohmann::json& details)
        : get_unspent_outputs_call(session, details, "get_balance")
    {
    }

    auth_handler::state_type get_balance_call::call_impl()
    {
        auto state = get_unspent_outputs_call::call_impl(); // Get UTXOs using parent call
        if (state == state_type::done) {
            compute_balance();
        }
        return state;
    }

    void get_balance_call::compute_balance()
    {
        const bool is_liquid = m_net_params.is_liquid();
        const auto policy_asset = is_liquid ? m_net_params.policy_asset() : std::string("btc");

        // Compute the balance data from returned UTXOs
        nlohmann::json balance({ { policy_asset, 0 } });

        for (const auto& asset : m_result["unspent_outputs"].items()) {
            if (asset.key() == "error") {
                // TODO: Should we return whether an unblinding error occurred
                // when computing the balance?
                continue;
            }
            amount::value_type satoshi = 0;
            for (const auto& utxo : asset.value()) {
                GDK_RUNTIME_ASSERT(!utxo.contains("error"));
                satoshi += amount::value_type(utxo.at("satoshi"));
            }
            balance[asset.key()] = satoshi;
        }
        m_result.swap(balance); // Return balance data to caller
    }

    //
    // Set unspent outputs status
    //
    set_unspent_outputs_status_call::set_unspent_outputs_status_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "set_unspent_output_status")
        , m_details(details)
        , m_initialized(false)
    {
    }

    void set_unspent_outputs_status_call::initialize()
    {
        GDK_RUNTIME_ASSERT(m_details.at("list").is_array());
        bool seen_frozen = false;

        for (auto& item : m_details["list"]) {
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

        if (seen_frozen) {
            // 2FA only needed to un-freeze a UTXO
            signal_2fa_request("set_utxo_status");
            m_twofactor_data = { { "list", m_details["list"] } };
        }
    }

    auth_handler::state_type set_unspent_outputs_status_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        m_result = m_session->set_unspent_outputs_status(m_details, m_twofactor_data);
        return state_type::done;
    }

    //
    // Change settings
    //
    change_settings_call::change_settings_call(session& session, const nlohmann::json& settings)
        : auth_handler_impl(session, "change_settings")
        , m_settings(settings)
        , m_initialized(false)
    {
    }

    void change_settings_call::initialize()
    {
        const auto nlocktime_p = m_settings.find("nlocktime");
        if (nlocktime_p != m_settings.end()) {
            const uint64_t new_nlocktime = nlocktime_p->get<uint64_t>();
            const uint64_t current_nlocktime = m_session->get_settings()["nlocktime"];
            if (new_nlocktime != current_nlocktime) {
                m_nlocktime_value = { { "value", new_nlocktime } };

                signal_2fa_request("set_nlocktime");
                m_twofactor_data = m_nlocktime_value;
            }
        }
    }

    auth_handler::state_type change_settings_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        m_session->change_settings(m_settings);
        if (!m_nlocktime_value.is_null()) {
            m_session->set_nlocktime(m_nlocktime_value, m_twofactor_data);
        }
        return state_type::done;
    }

    //
    // Enable 2FA
    //
    change_settings_twofactor_call::change_settings_twofactor_call(
        session& session, const std::string& method_to_update, const nlohmann::json& details)
        : auth_handler_impl(session, "change_settings_twofactor")
        , m_method_to_update(method_to_update)
        , m_details(details)
        , m_enabling(m_details.value("enabled", true))
        , m_initialized(false)
    {
    }

    void change_settings_twofactor_call::initialize()
    {
        m_current_config = m_session->get_twofactor_config();
        const auto& current_subconfig = m_current_config.at(m_method_to_update);

        const bool set_email = !m_enabling && m_method_to_update == "email" && m_details.value("confirmed", false)
            && !current_subconfig.value("confirmed", false);

        if (!set_email && current_subconfig.value("enabled", !m_enabling) == m_enabling) {
            // Caller is attempting to enable or disable when thats already the current state
            set_error(m_method_to_update + " is already " + (m_enabling ? "enabled" : "disabled"));
            return;
        }

        // The data associated with m_method_to_update e.g. email, phone etc
        const std::string data = json_get_value(m_details, "data");

        if (m_enabling) {
            signal_2fa_request("enable_2fa");
            if (m_method_to_update == "gauth") {
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
                signal_2fa_request("set_email");
                m_twofactor_data = { { "address", data } };
            } else {
                signal_2fa_request("disable_2fa");
                if (m_methods && m_methods->size() > 1) {
                    // If disabling 'm_method_to_update' will leave other methods enabled, insist
                    // the disable action is confirmed using one of the remaining methods to
                    // prevent the user accidentally leaving the wallet with 2fa enabled that they
                    // can't access
                    const auto being_disabled = std::find(m_methods->begin(), m_methods->end(), m_method_to_update);
                    GDK_RUNTIME_ASSERT(being_disabled != m_methods->end());
                    m_methods->erase(being_disabled);
                }
                m_twofactor_data = { { "method", m_method_to_update } };
            }
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
        m_gauth_data = m_twofactor_data;
        signal_2fa_request(new_action + m_method);
        m_methods.reset(new std::vector<std::string>({ { m_method_to_update } }));
        // Move to prompt the user for the code for the method they are enabling
        return state_type::resolve_code;
    }

    auth_handler::state_type change_settings_twofactor_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        if (m_action == "set_email") {
            const std::string data = json_get_value(m_details, "data");
            m_session->set_email(data, m_twofactor_data);
            // Move to activate email
            return on_init_done("activate_");
        }
        if (m_action == "activate_email") {
            m_session->activate_email(m_code);
            return state_type::done;
        }
        if (m_action == "enable_2fa") {
            if (m_method_to_update != "gauth") {
                // gauth doesn't have an init_enable step
                const std::string data = json_get_value(m_details, "data");
                m_auth_data = m_session->init_enable_twofactor(m_method_to_update, data, m_twofactor_data);
            } else {
                const std::string proxy_code = m_session->auth_handler_request_proxy_code("gauth", m_twofactor_data);
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
                m_session->enable_gauth(m_code, m_gauth_data);
            } else {
                m_session->enable_twofactor(m_method_to_update, m_code);
            }
            return state_type::done;
        }
        if (m_action == "disable_2fa") {
            m_session->disable_twofactor(m_method_to_update, m_twofactor_data);
            // For gauth, we must reset the sessions 2fa data since once it is
            // disabled, the server must create a new secret (which it only
            // does on fetching 2fa config). Without this a subsequent re-enable
            // will fail.
            // FIXME: The server should return the new secret/the user should be
            // able to supply their own
            const bool reset_cached = m_method_to_update == "gauth";
            m_result = m_session->get_twofactor_config(reset_cached).at(m_method_to_update);
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
    }

    auth_handler::state_type update_subaccount_call::call_impl()
    {
        nlohmann::json::const_iterator p;
        const uint32_t subaccount = m_details.value("subaccount", 0);
        if ((p = m_details.find("name")) != m_details.end()) {
            m_session->rename_subaccount(subaccount, p.value());
        }
        if ((p = m_details.find("hidden")) != m_details.end()) {
            m_session->set_subaccount_hidden(subaccount, p.value());
        }
        return state_type::done;
    }

    //
    // Change limits
    //
    change_limits_call::change_limits_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "twofactor_change_limits")
        , m_limit_details(details)
        , m_initialized(false)
    {
    }

    auth_handler::state_type change_limits_call::call_impl()
    {
        if (!m_initialized) {
            // Transform the details json that is passed in into the json that the api expects
            // The api expects {is_fiat: bool, total: in satoshis, per_tx: not really used}
            // This function takes a full amount json, e.g. {'btc': 1234}
            auto details = m_limit_details;
            const bool is_fiat = details.at("is_fiat").get<bool>();
            GDK_RUNTIME_ASSERT(is_fiat == (details.find("fiat") != details.end()));
            m_limit_details = { { "is_fiat", is_fiat }, { "per_tx", 0 } };
            if (is_fiat) {
                m_limit_details["total"] = amount::get_fiat_cents(details["fiat"]);
            } else {
                m_limit_details["total"] = m_session->convert_amount(details)["satoshi"];
            }

            if (!m_session->is_spending_limits_decrease(details)) {
                // Limit increases require 2fa
                signal_2fa_request("change_tx_limits");
                m_twofactor_data = m_limit_details;
            }
            m_initialized = true;
            return m_state;
        }

        m_session->change_settings_limits(m_limit_details, m_twofactor_data);
        m_result = m_session->get_spending_limits();
        return state_type::done;
    }

    //
    // Remove account
    //
    remove_account_call::remove_account_call(session& session)
        : auth_handler_impl(session, "remove_account")
        , m_initialized(false)
    {
    }

    auth_handler::state_type remove_account_call::call_impl()
    {
        if (!m_initialized) {
            signal_2fa_request("remove_account");
            m_initialized = true;
            return m_state;
        }
        m_session->remove_account(m_twofactor_data);
        return state_type::done;
    }

    //
    // Send transaction
    //
    send_transaction_call::send_transaction_call(session& session, const nlohmann::json& tx_details)
        : auth_handler_impl(session, "send_transaction")
        , m_tx_details(tx_details)
        , m_bump_amount(0)
        , m_twofactor_required(false)
        , m_under_limit(false)
        , m_initialized(false)
    {
    }

    void send_transaction_call::initialize()
    {
        signal_2fa_request("send_raw_tx");
        m_twofactor_required = m_state == state_type::request_code;

        if (!m_net_params.is_liquid() && !m_net_params.is_electrum()) {
            const uint64_t limit
                = m_twofactor_required ? m_session->get_spending_limits()["satoshi"].get<uint64_t>() : 0;
            const uint64_t satoshi = m_tx_details.at("satoshi").at("btc");
            const uint64_t fee = m_tx_details.at("fee");
            const uint32_t change_index = m_tx_details.at("change_index").at("btc");

            m_limit_details = { { "asset", "BTC" }, { "amount", satoshi + fee }, { "fee", fee },
                { "change_idx", change_index == NO_CHANGE_INDEX ? -1 : static_cast<int>(change_index) } };

            // If this transaction has a previous transaction, i.e. it is replacing a previous transaction
            // for example by RBF, then define m_bump_amount as the additional cost of this transaction
            // compared to the original
            const auto previous_transaction = m_tx_details.find("previous_transaction");
            if (previous_transaction != m_tx_details.end()) {
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
        m_twofactor_data = nlohmann::json::object();
        if (m_twofactor_required && !m_net_params.is_liquid()) {
            if (m_bump_amount != 0u) {
                signal_2fa_request("bump_fee");
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
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        if (!m_net_params.is_liquid()) {
            // The api requires the request and action data to differ, which is non-optimal
            json_rename_key(m_twofactor_data, "fee", "send_raw_tx_fee");
            json_rename_key(m_twofactor_data, "change_idx", "send_raw_tx_change_idx");

            const char* amount_key = m_bump_amount != 0u ? "bump_fee_amount" : "send_raw_tx_amount";
            json_rename_key(m_twofactor_data, "amount", amount_key);
        }

        // TODO: Add the recipient to twofactor_data for more server verification
        m_result = m_session->send_transaction(m_tx_details, m_twofactor_data);
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
    }

    auth_handler::state_type twofactor_reset_call::call_impl()
    {
        if (!m_confirming) {
            // Request the reset or undo
            if (m_is_undo) {
                m_result = m_session->request_undo_twofactor_reset(m_reset_email);
            } else {
                m_result = m_session->request_twofactor_reset(m_reset_email);
            }
            // Move on to confirming the reset or undo
            m_confirming = true;
            // Only the email given can be used to confirm, so enable email
            // as the only choice and move to the resolve_code state.
            m_methods.reset(new std::vector<std::string>({ { "email" } }));
            signal_2fa_request(m_is_undo ? "request_undo_reset" : "request_reset");
            m_method = "email";
            return state_type::resolve_code;
        }
        // Confirm the reset or undo
        if (m_is_undo) {
            m_result = m_session->confirm_undo_twofactor_reset(m_reset_email, m_twofactor_data);
        } else {
            m_result = m_session->confirm_twofactor_reset(m_reset_email, m_is_dispute, m_twofactor_data);
        }
        return state_type::done;
    }

    //
    // Cancel 2fa reset
    //
    twofactor_cancel_reset_call::twofactor_cancel_reset_call(session& session)
        : auth_handler_impl(session, "twofactor_cancel_reset")
        , m_initialized(false)
    {
    }

    auth_handler::state_type twofactor_cancel_reset_call::call_impl()
    {
        if (!m_initialized) {
            signal_2fa_request("cancel_reset");
            m_initialized = true;
            return m_state;
        }
        m_result = m_session->cancel_twofactor_reset(m_twofactor_data);
        return state_type::done;
    }

    //
    // Set nlocktime/csvtime
    //
    locktime_call::locktime_call(session& session, const nlohmann::json& params, bool is_csv)
        : auth_handler_impl(session, is_csv ? "set_csvtime" : "set_nlocktime")
        , m_params(params)
        , m_initialized(false)
    {
    }

    auth_handler::state_type locktime_call::call_impl()
    {
        if (!m_initialized) {
            signal_2fa_request(m_action);
            m_twofactor_data = { { "value", m_params.at("value") } };
            m_initialized = true;
            return m_state;
        }
        if (m_action == "set_csvtime") {
            m_session->set_csvtime(m_params, m_twofactor_data);
        } else {
            m_session->set_nlocktime(m_params, m_twofactor_data);
        }
        return state_type::done;
    }
} // namespace sdk
} // namespace ga
