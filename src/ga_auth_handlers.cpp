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
#include "signer.hpp"
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

        // UTXO user_status values from the Green server
        static constexpr uint32_t USER_STATUS_DEFAULT = 0;
        static constexpr uint32_t USER_STATUS_FROZEN = 1;

        static const auto& get_sized_array(const nlohmann::json& json, const char* key, size_t size)
        {
            const auto& value = json.at(key);
            GDK_RUNTIME_ASSERT_MSG(value.is_array() && value.size() == size,
                std::string(key) + " must be an array of length " + std::to_string(size));
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

        // Remove keys added by add_ae_host_data()
        static void remove_ae_host_data(nlohmann::json& data)
        {
            data.erase("ae_host_entropy");
            data.erase("ae_host_commitment");
        }

        // If the hww is populated and supports the AE signing protocol, add
        // the host-entropy and host-commitment fields to the passed json.
        static bool add_required_ae_data(const std::shared_ptr<signer>& signer, nlohmann::json& data)
        {
            const bool using_ae_protocol = signer->use_ae_protocol();
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

        static void set_blinding_nonce_request_data(const std::shared_ptr<signer>& signer,
            const unique_pubkeys_and_scripts_t& missing, nlohmann::json& twofactor_data)
        {
            twofactor_data["blinding_keys_required"] = !signer->has_master_blinding_key();
            auto& scripts = twofactor_data["scripts"];
            auto& public_keys = twofactor_data["public_keys"];
            for (const auto& m : missing) {
                public_keys.emplace_back(b2h(m.first));
                scripts.emplace_back(b2h(m.second));
            }
        }

        static void encache_blinding_data(
            session_impl& session, nlohmann::json& twofactor_data, const nlohmann::json& hw_reply)
        {
            const auto& scripts = twofactor_data.at("scripts");
            const auto& public_keys = twofactor_data.at("public_keys");
            const auto& nonces = get_sized_array(hw_reply, "nonces", scripts.size());
            const auto blinding_pubkeys_p = hw_reply.find("public_keys");
            const bool have_blinding_pubkeys = blinding_pubkeys_p != hw_reply.end();
            if (have_blinding_pubkeys) {
                get_sized_array(hw_reply, "public_keys", scripts.size()); // Must be a sized array if given
            }
            std::string blinding_pubkey_hex;

            // Encache the blinding nonces and any blinding pubkeys
            bool updated = false;
            for (size_t i = 0; i < scripts.size(); ++i) {
                const std::string nonce = nonces.at(i);
                if (!nonce.empty()) {
                    if (have_blinding_pubkeys) {
                        blinding_pubkey_hex = blinding_pubkeys_p->at(i);
                    }
                    updated
                        |= session.encache_blinding_data(public_keys.at(i), scripts.at(i), nonce, blinding_pubkey_hex);
                }
            }
            if (updated) {
                session.save_cache();
            }
        }

        class upload_ca_handler : public auth_handler_impl {
        public:
            upload_ca_handler(session& session, uint32_t subaccount, size_t num_addrs);
            void add_request(uint32_t subaccount, size_t num_addrs);

        private:
            state_type call_impl() override;

            std::vector<std::pair<uint32_t, size_t>> m_required_addrs;
            size_t m_num_required_addrs;
            size_t m_num_generated_addrs;
            bool m_is_blinded;
            std::map<uint32_t, std::vector<nlohmann::json>> m_addresses;
        };

        upload_ca_handler::upload_ca_handler(session& session, uint32_t subaccount, size_t num_addrs)
            : auth_handler_impl(session, "upload_confidential_addrs")
            , m_num_required_addrs(0)
            , m_num_generated_addrs(0)
            , m_is_blinded(false)
        {
            add_request(subaccount, num_addrs);
        }

        void upload_ca_handler::add_request(uint32_t subaccount, size_t num_addrs)
        {
            GDK_RUNTIME_ASSERT(num_addrs);
            m_required_addrs.emplace_back(std::make_pair(subaccount, num_addrs));
            m_num_required_addrs += num_addrs;
        }

        auth_handler::state_type upload_ca_handler::call_impl()
        {
            if (m_num_generated_addrs < m_num_required_addrs) {
                // Generate addresses to blind and upload, in a restartable fashion
                // TODO: Server support for returning multiple addresses for AMP subaccounts
                for (const auto& req : m_required_addrs) {
                    auto& generated = m_addresses[req.first];
                    generated.reserve(req.second);
                    while (generated.size() < req.second) {
                        generated.emplace_back(m_session->get_receive_address({ { "subaccount", req.first } }));
                        ++m_num_generated_addrs;
                    }
                }
            }

            if (m_hw_request == hw_request::none) {
                // We haven't asked the signer to blind the addresses; do so now
                nlohmann::json::array_t scripts;
                scripts.reserve(m_num_required_addrs);
                for (const auto& subaccount_addresses : m_addresses) {
                    for (const auto& addr : subaccount_addresses.second) {
                        scripts.push_back(addr.at("blinding_script"));
                    }
                }
                signal_hw_request(hw_request::get_blinding_public_keys);
                m_twofactor_data["scripts"] = std::move(scripts);
                return m_state;
            }

            // The signer has provided the blinding keys for our address.
            GDK_RUNTIME_ASSERT(m_hw_request == hw_request::get_blinding_public_keys);

            if (!m_is_blinded) {
                // Blind our addresses with the signer provided blinding keys
                const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");
                GDK_RUNTIME_ASSERT(public_keys.size() == m_num_required_addrs);

                size_t i = 0;
                for (auto& subaccount_addresses : m_addresses) {
                    for (auto& addr : subaccount_addresses.second) {
                        blind_address(m_net_params, addr, public_keys.at(i));
                        ++i;
                    }
                }
                m_is_blinded = true;
            }

            while (!m_addresses.empty()) {
                auto subaccount_addresses = m_addresses.begin();
                std::vector<std::string> addresses;
                addresses.reserve(subaccount_addresses->second.size());
                for (const auto& addr : subaccount_addresses->second) {
                    addresses.push_back(addr.at("address"));
                }
                const auto subaccount = subaccount_addresses->first;
                m_session->upload_confidential_addresses(subaccount, addresses);
                m_addresses.erase(subaccount_addresses);
            }
            return state_type::done;
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
        const bool is_electrum = m_net_params.is_electrum();

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
                m_result = m_session->login_wo(new_signer);
                m_signer = new_signer;
                return state_type::done;
            }

            m_signer = new_signer;
            if (is_electrum) {
                if (m_net_params.is_liquid()) {
                    // FIXME: Implement rust liquid login via authenticate()
                    m_result = m_session->login(new_signer);
                    return state_type::done;
                }
            }

            // We need master pubkey for the challenge, client secret pubkey for login
            try {
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

        if (m_hw_request == hw_request::get_xpubs && m_master_bip32_xpub.empty()) {
            GDK_RUNTIME_ASSERT(m_challenge.empty());

            // We have a result from our first get_xpubs request.
            const std::vector<std::string> xpubs = get_hw_reply().at("xpubs");

            m_master_bip32_xpub = xpubs.at(0);
            if (!is_electrum) {
                // Compute the login challenge with the master pubkey
                const auto public_key = make_xpub(m_master_bip32_xpub).second;
                m_challenge = m_session->get_challenge(public_key);
            }

            // Set the cache keys for the wallet, loading/creating the
            // local cache as needed.
            const auto local_xpub = make_xpub(xpubs.at(1));
            m_session->set_local_encryption_keys(local_xpub.second, m_signer);

            if (is_electrum) {
                // Skip the challenge/response steps since we have no server
                // to authenticate to.
                goto do_authenticate;
            }

            // Ask the caller to sign the challenge
            signal_hw_request(hw_request::sign_message);
            m_twofactor_data["message"] = CHALLENGE_PREFIX + m_challenge;
            m_twofactor_data["path"] = signer::LOGIN_PATH;
            add_required_ae_data(m_signer, m_twofactor_data);
            return m_state;
        } else if (m_hw_request == hw_request::sign_message) {
            // Caller has signed the challenge
        do_authenticate:
            std::string sig_der_hex;

            if (!is_electrum) {
                const auto& hw_reply = get_hw_reply();
                if (m_signer->use_ae_protocol()) {
                    // Anti-Exfil protocol: verify the signature
                    const auto login_bip32_xpub = m_signer->get_bip32_xpub(make_vector(signer::LOGIN_PATH));
                    verify_ae_message(m_twofactor_data, login_bip32_xpub, signer::EMPTY_PATH, hw_reply);
                }
                sig_der_hex = hw_reply.at("signature");
            }
            // Log in and set up the session
            m_result = m_session->authenticate(sig_der_hex, "GA", m_master_bip32_xpub, m_signer);

            if (m_signer->is_liquid()) {
                if (m_signer->supports_host_unblinding()) {
                    // Ask the HW device to provide the master blinding key.
                    // If we are a software wallet, we already have it, but we
                    // use the HW interface to ensure we exercise the same
                    // fetching and caching logic.
                    signal_hw_request(hw_request::get_master_blinding_key);
                    return m_state;
                } else {
                    GDK_RUNTIME_ASSERT_MSG(!is_electrum, "HWW must support host unblinding for singlesig wallets");
                }
            }

            return request_subaccount_xpubs();
        } else if (m_hw_request == hw_request::get_master_blinding_key) {
            // We either had the master blinding key cached, have fetched it
            // from the HWW, or the user has denied the request (if its blank).
            // Tell the session to cache the key or denial, and add it to
            // our signer if present to allow host unblinding.
            const std::string key_hex = get_hw_reply().at("master_blinding_key");
            m_session->set_cached_master_blinding_key(key_hex);

            return request_subaccount_xpubs();
        } else if (m_hw_request == hw_request::get_xpubs) {
            // Caller has provided the xpubs for each subaccount
            const std::vector<std::string> xpubs = get_hw_reply().at("xpubs");
            m_session->register_subaccount_xpubs(m_subaccount_pointers, xpubs);

            //
            // Completed Login. FALL THROUGH for post-login processing
            //
        }

        // We are logged in
        if (is_electrum) {
            m_session->start_sync_threads();
            return state_type::done;
        }

        // Check whether we need to upload confidential addresses.
        std::unique_ptr<upload_ca_handler> handler_p;
        for (const auto& sa : m_session->get_subaccounts()) {
            const size_t required_ca = sa.value("required_ca", 0);
            if (required_ca) {
                const uint32_t subaccount = sa["pointer"];
                if (!handler_p) {
                    handler_p.reset(new upload_ca_handler(m_session_parent, subaccount, required_ca));
                } else {
                    handler_p->add_request(subaccount, required_ca);
                }
            }
        }
        if (handler_p) {
            add_next_handler(handler_p.release());
        }
        return state_type::done;
    }

    auth_handler::state_type login_user_call::request_subaccount_xpubs()
    {
        // Ask the caller for the xpubs for each subaccount
        m_subaccount_pointers = m_session->get_subaccount_pointers();

        std::vector<nlohmann::json> paths;
        paths.reserve(m_subaccount_pointers.size());
        for (const auto& pointer : m_subaccount_pointers) {
            paths.emplace_back(m_session->get_subaccount_root_path(pointer));
        }
        signal_hw_request(hw_request::get_xpubs);
        m_twofactor_data["paths"] = paths;
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
        m_session->ensure_full_session();

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
                add_required_ae_data(get_signer(), m_twofactor_data);
                return m_state;
            }
            // Fall through to create the subaccount
        } else if (m_hw_request == hw_request::sign_message) {
            // 2of3 subaccount: Caller has signed the recovery key
            auto signer = get_signer();
            const auto& hw_reply = get_hw_reply();
            if (signer->use_ae_protocol()) {
                // Anti-Exfil protocol: verify the signature
                auto login_bip32_xpub = signer->get_bip32_xpub(make_vector(signer::LOGIN_PATH));
                verify_ae_message(m_twofactor_data, login_bip32_xpub, signer::EMPTY_PATH, hw_reply);
            }

            m_details["recovery_key_sig"] = b2h(ec_sig_from_der(h2b(hw_reply.at("signature")), false));
            // Fall through to create the subaccount
        }

        // Create the subaccount
        m_result = m_session->create_subaccount(m_details, m_subaccount, m_subaccount_xpub);
        // Ensure the server created the subaccount number we expected
        GDK_RUNTIME_ASSERT(m_subaccount == m_result.at("pointer"));

        if (m_details.at("type") == "2of2_no_recovery") {
            // Push a handler to upload confidential addresses
            add_next_handler(new upload_ca_handler(m_session_parent, m_subaccount, INITIAL_UPLOAD_CA));
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
        m_session->ensure_full_session();

        m_message_info = m_session->get_system_message_info(m_msg);

        signal_hw_request(hw_request::sign_message);
        m_twofactor_data["message"] = m_message_info.first;
        m_twofactor_data["path"] = m_message_info.second;
        add_required_ae_data(get_signer(), m_twofactor_data);
    }

    auth_handler::state_type ack_system_message_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        const auto& hw_reply = get_hw_reply();
        auto signer = get_signer();
        if (signer->use_ae_protocol()) {
            const auto master_bip32_xpub = signer->get_bip32_xpub(make_vector(signer::EMPTY_PATH));
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
        if (!m_twofactor_data.contains("signing_inputs")) {
            // Compute the data we need for the hardware to sign the transaction
            signal_hw_request(hw_request::sign_tx);
            m_twofactor_data["transaction"] = m_tx_details;

            // We need the inputs, augmented with types, scripts and paths
            auto signing_inputs = get_ga_signing_inputs(m_tx_details);
            for (auto& input : signing_inputs) {
                const auto& addr_type = input.at("address_type");
                // FIXME: Allow including inputs that are not spendable by us,
                // and that include sweep outouts
                GDK_RUNTIME_ASSERT(!addr_type.empty()); // Must be spendable by us
                // TODO: Support mixed/batched sweep transactions with non-sweep inputs
                GDK_RUNTIME_ASSERT(!input.contains("private_key"));
            }

            // FIXME: Do not duplicate the transaction_outputs in required_data
            m_twofactor_data["transaction_outputs"] = m_tx_details["transaction_outputs"];
            m_twofactor_data["signing_inputs"] = std::move(signing_inputs);
        }
    }

    void sign_transaction_call::set_signer_data(const std::shared_ptr<signer>& signer)
    {
        // We use the Anti-Exfil protocol if the hw supports it
        const bool use_ae_protocol = signer->use_ae_protocol();
        m_twofactor_data["use_ae_protocol"] = use_ae_protocol;

        for (auto& input : m_twofactor_data["signing_inputs"]) {
            const auto& addr_type = input.at("address_type");
            GDK_RUNTIME_ASSERT(!addr_type.empty()); // Must be spendable by us
            // TODO: Support mixed/batched sweep transactions with non-sweep inputs
            GDK_RUNTIME_ASSERT(!input.contains("private_key"));

            // Add host-entropy and host-commitment to each input if using the anti-exfil protocol
            if (use_ae_protocol) {
                add_ae_host_data(input);
            } else {
                remove_ae_host_data(input);
            }
        }

        if (!signer->is_remote() && !m_twofactor_data.contains("signing_transactions")) {
            nlohmann::json prev_txs;
            if (!m_net_params.is_liquid()) {
                // BTC: Provide the previous txs data for validation, even
                // for segwit, in order to mitigate the segwit fee attack.
                // (Liquid txs are segwit+explicit fee and so not affected)
                for (const auto& input : m_twofactor_data["signing_inputs"]) {
                    const std::string txhash = input.at("txhash");
                    if (!prev_txs.contains(txhash)) {
                        auto prev_tx = m_session->get_raw_transaction_details(txhash);
                        prev_txs.emplace(txhash, tx_to_hex(prev_tx));
                    }
                }
            }
            m_twofactor_data["signing_transactions"] = std::move(prev_txs);
        }
    }

    auth_handler::state_type sign_transaction_call::call_impl()
    {
        if (json_get_value(m_tx_details, "is_sweep", false)
            || (m_net_params.is_electrum() && m_net_params.is_liquid())) {
            // For sweep txs and liquid electrum single sig, sign the tx in software.
            // TODO: Once tx aggregation is implemented, merge the sweep logic
            // with general tx construction to allow HW devices to sign individual
            // inputs (currently HW expects to sign all tx inputs)
            // FIXME: Sign rust liquid txs using the standard code path
            m_result = m_session->user_sign_transaction(m_tx_details);
            return state_type::done;
        }

        auto signer = get_signer();

        if (!m_initialized) {
            // Create signing/twofactor data for user signing
            initialize();
            // Create the data needed for user signing
            set_signer_data(signer);
            m_initialized = true;
            return m_state;
        }

        if (!json_get_value(m_result, "user_signed", false)) {
            // We haven't signed the users inputs yet, do so now
            sign_user_inputs(signer);
        }
        return state_type::done;
    }

    void sign_transaction_call::sign_user_inputs(const std::shared_ptr<signer>& signer)
    {
        const auto& hw_reply = get_hw_reply();
        const auto& inputs = m_twofactor_data["signing_inputs"];
        const auto& signatures = get_sized_array(hw_reply, "signatures", inputs.size());
        const auto& outputs = m_twofactor_data["transaction_outputs"];
        const auto& transaction_details = m_twofactor_data["transaction"];
        const bool is_liquid = m_net_params.is_liquid();
        const bool is_electrum = m_net_params.is_electrum();
        const auto tx = tx_from_hex(transaction_details.at("transaction"), tx_flags(is_liquid));

        if (is_liquid && signer->is_hardware()) {
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
        if (signer->use_ae_protocol()) {
            // FIXME: User pubkeys is not threadsafe if adding a subaccount
            // at the same time (this cant happen yet but should be allowed
            // in the future).
            auto& user_pubkeys = m_session->get_user_pubkeys();
            size_t i = 0;
            const auto& signer_commitments = get_sized_array(hw_reply, "signer_commitments", inputs.size());
            for (const auto& utxo : inputs) {
                const uint32_t subaccount = utxo.at("subaccount");
                const uint32_t pointer = utxo.at("pointer");

                pub_key_t pubkey;
                if (!is_electrum) {
                    pubkey = user_pubkeys.derive(subaccount, pointer);
                } else {
                    pubkey = user_pubkeys.derive(subaccount, pointer, utxo.value("is_internal", false));
                }
                const auto script_hash = get_script_hash(m_net_params, utxo, tx, i);
                constexpr bool has_sighash = true;
                verify_ae_signature(
                    pubkey, script_hash, utxo.at("ae_host_entropy"), signer_commitments[i], signatures[i], has_sighash);
                ++i;
            }
        }

        const bool is_low_r = signer->supports_low_r();
        size_t i = 0;
        for (const auto& utxo : inputs) {
            add_input_signature(tx, i, utxo, signatures[i], is_low_r);
            ++i;
        }

        m_result.swap(m_twofactor_data["transaction"]);
        m_result["user_signed"] = true;
        m_result["blinded"] = true;
        update_tx_size_info(m_net_params, tx, m_result);
    }

    //
    // Sign PSBT
    //
    psbt_sign_call::psbt_sign_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "psbt_sign")
        , m_details(details)
        , m_initialized(false)
    {
    }

    void psbt_sign_call::initialize()
    {
        if (m_net_params.is_electrum() || !m_net_params.is_liquid() || !get_signer()->is_hardware()) {
            m_result = m_session->psbt_sign(m_details);
            m_state = state_type::done;
        } else {
            // TODO: hww interactions (anti exfil, set signing data, etc)
            GDK_RUNTIME_ASSERT_MSG(false, "PSBT signing not implemented.");
        }
    }

    auth_handler::state_type psbt_sign_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // TODO: hww interactions (anti exfil, set signing data, etc)
        GDK_RUNTIME_ASSERT_MSG(false, "PSBT signing not implemented.");
        return state_type::done;
    }

    //
    // PSBT get details
    //
    psbt_get_details_call::psbt_get_details_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "psbt_get_details")
        , m_details(details)
    {
    }

    auth_handler::state_type psbt_get_details_call::call_impl()
    {
        GDK_RUNTIME_ASSERT(!m_net_params.is_electrum());
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());
        // TODO: replace the following line with a user error once we have the string res.
        GDK_RUNTIME_ASSERT(get_signer()->has_master_blinding_key());

        // Currently updating the scriptpubkey cache is quite expensive
        // and requires multiple network calls, so for the time being
        // we only update it here.
        for (const auto& sa : m_session->get_subaccounts()) {
            const uint32_t subaccount = sa.at("pointer");
            m_session->encache_new_scriptpubkeys(subaccount);
        }

        m_result = m_session->psbt_get_details(m_details);
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
        blind_address(m_net_params, m_result, get_hw_reply().at("public_keys").at(0));
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
        m_result = m_session->get_previous_addresses(m_details);
        if (!m_net_params.is_liquid() || m_net_params.is_electrum() || m_result["list"].empty()) {
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
        const std::vector<std::string> public_keys = get_hw_reply().at("public_keys");
        size_t i = 0;
        for (auto& it : m_result.at("list")) {
            blind_address(m_net_params, it, public_keys.at(i));
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
                blind_address(m_net_params, addr, public_keys.at(i));
                ++i;
            }
        }

        // Update the transaction
        m_result = m_session->create_transaction(m_result);
        return check_change_outputs();
    }

    auth_handler::state_type create_transaction_call::check_change_outputs()
    {
        nlohmann::json::array_t scripts;

        if (m_net_params.is_liquid()) {
            // Check whether we have any unblinded change outputs
            const auto change_addresses_p = m_result.find("change_address");
            if (change_addresses_p != m_result.end()) {
                scripts.reserve(change_addresses_p->size());
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
    // Get subaccounts
    //
    get_subaccounts_call::get_subaccounts_call(session& session, const nlohmann::json& details)
        : auth_handler_impl(session, "get_subaccounts")
        , m_subaccount_type(address_type::p2sh_p2wpkh)
        , m_subaccount(0)
        , m_details(details)
    {
    }

    auth_handler::state_type get_subaccounts_call::call_impl()
    {
        if (!m_net_params.is_electrum() || !m_details.value("refresh", false) || m_subaccount_type.empty()) {
            m_result = { { "subaccounts", m_session->get_subaccounts() } };
            return state_type::done;
        }

        // TODO: consider batching requests for xpubs.
        // The current implementation asks for one xpub at the time.
        // Depending on network connection speed and hardware signer response time,
        // this might affect performance negatively.

        // BIP44 account discovery
        // Performed only for Electrum sessions and if the client requests it.
        if (m_hw_request == hw_request::get_xpubs) {
            // Caller has provided the xpub for the subaccount
            const std::string xpub = get_hw_reply().at("xpubs").at(0);
            if (m_session->discover_subaccount(xpub, m_subaccount_type)) {
                m_session->create_subaccount({ { "name", std::string() }, { "discovered", true } }, m_subaccount, xpub);
            } else {
                // Found an empty subaccount for the current subaccount type,
                // step to the next subaccount type.
                if (m_subaccount_type == address_type::p2sh_p2wpkh) {
                    m_subaccount_type = address_type::p2wpkh;
                } else if (m_subaccount_type == address_type::p2wpkh) {
                    m_subaccount_type = address_type::p2pkh;
                } else if (m_subaccount_type == address_type::p2pkh) {
                    m_subaccount_type.clear();
                    // No more subaccount types, ready to return
                    return m_state;
                }
            }
        }

        // Ask for the xpub for the next subaccount of the current type
        m_subaccount = m_session->get_next_subaccount(m_subaccount_type);
        signal_hw_request(hw_request::get_xpubs);
        auto& paths = m_twofactor_data["paths"];
        paths.emplace_back(m_session->get_subaccount_root_path(m_subaccount));
        return m_state;
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
        , m_subaccount(json_get_value(details, "subaccount", 0))
    {
    }

    auth_handler::state_type get_transactions_call::call_impl()
    {
        if (m_net_params.is_electrum()) {
            // FIXME: Move rust to ga_session interface
            m_result = { { "transactions", m_session->get_transactions(m_details) } };
            return state_type::done;
        }

        if (m_hw_request == hw_request::get_blinding_nonces) {
            // Parse and cache the nonces we got back
            encache_blinding_data(*m_session, m_twofactor_data, get_hw_reply());
            // Unblind, cleanup and store the fetched txs
            m_session->store_transactions(m_subaccount, m_result);
            // Make sure we don't re-encache the same nonces again next time through
            m_hw_request = hw_request::none;
            m_result.clear();
            // Continue on to check for the next page to sync
        }

        if (!m_result.empty() && !m_result.value("more", false)) {
            // We have finished iterating and caching the server results,
            // return the txs the user asked for
            m_details["sync_ts"] = m_result["sync_ts"];
            auto txs = m_session->get_transactions(m_details);
            if (!txs.is_boolean()) {
                m_session->postprocess_transactions(txs);
                m_result = { { "transactions", std::move(txs) } };
                return state_type::done;
            }
            // Otherwise the cache was invalidated, continue on to resync
        }

        // Sync a page of txs from the server
        unique_pubkeys_and_scripts_t missing;
        m_result = m_session->sync_transactions(m_subaccount, missing);
        if (!missing.empty()) {
            // We have missing nonces we need to fetch, request them
            signal_hw_request(hw_request::get_blinding_nonces);
            set_blinding_nonce_request_data(get_signer(), missing, m_twofactor_data);
            return m_state;
        }
        // No missing nonces, cleanup and store the fetched txs directly
        m_session->store_transactions(m_subaccount, m_result);
        // Call again to either continue fetching, or return the result
        return state_type::make_call;
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
        // Fetch all UTXOs including frozen for caching, we filter out
        // frozen UTXOs in filter_result before returning if requested.
        auto unfiltered_details = m_details;
        unfiltered_details["all_coins"] = true;
        auto utxos = m_session->get_unspent_outputs(unfiltered_details, missing);
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
        set_blinding_nonce_request_data(get_signer(), missing, m_twofactor_data);
    }

    auth_handler::state_type get_unspent_outputs_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // Parse and cache the nonces we got back
        encache_blinding_data(*m_session, m_twofactor_data, get_hw_reply());

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
        if (encache && !m_net_params.is_electrum()) {
            // Encache the unfiltered results, and set our result to a copy
            // for filtering.
            auto p = m_session->set_cached_utxos(m_details.at("subaccount"), m_details.at("num_confs"), m_result);
            m_result = *p;
        }

        auto& outputs = m_result.at("unspent_outputs");
        if (outputs.is_null() || outputs.empty()) {
            // Nothing to filter, return an empty json object
            outputs = nlohmann::json::object();
            return;
        }

        const bool is_liquid = m_net_params.is_liquid();
        if (is_liquid && m_details.value("confidential", false)) {
            // The user wants only confidential UTXOs, filter out non-confidential
            filter_utxos(outputs, [](const auto& u) { return !u.value("confidential", false); });
        }

        if (!m_details.value("all_coins", false)) {
            // User did not request frozen UTXOs, filter them out
            filter_utxos(outputs,
                [](const auto& u) { return u.value("user_status", USER_STATUS_DEFAULT) == USER_STATUS_FROZEN; });
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
        m_session->ensure_full_session();

        GDK_RUNTIME_ASSERT(m_details.at("list").is_array());
        bool seen_frozen = false;

        for (auto& item : m_details["list"]) {
            auto& status = item["user_status"];
            if (status == "default") {
                status = USER_STATUS_DEFAULT;
            } else if (status == "frozen") {
                status = USER_STATUS_FROZEN;
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
        m_session->ensure_full_session();

        if (m_net_params.is_electrum()) {
            return; // Ignore nlocktime for singlesig
        }
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
        m_session->ensure_full_session();

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
        m_session->ensure_full_session();

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
            m_session->ensure_full_session();
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
    send_transaction_call::send_transaction_call(session& session, const nlohmann::json& tx_details, bool sign_only)
        : auth_handler_impl(session, sign_only ? "sign_transaction" : "send_transaction")
        , m_tx_details(tx_details)
        , m_bump_amount(0)
        , m_type(sign_only ? "sign" : "send")
        , m_twofactor_required(false)
        , m_under_limit(false)
        , m_initialized(false)
    {
        // sign_only is for multisig signing by the Green service only
        GDK_RUNTIME_ASSERT(!sign_only || !m_net_params.is_electrum());
    }

    void send_transaction_call::initialize()
    {
        signal_2fa_request(m_type + "_raw_tx");
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
        // Prevent the call from using the limit next time through the state machine
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
                    // Tx is under the limit and an attempt hasn't previously failed causing
                    // the user to enter a code. Try again without 2fa as an under limits spend
                    m_twofactor_data["try_under_limits_spend"] = m_limit_details;
                } else {
                    // 2FA is provided or not configured. Add the details
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
            json_rename_key(m_twofactor_data, "fee", m_type + "_raw_tx_fee");
            json_rename_key(m_twofactor_data, "change_idx", m_type + "_raw_tx_change_idx");

            std::string key = m_bump_amount ? "bump_fee_amount" : (m_type + "_raw_tx_amount");
            json_rename_key(m_twofactor_data, "amount", key);
        }

        // TODO: Add the recipient to twofactor_data for more server verification
        if (m_type == "send") {
            m_result = m_session->send_transaction(m_tx_details, m_twofactor_data);
        } else {
            m_result = m_session->service_sign_transaction(m_tx_details, m_twofactor_data);
        }
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
                m_session->request_undo_twofactor_reset(m_reset_email);
            } else {
                m_session->request_twofactor_reset(m_reset_email);
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
