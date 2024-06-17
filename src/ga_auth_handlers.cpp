#include "ga_auth_handlers.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio/io_context.hpp>
#include <utility>

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_psbt.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "ga_wally.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace green {

    namespace {
        static const std::string CHALLENGE_PREFIX("greenaddress.it      login ");
        // Addresses uploaded after creation of 2of2_no_recovery subaccounts.
        // Note that this is deliberately less than the server default (25) so
        // that the code path to upload on login is always executed/doesn't bitrot.
        static const uint32_t INITIAL_UPLOAD_CA = 20;

        // UTXO user_status values from the Green server
        static constexpr uint32_t USER_STATUS_DEFAULT = 0;
        static constexpr uint32_t USER_STATUS_FROZEN = 1;

        // Add anti-exfil protocol host-entropy and host-commitment to the passed json
        static void add_ae_host_data(nlohmann::json& data)
        {
            // Add entropy if missing. Otherwise, use the caller provided
            // (or previous, in the case of a failed signing) values.
            if (!data.contains("ae_host_entropy")) {
                data["ae_host_entropy"] = b2h(get_random_bytes<WALLY_S2C_DATA_LEN>());
            }
            // Regenerate the host commitment
            const auto host_entropy = j_bytesref(data, "ae_host_entropy");
            data["ae_host_commitment"] = b2h(ae_host_commit_from_bytes(host_entropy));
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

        // Verify an Anti-Exfil signature wrt the passed host-entropy and signer commitment
        // TODO: any failures here should be tracked/counted by the wallet (eg. in the client-blob)
        // to ensure the hww is abiding by the Anti-Exfil protocol.
        void verify_ae_signature(byte_span_t pubkey, byte_span_t message_hash, byte_span_t host_entropy,
            byte_span_t signer_commitment, byte_span_t sig)
        {
            const uint32_t flags = EC_FLAG_ECDSA;
            auto ret = wally_ae_verify(pubkey.data(), pubkey.size(), message_hash.data(), message_hash.size(),
                host_entropy.data(), host_entropy.size(), signer_commitment.data(), signer_commitment.size(), flags,
                sig.data(), sig.size());
            if (ret != WALLY_OK) {
                throw user_error(res::id_signature_validation_failed_if);
            }
        }

        static void verify_ae_message(const nlohmann::json& twofactor_data, byte_span_t pubkey,
            byte_span_t signer_commitment, byte_span_t compact_sig)
        {
            const auto& message = j_strref(twofactor_data, "message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));

            verify_ae_signature(
                pubkey, message_hash, j_bytesref(twofactor_data, "ae_host_entropy"), signer_commitment, compact_sig);
        }

        static void verify_ae_message(const nlohmann::json& twofactor_data, const std::string& root_bip32_xpub,
            uint32_span_t path, const nlohmann::json& hw_reply)
        {
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

            constexpr bool has_sighash_byte = false;
            const auto compact_sig = ec_sig_from_der(j_bytesref(hw_reply, "signature"), has_sighash_byte);
            return verify_ae_message(twofactor_data, pubkey, j_bytesref(hw_reply, "signer_commitment"), compact_sig);
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
            const auto& nonces = j_arrayref(hw_reply, "nonces", scripts.size());
            const auto blinding_pubkeys_p = hw_reply.find("public_keys");
            const bool have_blinding_pubkeys = blinding_pubkeys_p != hw_reply.end();
            if (have_blinding_pubkeys) {
                // Must be a correctly sized array if given
                (void)j_arrayref(hw_reply, "public_keys", scripts.size());
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
            bool m_are_confidential;
            std::map<uint32_t, std::vector<nlohmann::json>> m_addresses;
        };

        upload_ca_handler::upload_ca_handler(session& session, uint32_t subaccount, size_t num_addrs)
            : auth_handler_impl(session, "upload_confidential_addrs")
            , m_num_required_addrs(0)
            , m_num_generated_addrs(0)
            , m_are_confidential(false)
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
                        scripts.push_back(addr.at("scriptpubkey"));
                    }
                }
                auto& request = signal_hw_request(hw_request::get_blinding_public_keys);
                request["scripts"] = std::move(scripts);
                return m_state;
            }

            // The signer has provided the blinding keys for our address.
            GDK_RUNTIME_ASSERT(m_hw_request == hw_request::get_blinding_public_keys);

            if (!m_are_confidential) {
                // Liquid: Make our addresses confidential with the signer provided blinding keys
                const auto& public_keys = j_arrayref(get_hw_reply(), "public_keys", m_num_required_addrs);

                size_t i = 0;
                for (auto& subaccount_addresses : m_addresses) {
                    for (auto& addr : subaccount_addresses.second) {
                        confidentialize_address(m_net_params, addr, public_keys.at(i));
                        ++i;
                    }
                }
                m_are_confidential = true;
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

        static void sync_scriptpubkeys(session_impl& session)
        {
            if (session.get_network_parameters().is_liquid()) {
                const bool have_master_key = session.get_signer()->has_master_blinding_key();
                GDK_RUNTIME_ASSERT_MSG(have_master_key, "Master blinding key must be exported for PSBT operations");
            }
            // FIXME: Updating the scriptpubkey cache can be very expensive
            for (const auto subaccount : session.get_subaccount_pointers()) {
                session.encache_new_scriptpubkeys(subaccount);
            }
        }
    } // namespace

    //
    // Register
    //
    register_call::register_call(session& session, nlohmann::json hw_device, nlohmann::json credential_data)
        : auth_handler_impl(session, "register_user", session.get_nonnull_impl()->get_signer())
        , m_hw_device(std::move(hw_device))
        , m_credential_data(std::move(credential_data))
        , m_registration_signer()
    {
    }

    auth_handler::state_type register_call::call_impl()
    {
        if (m_hw_request == hw_request::get_xpubs) {
            // xpubs have been loaded into the signer: Register the user.
            m_result = m_session->register_user(m_registration_signer);
            return state_type::done;
        }

        const bool is_electrum = m_net_params.is_electrum();
        // Create our signer for registration
        m_registration_signer = std::make_shared<signer>(m_net_params, m_hw_device, m_credential_data);
        const bool registering_watch_only = m_registration_signer->is_watch_only();
        if (registering_watch_only) {
            // A logged in full session is required to register a watch only session
            m_session->ensure_full_session();
        } else {
            // Use the (full session) registration signer to resolve our xpub requests
            m_signer = m_registration_signer;
        }

        // Fetch the xpubs needed for registration
        auto& paths = signal_hw_request(hw_request::get_xpubs)["paths"];
        // We need the master xpub to identify the wallet
        paths.emplace_back(signer::EMPTY_PATH);
        if (registering_watch_only) {
            // We need the client secret path to generate blobserver credentials
            paths.emplace_back(signer::CLIENT_SECRET_PATH);
        } else if (!is_electrum) {
            // Multisig: we need the registration xpub to compute our gait path
            paths.emplace_back(signer::REGISTER_PATH);
        }
        return m_state;
    }

    //
    // Login User
    //
    login_user_call::login_user_call(session& session, nlohmann::json hw_device, nlohmann::json credential_data)
        : auth_handler_impl(session, "login_user", {})
        , m_hw_device(std::move(hw_device))
        , m_credential_data(std::move(credential_data))
    {
    }

    auth_handler::state_type login_user_call::call_impl()
    {
        const bool is_electrum = m_net_params.is_electrum();

        if (!m_signer) {
            if (m_credential_data.contains("pin")) {
                // Login with PIN. Fetch the mnemonic from the pin and pin data
                m_credential_data = m_session->credentials_from_pin_data(m_credential_data);
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

            try {
                auto& paths = signal_hw_request(hw_request::get_xpubs)["paths"];
                paths.emplace_back(signer::EMPTY_PATH); // Master xpub
                paths.emplace_back(signer::CLIENT_SECRET_PATH);
                if (!is_electrum) {
                    // Multisig: fetch the xpubs for login authentication
                    paths.emplace_back(signer::LOGIN_PATH);
                }
            } catch (const std::exception&) {
                m_signer.reset(); // Allow this code path to re-run if the above throws
                throw;
            }
            return m_state;
        }

        if (m_hw_request == hw_request::get_xpubs && m_master_bip32_xpub.empty()) {
            GDK_RUNTIME_ASSERT(m_challenge.empty());

            // We have a result from our first get_xpubs request.
            const auto& xpubs = j_arrayref(get_hw_reply(), "xpubs");
            m_master_bip32_xpub = xpubs.at(0);

            if (is_electrum) {
                // Skip the challenge/response steps since we have no server
                // to authenticate to.
                goto do_authenticate;
            }

            // Compute the login challenge with the master pubkey
            const auto public_key = make_xpub(m_master_bip32_xpub).second;
            m_challenge = m_session->get_challenge(public_key);
            // Ask the caller to sign the challenge
            auto& request = signal_hw_request(hw_request::sign_message);
            request["message"] = CHALLENGE_PREFIX + m_challenge;
            request["path"] = signer::LOGIN_PATH;
            add_required_ae_data(m_signer, request);
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
            m_result = m_session->authenticate(sig_der_hex, m_signer);

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

        nlohmann::json::array_t paths;
        paths.reserve(m_subaccount_pointers.size());
        for (const auto& pointer : m_subaccount_pointers) {
            paths.emplace_back(m_session->get_subaccount_root_path(pointer));
        }
        auto& request = signal_hw_request(hw_request::get_xpubs);
        request["paths"] = std::move(paths);
        return m_state;
    }

    //
    // Create subaccount
    //
    create_subaccount_call::create_subaccount_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "create_subaccount")
        , m_details(std::move(details))
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
            auto recovery_mnemonic = j_str_or_empty(m_details, "recovery_mnemonic");
            const bool missing_recovery_xpub = j_str_is_empty(m_details, "recovery_xpub");
            if (!(missing_recovery_xpub ^ recovery_mnemonic.empty())) {
                throw user_error("2of3 accounts require either recovery_mnemonic or recovery_xpub");
            }

            if (missing_recovery_xpub) {
                // Derive recovery_xpub from recovery_mnemonic
                const std::vector<uint32_t> mnemonic_path{ harden(3), harden(m_subaccount) };
                const nlohmann::json credentials = { { "mnemonic", std::move(recovery_mnemonic) } };
                m_details["recovery_xpub"] = signer{ m_net_params, {}, credentials }.get_bip32_xpub(mnemonic_path);
                m_details.erase("recovery_mnemonic");
            }
        }

        auto& paths = signal_hw_request(hw_request::get_xpubs)["paths"];
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
            const auto& xpubs = j_arrayref(get_hw_reply(), "xpubs");
            m_subaccount_xpub = xpubs.at(0);
            if (m_details.at("type") == "2of3") {
                // Ask the caller to sign the recovery key with the login key
                auto& request = signal_hw_request(hw_request::sign_message);
                request["message"] = format_recovery_key_message(m_details["recovery_xpub"], m_subaccount);
                request["path"] = signer::LOGIN_PATH;
                add_required_ae_data(get_signer(), request);
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

            m_details["recovery_key_sig"] = b2h(ec_sig_from_der(j_bytesref(hw_reply, "signature"), false));
            // Fall through to create the subaccount
        }

        // This is an actual subaccount creation, do not allow the caller to set this flag
        m_details.erase("is_already_created");
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

        auto& request = signal_hw_request(hw_request::sign_message);
        request["message"] = m_message_info.first;
        request["path"] = m_message_info.second;
        add_required_ae_data(get_signer(), request);
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
    // Cache control
    //
    cache_control_call::cache_control_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "cache_control")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type cache_control_call::call_impl()
    {
        m_result = m_session->cache_control(m_details);
        return state_type::done;
    }

    //
    // Sign tx
    //
    sign_transaction_call::sign_transaction_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "sign_transaction")
        , m_details(std::move(details))
        , m_sweep_private_keys()
        , m_sweep_signatures()
        , m_initialized(false)
        , m_user_signed(false)
        , m_server_signed(false)
    {
    }

    void sign_transaction_call::initialize()
    {
        const bool is_electrum = m_net_params.is_electrum();
        bool have_checked_full_session = false;

        if (!m_details.empty()) {
            m_details.erase("utxos"); // Not needed anymore
        }
        if (!j_str_is_empty(m_details, "error")) {
            // Can't sign a tx with an error, return it as-is
            m_result = std::move(m_details);
            m_state = state_type::done;
            return;
        }
        // Ensure we have an empty error element for the happy path
        m_details["error"] = std::string();

        const bool is_liquid = m_net_params.is_liquid();
        const auto signer = get_signer();
        const bool use_ae_protocol = signer->use_ae_protocol();
        const bool is_local_signer = !signer->is_remote();
        bool have_inputs_to_sign = false;

        // Compute the data we need for the hardware to sign the transaction
        auto& request = signal_hw_request(hw_request::sign_tx);
        request["transaction"] = std::move(m_details["transaction"]);
        auto& inputs = request["transaction_inputs"];
        inputs = std::move(m_details["transaction_inputs"]);
        request["transaction_outputs"] = std::move(m_details["transaction_outputs"]);
        request["use_ae_protocol"] = use_ae_protocol;
        const bool is_partial = j_bool_or_false(m_details, "is_partial");
        const bool is_partial_multisig = is_partial && !is_electrum;
        if (is_partial_multisig) {
            // Multisig partial signing. Ensure all inputs to be signed are segwit
            for (const auto& utxo : inputs) {
                const auto addr_type = j_str_or_empty(utxo, "address_type");
                if (!addr_type.empty() && !address_type_is_segwit(addr_type)) {
                    throw user_error("Non-segwit utxos cannnot be used with partial signing");
                }
            }
        }
        request["is_partial"] = is_partial;

        // We need the inputs, augmented with types, scripts and paths
        std::unique_ptr<Tx> tx;
        m_sweep_private_keys.resize(inputs.size());
        m_sweep_signatures.resize(inputs.size());
        for (size_t i = 0; i < inputs.size(); ++i) {
            auto& input = inputs[i];
            if (input.contains("private_key")) {
                // Sweep input. Compute the signature using the provided
                // private key and store it. Then mark the input as
                // skip_signing=true and remove its private key so we
                // don't expose it to the signer.
                if (!tx) {
                    tx = std::make_unique<Tx>(j_strref(m_twofactor_data, "transaction"), is_liquid);
                }
                const uint32_t sighash_flags = WALLY_SIGHASH_ALL;
                const auto tx_signature_hash = tx->get_signature_hash(input, i, sighash_flags);
                m_sweep_private_keys[i] = input["private_key"];
                const auto sig = ec_sig_from_bytes(h2b(m_sweep_private_keys[i]), tx_signature_hash);
                m_sweep_signatures[i] = b2h(ec_sig_to_der(sig, sighash_flags));
                input["skip_signing"] = true;
                input.erase("private_key");
            } else if (!j_bool_or_false(input, "skip_signing")) {
                // Wallet input we have been asked to sign. Must be spendable by us
                GDK_RUNTIME_ASSERT(!j_strref(input, "address_type").empty());
                if (!have_checked_full_session) {
                    // Only full (i.e. non watch-only) sessions can sign wallet inputs
                    m_session->ensure_full_session();
                    have_checked_full_session = true; // Avoid re-checking
                }

                // Add host-entropy and host-commitment to each input if using the anti-exfil protocol
                if (use_ae_protocol) {
                    add_ae_host_data(input);
                } else {
                    remove_ae_host_data(input);
                }
                have_inputs_to_sign = true;
            }
        }

        nlohmann::json prev_txs; // FIXME: allow caller to pass in (e.g. from PSBT)
        if (is_local_signer && have_inputs_to_sign && !is_liquid) {
            // BTC: Provide the previous txs data for validation, even
            // for segwit, in order to mitigate the segwit fee attack.
            // (Liquid txs are explicit fee and so not affected)
            for (const auto& input : inputs) {
                std::string txhash = input.at("txhash");
                if (!prev_txs.contains(txhash)) {
                    auto tx_hex = m_session->get_raw_transaction_details(txhash).to_hex();
                    prev_txs.emplace(std::move(txhash), std::move(tx_hex));
                }
            }
        }
        m_twofactor_data["signing_transactions"] = std::move(prev_txs);
    }

    // Determine whether to sign with the users key, green backend, or both
    static std::pair<bool, bool> get_sign_with(const nlohmann::json& details, bool is_electrum)
    {
        const auto with = j_array(details, "sign_with").value_or(nlohmann::json::array_t{});
        auto&& contains
            = [&with](const auto& who) -> bool { return std::find(with.begin(), with.end(), who) != with.end(); };

        const bool sign_with_all = contains("all");
        const bool user_sign = sign_with_all || with.empty() || contains("user");
        const bool server_sign = is_electrum ? false : (sign_with_all || contains("green-backend"));
        return { user_sign, server_sign };
    }

    auth_handler::state_type sign_transaction_call::call_impl()
    {
        if (!m_initialized) {
            // Create signing/twofactor data for user signing
            initialize();
            m_initialized = true;
            return m_state;
        }

        bool user_sign, server_sign;
        std::tie(user_sign, server_sign) = get_sign_with(m_details, m_net_params.is_electrum());

        if (user_sign && !m_user_signed) {
            // We haven't signed the users inputs yet, do so now
            sign_user_inputs();
            m_user_signed = true;
        } else {
            // Set the transaction details in the result
            m_result.swap(m_details);
            m_result["transaction"] = std::move(m_twofactor_data["transaction"]);
            m_result["transaction_inputs"] = std::move(m_twofactor_data["transaction_inputs"]);
            m_result["transaction_outputs"] = std::move(m_twofactor_data["transaction_outputs"]);
        }

        if (server_sign && !m_server_signed) {
            // Note that the server will fail to sign if the user hasn't signed first
            auto&& must_sign = [](const auto& in) -> bool { return !j_bool_or_false(in, "skip_signing"); };
            const auto& inputs = m_result.at("transaction_inputs");
            if (std::any_of(inputs.begin(), inputs.end(), must_sign)) {
                /* We have inputs that need signing */
                constexpr bool sign_only = true;
                add_next_handler(new send_transaction_call(m_session_parent, m_result, sign_only));
            }
            m_server_signed = true;
        }
        return state_type::done;
    }

    void sign_transaction_call::sign_user_inputs()
    {
        auto signer = get_signer();
        const auto& hw_reply = get_hw_reply();
        auto& inputs = m_twofactor_data["transaction_inputs"];
        const auto& signatures = j_arrayref(hw_reply, "signatures", inputs.size());
        const bool is_liquid = m_net_params.is_liquid();
        const bool is_electrum = m_net_params.is_electrum();
        Tx tx(j_strref(m_twofactor_data, "transaction"), is_liquid);

        // If we are using the Anti-Exfil protocol we verify the signatures
        // TODO: the signer-commitments should be verified as being the same for the
        // same input data and host-entropy (eg. if retrying following failure).
        if (signer->use_ae_protocol()) {
            // FIXME: User pubkeys is not threadsafe if adding a subaccount
            // at the same time (this cant happen yet but should be allowed
            // in the future).
            auto& user_pubkeys = m_session->get_user_pubkeys();
            for (size_t i = 0; i < inputs.size(); ++i) {
                const auto& utxo = inputs.at(i);
                if (j_bool_or_false(utxo, "skip_signing")) {
                    continue;
                }
                const uint32_t subaccount = j_uint32ref(utxo, "subaccount");
                const uint32_t pointer = j_uint32ref(utxo, "pointer");
                const uint32_t sighash_flags = j_uint32(utxo, "user_sighash").value_or(WALLY_SIGHASH_ALL);

                pub_key_t pubkey;
                if (is_electrum) {
                    pubkey = user_pubkeys.derive(subaccount, pointer, j_bool_or_false(utxo, "is_internal"));
                } else {
                    pubkey = user_pubkeys.derive(subaccount, pointer);
                }
                const auto tx_signature_hash = tx.get_signature_hash(utxo, i, sighash_flags);
                constexpr bool has_sighash_byte = true;
                const auto& signer_commitments = j_arrayref(hw_reply, "signer_commitments", inputs.size());
                const auto sig = ec_sig_from_der(h2b(signatures[i]), has_sighash_byte);
                verify_ae_signature(
                    pubkey, tx_signature_hash, j_bytesref(utxo, "ae_host_entropy"), h2b(signer_commitments[i]), sig);
            }
        }

        for (size_t i = 0; i < inputs.size(); ++i) {
            auto& txin = inputs.at(i);
            std::string der_hex = signatures.at(i);
            if (j_bool_or_false(txin, "skip_signing")) {
                GDK_RUNTIME_ASSERT(der_hex.empty());
                der_hex = m_sweep_signatures.at(i);
                if (der_hex.empty()) {
                    continue;
                }
                txin["private_key"] = std::move(m_sweep_private_keys[i]);
            }
            tx_set_user_signature(*m_session, m_twofactor_data, tx, i, h2b(der_hex));
        }

        // Return our input details with the signatures updated
        m_result.swap(m_details);
        m_result["transaction_outputs"] = std::move(m_twofactor_data["transaction_outputs"]);
        m_result["transaction_inputs"] = std::move(m_twofactor_data["transaction_inputs"]);
        update_tx_size_info(m_net_params, tx, m_result);
        m_result["txhash"] = b2h_rev(tx.get_txid());
    }

    void sign_transaction_call::on_next_handler_complete(auth_handler* next_handler)
    {
        // We have completed server signing, copy the result into our result
        m_result = std::move(next_handler->move_result());
    }

    //
    // Sign PSBT
    //
    psbt_sign_call::psbt_sign_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "psbt_sign")
        , m_details(std::move(details))
        , m_is_synced(false)
    {
    }

    psbt_sign_call::~psbt_sign_call() {}

    auth_handler::state_type psbt_sign_call::call_impl()
    {
        m_session->ensure_full_session();
        if (!m_is_synced) {
            sync_scriptpubkeys(*m_session);
            m_is_synced = true;
        }

        m_psbt = std::make_unique<Psbt>(j_strref(m_details, "psbt"), m_net_params.is_liquid());
        m_signing_details = m_psbt->to_json(*m_session, std::move(m_details.at("utxos")));

        if (m_signing_details.empty()) {
            // No signatures required, return the PSBT unchanged
            m_result = std::move(m_details);
            return state_type::done;
        }

        nlohmann::json::array_t sign_with;
        sign_with.push_back("all");
        m_signing_details["sign_with"] = m_details.value("sign_with", sign_with);

        if (const auto p = m_details.find("blinding_nonces"); p != m_details.end()) {
            m_signing_details.emplace("blinding_nonces", *p);
        }
        // FIXME: pass in prev_txs from PSBT if present

        // Use the sign_transaction handler to sign
        add_next_handler(new sign_transaction_call(m_session_parent, m_signing_details));
        return state_type::done;
    }

    void psbt_sign_call::on_next_handler_complete(auth_handler* next_handler)
    {
        // User/server signing is complete: add the signing data to our psbt
        m_result = std::move(next_handler->move_result());
        if (!j_str_is_empty(m_details, "error")) {
            m_result["psbt"] = std::move(m_details.at("psbt"));
            return;
        }

        const Tx tx(j_strref(m_result, "transaction"), m_net_params.is_liquid());
        const auto num_inputs = tx.get_num_inputs();
        const auto& tx_inputs = j_arrayref(m_result, "transaction_inputs", num_inputs);
        for (size_t i = 0; i < num_inputs; ++i) {
            if (!j_bool_or_false(tx_inputs.at(i), "skip_signing")) {
                m_psbt->set_input_finalization_data(i, tx);
            }
        }
        /* For partial signing, we must keep the redeem script in the PSBT
         * for inputs that we have finalized, despite this breaking the spec
         * behaviour. FIXME: Use an extension field for this, since some
         * inputs may have been already properly finalized before we sign.
         */
        const bool include_redundant = j_bool_or_false(m_result, "is_partial");
        m_result["psbt"] = m_psbt->to_base64(include_redundant);
    }

    //
    // PSBT from JSON
    //
    psbt_from_json_call::psbt_from_json_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "psbt_from_json")
        , m_details(std::move(details))
    {
    }

    psbt_from_json_call::~psbt_from_json_call() {}

    auth_handler::state_type psbt_from_json_call::call_impl()
    {
        Psbt psbt(*m_session, m_details, m_net_params.is_liquid());
        const bool include_redundant = j_bool_or_false(m_details, "is_partial");
        m_result = { { "psbt", psbt.to_base64(include_redundant) } };
        if (auto p = m_details.find("blinding_nonces"); p != m_details.end()) {
            m_result.emplace("blinding_nonces", std::move(*p));
        }
        return state_type::done;
    }

    //
    // PSBT get details
    //
    psbt_get_details_call::psbt_get_details_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "psbt_get_details")
        , m_details(std::move(details))
        , m_is_synced(false)
    {
    }

    auth_handler::state_type psbt_get_details_call::call_impl()
    {
        if (!m_is_synced) {
            sync_scriptpubkeys(*m_session);
            m_is_synced = true;
        }

        const Psbt psbt(m_details.at("psbt"), m_net_params.is_liquid());
        m_result = psbt.get_details(*m_session, std::move(m_details));
        return state_type::done;
    }

    //
    // Get receive address
    //
    get_receive_address_call::get_receive_address_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_receive_address")
        , m_details(std::move(details))
        , m_initialized(false)
    {
    }

    void get_receive_address_call::initialize()
    {
        m_result = m_session->get_receive_address(m_details);

        if (m_net_params.is_liquid() && !m_net_params.is_electrum()) {
            // Ask the caller to provide the blinding key
            auto& request = signal_hw_request(hw_request::get_blinding_public_keys);
            request["scripts"].push_back(m_result.at("scriptpubkey"));
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

        // Liquid: Make our address confidential with the signer provided blinding key
        confidentialize_address(m_net_params, m_result, get_hw_reply().at("public_keys").at(0));
        return state_type::done;
    }

    //
    // Get previous addresses
    //
    get_previous_addresses_call::get_previous_addresses_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_previous_addresses")
        , m_details(std::move(details))
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
        auto& request = signal_hw_request(hw_request::get_blinding_public_keys);
        auto& scripts = request["scripts"];
        for (const auto& it : m_result.at("list")) {
            scripts.push_back(it.at("scriptpubkey"));
        }
    }

    auth_handler::state_type get_previous_addresses_call::call_impl()
    {
        if (!m_initialized) {
            initialize();
            m_initialized = true;
            return m_state;
        }

        // Liquid: Make our addresses confidential with the signer provided blinding keys
        const auto& public_keys = j_arrayref(get_hw_reply(), "public_keys");
        size_t i = 0;
        for (auto& it : m_result.at("list")) {
            confidentialize_address(m_net_params, it, public_keys.at(i));
            ++i;
        }
        return state_type::done;
    }

    //
    // Create transaction
    //
    create_transaction_call::create_transaction_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "create_transaction")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type create_transaction_call::call_impl()
    {
        if (!m_details.empty()) {
            // Initial call: Set up details and create the tx below
            m_result.swap(m_details);
        } else {
            // Otherwise, we have been called after resolving our blinding keys:
            // make any non-confidential change addresseses confidential
            const auto& public_keys = get_hw_reply().at("public_keys");
            size_t i = 0;
            for (auto& it : m_result.at("change_address").items()) {
                auto& addr = it.value();
                if (!addr.value("is_confidential", false)) {
                    confidentialize_address(m_net_params, addr, public_keys.at(i));
                    ++i;
                }
            }
        }

        // Create/update the transaction
        create_transaction(*m_session, m_result);

        if (!m_net_params.is_liquid()) {
            return state_type::done; // Nothing to do for non-Liquid
        }

        // Check whether we have any unblinded change outputs
        nlohmann::json::array_t scripts;
        const auto change_addresses_p = m_result.find("change_address");
        if (change_addresses_p != m_result.end()) {
            scripts.reserve(change_addresses_p->size());
            for (auto& it : change_addresses_p->items()) {
                if (!it.value().value("is_confidential", false)) {
                    scripts.push_back(it.value().at("scriptpubkey"));
                }
            }
        }

        if (scripts.empty()) {
            // All change outputs are blinded, so we are done
            return state_type::done;
        }
        // We have unblinded change outputs, request the blinding keys
        auto& request = signal_hw_request(hw_request::get_blinding_public_keys);
        request.emplace("scripts", std::move(scripts));
        return m_state;
    }

    //
    // Blind transaction
    //
    blind_transaction_call::blind_transaction_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "blind_transaction")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type blind_transaction_call::call_impl()
    {
        if (!m_details.empty()) {
            m_details.erase("utxos"); // Not needed for blinding
        }
        const bool is_liquid = m_net_params.is_liquid();

        if (!is_liquid || !j_str_is_empty(m_details, "error") || j_bool_or_false(m_details, "is_blinded")) {
            // Already blinded, or non-Liquid network: return the details as-is
            m_result = std::move(m_details);
            return state_type::done;
        }

        if (m_hw_request == hw_request::get_blinding_factors) {
            // HWW has returned the blinding factors, blind the tx
            // For txs containing AMP v1 inputs, ask the HWW to return the
            // nonces the service requires.
            m_details["blinding_nonces_required"] = tx_has_amp_inputs(*m_session, m_details);
            blind_transaction(*m_session, m_details, get_hw_reply());
            m_details.erase("blinding_nonces_required");
            m_result = std::move(m_details);
            return state_type::done;
        }

        // Ask the HWW for the blinding factors to blind the tx
        auto& request = signal_hw_request(hw_request::get_blinding_factors);
        nlohmann::json::array_t utxos;
        const auto& tx_inputs = m_details["transaction_inputs"];
        utxos.reserve(tx_inputs.size());
        for (const auto& u : tx_inputs) {
            nlohmann::json prevout = { { "txhash", u.at("txhash") }, { "pt_idx", u.at("pt_idx") } };
            utxos.emplace_back(std::move(prevout));
        }
        request["transaction_inputs"] = std::move(utxos);
        const bool is_partial = j_bool_or_false(m_details, "is_partial");
        request["is_partial"] = is_partial;
        GDK_RUNTIME_ASSERT(is_partial || m_details["transaction_outputs"].size() >= 2);
        auto& outputs = request["transaction_outputs"];
        outputs = m_details["transaction_outputs"];
        if (!is_partial) {
            // Remove the fee output for non-partial txs
            GDK_RUNTIME_ASSERT(!outputs.empty());
            GDK_RUNTIME_ASSERT(j_str_is_empty(outputs.back(), "scriptpubkey"));
            outputs.erase(outputs.size() - 1);
        }
        return m_state;
    }

    //
    // Get subaccounts
    //
    get_subaccounts_call::get_subaccounts_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_subaccounts")
        , m_details(std::move(details))
        , m_found{}
    {
    }

    auth_handler::state_type get_subaccounts_call::call_impl()
    {
        constexpr size_t NUM_ACCT_TYPES = 3u;
        if (m_found.size() == NUM_ACCT_TYPES || !m_net_params.is_electrum() || !j_bool_or_false(m_details, "refresh")) {
            m_result = { { "subaccounts", m_session->get_subaccounts() } };
            return state_type::done;
        }

        // Singlesig: We have been requested to perform BIP44 account discovery
        // Singlesig watch only sessions cannot derive xpubs for finding accounts
        m_session->ensure_full_session();

        nlohmann::json::array_t paths;
        auto signer = get_signer();
        using namespace address_type;
        const nlohmann::json sa_details = { { "name", std::string() }, { "discovered", true } };
        for (const auto& addr_type : { p2sh_p2wpkh, p2wpkh, p2pkh }) {
            if (std::find(m_found.begin(), m_found.end(), addr_type) != m_found.end()) {
                // Already discovered all subaccounts for this type
                continue;
            }
            for (;;) {
                // Find the last empty subaccount of this type
                auto subaccount = m_session->get_last_empty_subaccount(addr_type);
                auto path = m_session->get_subaccount_root_path(subaccount);
                if (!signer->has_bip32_xpub(path)) {
                    // Request the xpub for this subaccount so we can discover it
                    paths.emplace_back(std::move(path));
                    break;
                } else {
                    // Discover whether the subaccount exists
                    const auto xpub = signer->get_bip32_xpub(path);
                    if (m_session->discover_subaccount(xpub, addr_type)) {
                        // Subaccount exists. Add it and loop to try the next one
                        m_session->create_subaccount(sa_details, subaccount, xpub);
                    } else {
                        // Reached the last discoverable subaccount of this type
                        m_found.push_back(addr_type);
                        break;
                    }
                }
            }
        }

        if (paths.empty()) {
            // We have discovered all subaccounts. When the caller calls
            // us again, the results will be returned
            GDK_RUNTIME_ASSERT(m_found.size() == NUM_ACCT_TYPES);
            m_state = state_type::make_call;
        } else {
            // Request paths for further subaccounts to discover
            signal_hw_request(hw_request::get_xpubs)["paths"] = std::move(paths);
        }
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
    get_transactions_call::get_transactions_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_transactions")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type get_transactions_call::call_impl()
    {
        if (m_net_params.is_electrum()) {
            // FIXME: Move rust to ga_session interface
            auto txs = m_session->get_transactions(m_details);
            m_session->postprocess_transactions(txs);
            m_result = { { "transactions", std::move(txs) } };
            return state_type::done;
        }

        const auto subaccount = j_uint32_or_zero(m_details, "subaccount");
        if (m_hw_request == hw_request::get_blinding_nonces) {
            // Parse and cache the nonces we got back
            encache_blinding_data(*m_session, m_twofactor_data, get_hw_reply());
            // Unblind, cleanup and store the fetched txs
            m_session->store_transactions(subaccount, m_result);
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
        m_result = m_session->sync_transactions(subaccount, missing);
        if (!missing.empty()) {
            // We have missing nonces we need to fetch, request them
            auto& request = signal_hw_request(hw_request::get_blinding_nonces);
            set_blinding_nonce_request_data(get_signer(), missing, request);
            return m_state;
        }
        // No missing nonces, cleanup and store the fetched txs directly
        m_session->store_transactions(subaccount, m_result);
        // Call again to either continue fetching, or return the result
        return state_type::make_call;
    }

    struct utxo_sorter {
        enum class sort_by_t : size_t { OLDEST = 0, NEWEST, LARGEST, SMALLEST };

        utxo_sorter(const std::string& sort_by)
        {
            if (sort_by == "oldest") {
                m_sort_by = sort_by_t::OLDEST;
            } else if (sort_by == "newest") {
                m_sort_by = sort_by_t::NEWEST;
            } else if (sort_by == "largest") {
                m_sort_by = sort_by_t::LARGEST;
            } else if (sort_by == "smallest") {
                m_sort_by = sort_by_t::SMALLEST;
            } else {
                throw user_error("invalid \"sort_by\" value");
            }
        }

        static bool compare_blockheight(const nlohmann::json& lhs, const nlohmann::json& rhs)
        {
            const uint32_t max_bh = 0xffffffff;
            const auto lhs_bh = j_uint32ref(lhs, "block_height");
            const auto rhs_bh = j_uint32ref(rhs, "block_height");
            return (lhs_bh ? lhs_bh : max_bh) < (rhs_bh ? rhs_bh : max_bh);
        }

        bool operator()(const nlohmann::json& lhs, const nlohmann::json& rhs) const
        {
            switch (m_sort_by) {
            case sort_by_t::OLDEST:
                return compare_blockheight(lhs, rhs);
                break;
            case sort_by_t::NEWEST:
                return compare_blockheight(rhs, lhs);
                break;
            case sort_by_t::LARGEST:
                return j_amountref(rhs) < j_amountref(lhs);
                break;
            case sort_by_t::SMALLEST:
                return j_amountref(lhs) < j_amountref(rhs);
                break;
            }
            return false; // Unreachable
        };
        sort_by_t m_sort_by;
    };

    //
    // Get unspent outputs
    //
    get_unspent_outputs_call::get_unspent_outputs_call(
        session& session, nlohmann::json details, const std::string& name)
        : auth_handler_impl(session, name.empty() ? "get_unspent_outputs" : name)
        , m_details(std::move(details))
        , m_initialized(false)
    {
    }

    void get_unspent_outputs_call::initialize()
    {
        const auto num_confs = j_uint32(m_details, "num_confs").value_or(0xff);
        if (num_confs != 0 && num_confs != 1u) {
            set_error("num_confs must be set to 0 or 1");
            return;
        }
        auto p = m_session->get_cached_utxos(j_uint32ref(m_details, "subaccount"), num_confs);
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
        auto& request = signal_hw_request(hw_request::get_blinding_nonces);
        set_blinding_nonce_request_data(get_signer(), missing, request);
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
            auto p = m_session->set_cached_utxos(
                j_uint32ref(m_details, "subaccount"), j_uint32ref(m_details, "num_confs"), m_result);
            m_result = *p;
        }

        auto& outputs = m_result.at("unspent_outputs");
        if (outputs.is_null() || outputs.empty()) {
            // Nothing to filter, return an empty json object
            outputs = nlohmann::json::object();
            return;
        }

        const auto address_type = j_str_or_empty(m_details, "address_type");
        if (!address_type.empty()) {
            // The user only wants a particular address type, filter out others
            filter_utxos(
                outputs, [&address_type](const auto& u) { return j_strref(u, "address_type") != address_type; });
        }

        const bool is_liquid = m_net_params.is_liquid();
        if (is_liquid && j_bool_or_false(m_details, "confidential")) {
            // The user only wants confidential UTXOs, filter out non-confidential
            filter_utxos(outputs, [](const auto& u) { return !j_bool_or_false(u, "is_blinded"); });
        }

        if (!j_bool_or_false(m_details, "all_coins")) {
            // User did not request frozen UTXOs, filter them out
            filter_utxos(outputs, [](const auto& u) {
                return j_uint32(u, "user_status").value_or(USER_STATUS_DEFAULT) == USER_STATUS_FROZEN;
            });
        }

        const auto expired_at = j_uint32(m_details, "expired_at");
        if (expired_at.has_value()) {
            // Return only UTXOs that have expired as at block number 'expired_at'.
            // A UTXO is expired if its nlocktime has been reached; i.e. its
            // nlocktime is less than or equal to the block number in
            // 'expired_at'. Therefore we filter out UTXOs where nlocktime
            // is greater than 'expired_at', or not present (i.e. non-expiring UTXOs)
            constexpr uint32_t max_ = 0xffffffff; // 81716 years from genesis
            filter_utxos(
                outputs, [expired_at, max_](const auto& u) { return u.value("expiry_height", max_) > expired_at; });
        }

        const auto dust_limit = j_amount_or_zero(m_details, "dust_limit");
        if (dust_limit.value()) {
            // The user passed a dust limit, filter UTXOs that are below it
            filter_utxos(outputs, [dust_limit](const auto& u) { return j_amountref(u) <= dust_limit; });
        }

        // Remove any keys that have become empty
        for (auto asset = outputs.begin(); asset != outputs.end(); /* no-op */) {
            if (asset.value().empty()) {
                // Use post increment to increment the iterator before it
                // is invalidated, passing the current value to erase()
                outputs.erase(asset++);
            } else {
                ++asset;
            }
        }

        // Sort the results
        if (!outputs.empty()) {
            const utxo_sorter sorter(get_sort_by());
            for (auto& asset : outputs.items()) {
                if (asset.key() != "error") {
                    auto& utxos = asset.value();
                    std::sort(utxos.begin(), utxos.end(), sorter);
                }
            }
        }
    }

    std::string get_unspent_outputs_call::get_sort_by() const
    {
        auto sort_by = j_str_or_empty(m_details, "sort_by");
        if (sort_by.empty()) {
            sort_by = "largest"; // Default to largest-first
            if (!m_net_params.is_electrum()) {
                // For 2of2, spend older outputs first by default, to reduce redeposits.
                // Otherwise, spend bigger outputs first by default to minimise fees.
                auto subaccount = j_uint32ref(m_details, "subaccount");
                if (subaccount == 0 || j_strref(m_session->get_subaccount(subaccount), "type") == "2of2") {
                    sort_by = "oldest";
                }
            }
        }
        return sort_by;
    }

    //
    // Get unspent outputs for private key
    //
    get_unspent_outputs_for_private_key_call::get_unspent_outputs_for_private_key_call(
        session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_unspent_outputs_for_private_key")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type get_unspent_outputs_for_private_key_call::call_impl()
    {
        if (m_net_params.is_liquid()) {
            throw user_error("Sweeping is not yet implemented for Liquid wallets");
        }
        m_result = m_session->get_external_unspent_outputs(m_details);
        return state_type::done;
    }

    //
    // Get balance
    //
    get_balance_call::get_balance_call(session& session, nlohmann::json details)
        : get_unspent_outputs_call(session, std::move(details), "get_balance")
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
        // Compute the balance data from returned UTXOs
        nlohmann::json balance({ { m_net_params.get_policy_asset(), 0 } });

        for (const auto& asset : m_result["unspent_outputs"].items()) {
            if (asset.key() == "error") {
                // TODO: Should we return whether an unblinding error occurred
                // when computing the balance?
                continue;
            }
            amount::value_type satoshi = 0;
            for (const auto& utxo : asset.value()) {
                GDK_RUNTIME_ASSERT(!utxo.contains("error"));
                satoshi += j_amountref(utxo).value();
            }
            balance[asset.key()] = satoshi;
        }
        m_result.swap(balance); // Return balance data to caller
    }

    //
    // Set unspent outputs status
    //
    set_unspent_outputs_status_call::set_unspent_outputs_status_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "set_unspent_output_status")
        , m_details(std::move(details))
        , m_initialized(false)
    {
    }

    void set_unspent_outputs_status_call::initialize()
    {
        m_session->ensure_full_session();

        (void)j_arrayref(m_details, "list"); // Must be an array
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
    change_settings_call::change_settings_call(session& session, nlohmann::json settings)
        : auth_handler_impl(session, "change_settings")
        , m_settings(std::move(settings))
        , m_initialized(false)
    {
    }

    void change_settings_call::initialize()
    {
        if (m_net_params.is_electrum() || m_session->is_watch_only()) {
            return; // Ignore nlocktime for singlesig/watch-only
        }
        const auto nlocktime_p = m_settings.find("nlocktime");
        if (nlocktime_p != m_settings.end()) {
            m_session->ensure_full_session();
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

        if (!m_nlocktime_value.empty()) {
            m_session->set_nlocktime(m_nlocktime_value, m_twofactor_data);
            m_nlocktime_value = {};
        }

        m_session->change_settings(m_settings);
        return state_type::done;
    }

    //
    // Enable 2FA
    //
    change_settings_twofactor_call::change_settings_twofactor_call(
        session& session, const std::string& method_to_update, nlohmann::json details)
        : auth_handler_impl(session, "change_settings_twofactor")
        , m_method_to_update(method_to_update)
        , m_details(std::move(details))
        , m_enabling(false)
        , m_initialized(false)
    {
    }

    bool change_settings_twofactor_call::is_sms_backup() const
    {
        return m_method_to_update == "phone" && j_bool_or_false(m_details, "is_sms_backup");
    }

    void change_settings_twofactor_call::initialize()
    {
        m_session->ensure_full_session();
        m_enabling = j_bool(m_details, "enabled").value_or(true);

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
        const std::string data = j_str_or_empty(m_details, "data");

        if (m_enabling) {
            signal_2fa_request("enable_2fa");
            if (m_method_to_update == "gauth") {
                // For gauth the user must pass in the current seed returned by the
                // server.
                // FIXME: Allow the user to specify their own seed in the future.
                if (data != j_str_or_empty(current_subconfig, "data")) {
                    set_error(res::id_inconsistent_data_provided_for);
                    return;
                }
            }
            if (is_sms_backup()) {
                // For sms backup disable all 2fa checks and go straight to the call
                // The backend will waive the 2fa checks provided that sms and only sms
                // is already enabled and the phone number requested matches
                m_methods->clear();
                m_state = state_type::make_call;
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
            if (m_net_params.is_electrum()) {
                throw user_error("Two-Factor settings cannot be changed for singlesig wallets");
            }
            initialize();
            m_initialized = true;
            return m_state;
        }

        if (m_action == "set_email") {
            m_session->set_email(j_strref(m_details, "data"), m_twofactor_data);
            // Move to activate email
            return on_init_done("activate_");
        }
        if (m_action == "activate_email") {
            m_session->activate_email(m_code);
            return state_type::done;
        }
        if (m_action == "enable_2fa") {
            if (m_method_to_update != "gauth") {
                if (is_sms_backup()) {
                    // Request to enable phone as backup of existing sms
                    // The backend will not require 2fa data as long as the conditions
                    // for sms backup are met
                    m_twofactor_data = { { "is_sms_backup", true } };
                }
                const auto data = j_str_or_empty(m_details, "data");
                m_auth_data = m_session->init_enable_twofactor(m_method_to_update, data, m_twofactor_data);
            } else {
                // gauth doesn't have an init_enable step
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
    update_subaccount_call::update_subaccount_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "update_subaccount")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type update_subaccount_call::call_impl()
    {
        m_session->ensure_full_session();

        const auto subaccount = j_uint32ref(m_details, "subaccount");
        m_session->update_subaccount(subaccount, m_details);
        return state_type::done;
    }

    //
    // Change limits
    //
    change_limits_call::change_limits_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "twofactor_change_limits")
        , m_limit_details(std::move(details))
        , m_initialized(false)
    {
    }

    auth_handler::state_type change_limits_call::call_impl()
    {
        if (!m_initialized) {
            if (m_net_params.is_electrum()) {
                throw user_error("Spending limits cannot be set for singlesig wallets");
            }
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
                const auto converted = m_session->convert_amount(details);
                m_limit_details["total"] = j_amountref(converted).value();
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
    send_transaction_call::send_transaction_call(session& session, nlohmann::json details, bool sign_only)
        : auth_handler_impl(session, sign_only ? "sign_transaction" : "send_transaction")
        , m_details(std::move(details))
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
        if (!m_details.empty()) {
            m_details.erase("utxos"); // Not needed anymore
        }
        if (!j_str_is_empty(m_details, "error")) {
            // Can't send a tx with an error, return it as-is
            m_result = std::move(m_details);
            m_state = state_type::done;
            return;
        }

        signal_2fa_request(m_type + "_raw_tx");
        m_twofactor_required = m_state == state_type::request_code;
        Tx tx(j_strref(m_details, "transaction"), m_net_params.is_liquid());
        auto [user_signed, server_signed, sweep_signed, has_sweeps]
            = tx_get_user_server_sweep_signed(*m_session, m_details, tx);

        if (m_twofactor_required && server_signed) {
            // Already server signed, no need for 2fa
            m_twofactor_required = false;
            m_state = state_type::make_call;
        }

        if (m_twofactor_required && !m_net_params.is_liquid() && !m_net_params.is_electrum()) {
            // Avoid 2FA if this tx is under the users spending limit
            auto user_limits = m_twofactor_required ? m_session->get_spending_limits() : nlohmann::json({});
            if (user_limits.value("is_fiat", false)) {
                try {
                    user_limits = m_session->convert_amount(user_limits);
                } catch (const std::exception& ex) {
                    // If the fiat limit cannot be converted, require 2FA
                    GDK_LOG(warning) << "2FA limit unavailable: " << ex.what();
                    user_limits.clear();
                }
            }
            const auto limit = j_amount_or_zero(user_limits);
            amount::value_type satoshi = 0;
            for (const auto& o : m_details.at("transaction_outputs")) {
                if (!o.value("is_change", false)) {
                    satoshi += j_amountref(o).value();
                }
            }
            const auto fee = j_amountref(m_details, "fee").value();

            m_limit_details = { { "asset", "BTC" }, { "amount", satoshi + fee }, { "fee", fee },
                { "change_idx", get_tx_change_index(m_details, "btc").value_or(-1) } };

            // If this transaction has a previous transaction, i.e. it is replacing a previous transaction
            // for example by RBF, then define m_bump_amount as the additional cost of this transaction
            // compared to the original
            const auto previous_transaction = m_details.find("previous_transaction");
            if (previous_transaction != m_details.end()) {
                const auto previous_fee = j_amountref(*previous_transaction, "fee");
                GDK_RUNTIME_ASSERT(previous_fee < fee);
                m_bump_amount = fee - previous_fee.value();
            }

            // limit_delta is the amount to deduct from the current spending limit for this tx
            // For a fee bump (RBF) it is just the bump amount, i.e. the additional fee, because the
            // previous fee and tx amount has already been deducted from the limits
            const uint64_t limit_delta = m_bump_amount != 0u ? m_bump_amount : satoshi + fee;

            if (limit.value() && limit_delta <= limit.value()) {
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
            j_rename(m_twofactor_data, "fee", m_type + "_raw_tx_fee");
            j_rename(m_twofactor_data, "change_idx", m_type + "_raw_tx_change_idx");

            std::string key = m_bump_amount ? "bump_fee_amount" : (m_type + "_raw_tx_amount");
            j_rename(m_twofactor_data, "amount", key);
        }

        // TODO: Add the recipient to twofactor_data for more server verification?

        const bool is_partial = m_details.value("is_partial", false);
        if (m_type == "send") {
            m_result = m_session->send_transaction(m_details, m_twofactor_data);
        } else {
            std::vector<std::vector<unsigned char>> old_scripts;
            const bool is_partial_multisig = is_partial && !m_net_params.is_electrum();
            if (is_partial_multisig) {
                // Multisig partial signing. Ensure all inputs to be signed are segwit
                auto& inputs = m_details.at("transaction_inputs");
                for (const auto& utxo : inputs) {
                    const auto addr_type = j_str_or_empty(utxo, "address_type");
                    if (!addr_type.empty() && !address_type_is_segwit(addr_type)) {
                        throw user_error("Non-segwit utxos cannnot be used with partial signing");
                    }
                }
                // Replace tx input scriptSigs with redeem scripts so the Green
                // backend can ensure they are segwit for partial signing
                Tx tx(j_strref(m_details, "transaction"), m_net_params.is_liquid());
                size_t i = 0;
                bool have_redeem_scripts = false;
                for (auto& utxo : inputs) {
                    const auto& txin = tx.get()->inputs[i];
                    if (utxo.contains("redeem_script")) {
                        old_scripts.push_back({ txin.script, txin.script + txin.script_len });
                        const auto redeem_script = j_bytesref(utxo, "redeem_script");
                        tx.set_input_script(i, script_push_from_bytes(redeem_script));
                        have_redeem_scripts = true;
                    } else {
                        old_scripts.push_back({});
                    }
                    ++i;
                }
                if (!have_redeem_scripts) {
                    old_scripts.clear();
                }
                m_details["transaction"] = tx.to_hex();
            }
            m_result = m_session->service_sign_transaction(m_details, m_twofactor_data, old_scripts);
        }
        return state_type::done;
    }

    //
    // Sign Message
    //
    sign_message_call::sign_message_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "sign_message")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type sign_message_call::call_impl()
    {
        GDK_RUNTIME_ASSERT_MSG(m_net_params.is_electrum() && !m_net_params.is_liquid(), "Invalid network");
        auto signer = get_signer();

        if (m_address_data.empty()) {
            // Get address data and request the xpub for signing
            m_address_data = m_session->get_address_data(m_details);
            auto& paths = signal_hw_request(hw_request::get_xpubs)["paths"];
            paths.emplace_back(m_address_data.at("user_path"));
            return m_state;
        }
        if (m_hw_request == hw_request::get_xpubs) {
            // Caller has provided the xpub for the address to sign.
            // Store it and ask the signer to sign the message
            m_address_data["xpub"] = j_arrayref(get_hw_reply(), "xpubs").at(0);

            auto& request = signal_hw_request(hw_request::sign_message);
            request["path"] = m_address_data.at("user_path");
            request["message"] = m_details.at("message");
            add_required_ae_data(signer, request);
            return m_state;
        }
        // Caller has provided the signed message.
        GDK_RUNTIME_ASSERT(m_hw_request == hw_request::sign_message);
        const auto& hw_reply = get_hw_reply();
        auto bip32_xpub = signer->get_bip32_xpub(m_address_data.at("user_path"));
        auto xpub_hdkey = bip32_public_key_from_bip32_xpub(bip32_xpub);

        // Get the compact and recoverable signatures from the DER/compact/recoverable signature
        const auto sig = j_bytesref(hw_reply, "signature");
        ecdsa_sig_t compact_sig;
        ecdsa_sig_rec_t recoverable_sig;
        if (sig[0] == 48 || sig.size() == 64) {
            if (sig[0] == 48) {
                // DER format
                constexpr bool has_sighash_byte = false;
                compact_sig = ec_sig_from_der(sig, has_sighash_byte);
            } else {
                // Compact format
                std::copy(sig.begin(), sig.end(), compact_sig.begin());
            }
            const auto& message = j_strref(m_twofactor_data, "message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
            recoverable_sig = ec_sig_rec_from_compact(compact_sig, message_hash, xpub_hdkey->pub_key);
        } else if (sig.size() == 65) {
            // Recoverable format
            std::copy(sig.begin(), sig.end(), recoverable_sig.begin());
            std::copy(sig.begin() + 1, sig.end(), compact_sig.begin());
        } else {
            GDK_RUNTIME_ASSERT_MSG(false, "Invalid signature");
        }

        if (signer->use_ae_protocol()) {
            const auto signer_commitment = j_bytesref(hw_reply, "signer_commitment");
            verify_ae_message(m_twofactor_data, xpub_hdkey->pub_key, signer_commitment, compact_sig);
        }

        m_result["signature"] = base64_from_bytes(recoverable_sig);
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
    locktime_call::locktime_call(session& session, nlohmann::json params, bool is_csv)
        : auth_handler_impl(session, is_csv ? "set_csvtime" : "set_nlocktime")
        , m_params(std::move(params))
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

    //
    // Get credentials
    //
    get_credentials_call::get_credentials_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "get_credentials")
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type get_credentials_call::call_impl()
    {
        const auto signer = get_signer();
        m_result = signer->get_credentials();
        const auto password = j_str_or_empty(m_details, "password");
        if (!password.empty()) {
            // Encrypt the mnemonic credentials with the supplied password
            GDK_RUNTIME_ASSERT(m_result.contains("mnemonic"));
            GDK_RUNTIME_ASSERT_MSG(!m_result.contains("bip39_passphrase"), "cannot use password and bip39_passphrase");
            m_result["mnemonic"] = signer->get_mnemonic(password);
            m_result["password"] = password;
        }
        if (m_result.contains("username")) {
            m_result.erase("password");
        }
        return state_type::done;
    }

    //
    // Encrypt with PIN
    //
    encrypt_with_pin_call::encrypt_with_pin_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "encrypt_with_pin", {})
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type encrypt_with_pin_call::call_impl()
    {
        m_result["pin_data"] = m_session->encrypt_with_pin(m_details);
        return state_type::done;
    }

    //
    // Decrypt with PIN
    //
    decrypt_with_pin_call::decrypt_with_pin_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "decrypt_with_pin", {})
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type decrypt_with_pin_call::call_impl()
    {
        m_result = m_session->decrypt_with_pin(m_details);
        return state_type::done;
    }

} // namespace green
