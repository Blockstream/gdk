#include <boost/algorithm/string/trim.hpp>

#include "client_blob.hpp"
#include "exception.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "signer.hpp"
#include "utils.hpp"

namespace green {

    namespace {
        static const std::string ZERO_HMAC_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        static const std::string ONE_HMAC_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=";

        // Types of data stored in the client blob
        constexpr uint32_t USER_VERSION = 0; // User incremented version number
        constexpr uint32_t SA_NAMES = 1; // Subaccount names
        constexpr uint32_t TX_MEMOS = 2; // Transaction memos
        constexpr uint32_t SA_HIDDEN = 3; // Subaccounts that are hidden
        constexpr uint32_t SLIP77KEY = 4; // Master blinding key
        constexpr uint32_t WATCHONLY = 5; // Watch-only data
        constexpr uint32_t ENCRYPTED = 6; // Holds which (if any) blob data is further encrypted

        // blob prefix: 1 byte version, 3 reserved bytes
        static const std::array<unsigned char, 4> PREFIX{ 1, 0, 0, 0 };

        // Increment the blob version number. Returns true as the blob has changed.
        static bool increment_version(nlohmann::json& data)
        {
            auto& p = data[USER_VERSION];
            uint64_t version = p;
            p = version + 1;
            return true;
        }

        // Set a value to a JSON object if it is non-default, otherwise remove any existing value.
        // This saves space storing the value if a default value is returned when its fetched.
        // Returns true if the JSON object was changed.
        template <typename T, typename = std::enable_if_t<std::is_default_constructible<T>::value>>
        static bool json_add_non_default(nlohmann::json& data, const std::string& key, const T& value)
        {
            const bool is_default = value == T(); // NOLINT: readability-container-size-empty
            const auto p = data.find(key);
            const bool found = p != data.end();
            if (is_default) {
                if (found) {
                    data.erase(p); // Remove existing value
                    return true;
                }
                return false;
            }
            if (found) {
                if (*p == value) {
                    return false;
                }
                *p = value; // Overwrite existing value
                return true;
            }
            data[key] = value; // Insert new value
            return true;
        }
    } // namespace

    client_blob::client_blob() { reset(); }

    void client_blob::reset()
    {
        m_data = nlohmann::json();
        m_data[USER_VERSION] = static_cast<uint64_t>(0);
        // Pre-create top level json objects for future cached items,
        // allowing later additions to be checked for without special cases
        for (uint32_t i = SA_NAMES; i < 32u; ++i) {
            m_data[i] = nlohmann::json();
        }
        m_client_id.clear();
        m_key.reset();
        m_hmac_key.reset();
        m_hmac.clear();
        m_is_outdated = false;
        m_is_modified = false;
        m_requires_merge = false;
        m_server_is_mandatory = false;
    }

    void client_blob::compute_client_id(const std::string& network, byte_span_t key)
    {
        // Our client id is private: sha256(network | client secret pubkey)
        std::vector<unsigned char> id_buffer(network.size() + key.size());
        init_container(id_buffer, ustring_span(network), key);
        m_client_id = b2h(sha256(id_buffer));
    }

    void client_blob::set_key(pbkdf2_hmac256_t key) { set_optional_variable(m_key, std::move(key)); }

    void client_blob::compute_keys(byte_span_t public_key)
    {
        // Compute the encryption and HMAC keys
        const auto tmp_key = pbkdf2_hmac_sha512(public_key, signer::BLOB_SALT);
        const auto tmp_span = gsl::make_span(tmp_key);
        set_optional_variable(m_key, sha256(tmp_span.subspan(SHA256_LEN)));
        set_optional_variable(m_hmac_key, make_byte_array<SHA256_LEN>(tmp_span.subspan(SHA256_LEN, SHA256_LEN)));
    }

    bool client_blob::has_key() const { return m_key.has_value(); }

    pbkdf2_hmac256_t client_blob::get_key() const
    {
        GDK_RUNTIME_ASSERT(has_key());
        return m_key.value();
    }

    bool client_blob::has_hmac_key() const { return m_hmac_key.has_value(); }

    bool client_blob::on_update(const std::string& new_hmac)
    {
        if (m_hmac != new_hmac) {
            m_is_outdated = true;
            return true;
        }
        return false;
    }

    bool client_blob::is_key_encrypted(uint32_t key) const
    {
        const auto& parent = m_data[ENCRYPTED];
        if (parent.contains("items")) {
            const auto& items = parent["items"];
            return std::find(items.begin(), items.end(), key) != items.end();
        }
        return false;
    }

    void client_blob::set_user_version(uint64_t version) { m_data[USER_VERSION] = version; }

    uint64_t client_blob::get_user_version() const { return m_data[USER_VERSION]; }

    bool client_blob::update_subaccounts_data(const nlohmann::json& subaccounts, const nlohmann::json& xpubs)
    {
        if (is_key_encrypted(SA_NAMES)) {
            // This gdk version does not support encrypted subaccount names
            throw user_error("Client too old. Please upgrade your app!"); // TODO: i18n
        }
        bool changed = false;

        for (const auto& sa : subaccounts.items()) {
            if (auto name = j_str(sa.value(), "name"); name.has_value()) {
                GDK_RUNTIME_ASSERT_MSG(is_valid_utf8(name.value()), "Subaccount name is not a valid utf-8 string");
                changed |= json_add_non_default(m_data[SA_NAMES], sa.key(), name.value());
            }
            if (auto is_hidden = j_bool(sa.value(), "hidden"); is_hidden.has_value()) {
                changed |= json_add_non_default(m_data[SA_HIDDEN], sa.key(), is_hidden.value());
            }
        }
        // Update the subaccount xpubs
        changed |= merge_xpubs(xpubs);
        return changed ? increment_version(m_data) : changed;
    }

    nlohmann::json client_blob::get_subaccounts_data() const
    {
        nlohmann::json ret{};

        if (is_key_encrypted(SA_NAMES)) {
            // This gdk version does not support encrypted subaccount names
            throw user_error("Client too old. Please upgrade your app!"); // TODO: i18n
        }
        for (const auto& item : m_data[SA_NAMES].items()) {
            ret[item.key()] = { { "name", item.value() } };
        }
        for (const auto& item : m_data[SA_HIDDEN].items()) {
            ret[item.key()].update({ { "hidden", item.value() } });
        }
        return ret;
    }

    nlohmann::json client_blob::get_subaccount_data(uint32_t subaccount) const
    {
        const auto subaccount_str(std::to_string(subaccount));
        auto is_hidden = j_bool(m_data[SA_HIDDEN], subaccount_str);
        std::optional<std::string> name;
        if (!is_key_encrypted(SA_NAMES)) {
            name = j_str(m_data[SA_NAMES], subaccount_str);
        }
        nlohmann::json ret({});
        if (name.has_value()) {
            ret["name"] = std::move(name.value());
        }
        if (is_hidden.has_value()) {
            ret["hidden"] = is_hidden.value();
        }
        return ret;
    }

    bool client_blob::set_tx_memo(const std::string& txhash_hex, const std::string& memo)
    {
        if (is_key_encrypted(TX_MEMOS)) {
            // This gdk version does not support encrypted memos
            throw user_error("Client too old. Please upgrade your app!"); // TODO: i18n
        }
        const std::string trimmed = boost::algorithm::trim_copy(memo);
        bool changed = json_add_non_default(m_data[TX_MEMOS], txhash_hex, trimmed);
        return changed ? increment_version(m_data) : changed;
    }

    bool client_blob::update_tx_memos(const nlohmann::json& memos)
    {
        const auto version = get_user_version();
        for (const auto& m : memos.items()) {
            set_tx_memo(m.key(), m.value());
        }
        if (get_user_version() == version) {
            return false; // Nothing updated
        }
        set_user_version(version + 1);
        return true;
    }

    std::string client_blob::get_tx_memo(const std::string& txhash_hex) const
    {
        if (is_key_encrypted(TX_MEMOS)) {
            return {}; // Has been made unavailable to watch only sessions
        }
        return j_str_or_empty(m_data[TX_MEMOS], txhash_hex);
    }

    nlohmann::json client_blob::get_tx_memos() const
    {
        if (is_key_encrypted(TX_MEMOS)) {
            return {}; // Has been made unavailable to watch only sessions
        }
        return m_data[TX_MEMOS];
    }

    bool client_blob::set_master_blinding_key(const std::string& master_blinding_key_hex)
    {
        auto& unblinder = m_data[SLIP77KEY];
        bool changed = json_add_non_default(unblinder, "key", master_blinding_key_hex);
        changed |= json_add_non_default(unblinder, "denied", master_blinding_key_hex.empty());
        return changed ? increment_version(m_data) : changed;
    }

    std::string client_blob::get_master_blinding_key() const
    {
        return j_str_or_empty(m_data[SLIP77KEY], "key"); // Blank if denied
    }

    bool client_blob::is_master_blinding_key_denied() const
    {
        return j_bool_or_false(m_data[SLIP77KEY], "denied"); // False if not explicitly denied
    }

    bool client_blob::set_wo_data(const std::string& username, const nlohmann::json& xpubs)
    {
        bool changed = json_add_non_default(m_data[WATCHONLY], "username", username);
        changed |= merge_xpubs(xpubs);
        return changed ? increment_version(m_data) : changed;
    }

    bool client_blob::merge_xpubs(const nlohmann::json& xpubs)
    {
        bool changed = false;
        auto& dest = m_data[WATCHONLY]["xpubs"];
        for (const auto& xpub : xpubs.items()) {
            if (!dest.contains(xpub.key())) {
                dest.emplace(xpub.key(), xpub.value());
                changed = true;
            }
        }
        return changed;
    }

    bool client_blob::set_xpubs(const nlohmann::json& xpubs)
    {
        bool changed = merge_xpubs(xpubs);
        return changed ? increment_version(m_data) : changed;
    }

    std::string client_blob::get_wo_username() const
    {
        return j_str_or_empty(m_data[WATCHONLY], "username"); // Blank if unset
    }

    nlohmann::json client_blob::get_xpubs() const
    {
        auto& wo = m_data[WATCHONLY];
        if (auto xpubs_p = wo.find("xpubs"); xpubs_p != wo.end()) {
            return *xpubs_p;
        }
        return {};
    }

    nlohmann::json::array_t client_blob::get_bip329() const
    {
        nlohmann::json::array_t items;
        const auto memos = get_tx_memos();
        for (const auto& memo : memos.items()) {
            nlohmann::json line = { { "type", "tx" }, { "ref", memo.key() }, { "label", memo.value() } };
            items.emplace_back(std::move(line));
        }
        // TODO: Once subaccounts/addresses are in the blob, add them here
        // instead of having the session do it
        return items;
    }

    const std::string& client_blob::get_zero_hmac() { return ZERO_HMAC_BASE64; }

    const std::string& client_blob::get_one_hmac() { return ONE_HMAC_BASE64; }

    std::string client_blob::compute_hmac(byte_span_t data) const
    {
        GDK_RUNTIME_ASSERT(m_hmac_key.has_value());
        return base64_from_bytes(hmac_sha256(*m_hmac_key, data));
    }

    void client_blob::load(byte_span_t data, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(m_key.has_value());

        // Decrypt the encrypted data
        std::vector<unsigned char> decrypted(aes_gcm_decrypt_get_length(data));
        GDK_RUNTIME_ASSERT(decrypted.size() > PREFIX.size());
        GDK_RUNTIME_ASSERT(aes_gcm_decrypt(*m_key, data, decrypted) == decrypted.size());

        // Only one fixed prefix value is currently allowed, check we match it
        GDK_RUNTIME_ASSERT(memcmp(decrypted.data(), PREFIX.data(), PREFIX.size()) == 0);

        // Decompress the compressed representation excluding PREFIX
        auto decompressed = decompress(gsl::make_span(decrypted).subspan(PREFIX.size()));

        // Clear and free the decrypted representation immediately
        bzero_and_free(decrypted);

        // Load our blob data from the uncompressed data in msgpack format
        auto new_data = nlohmann::json::from_msgpack(decompressed.begin(), decompressed.end());
        // Clear and free the decompressed representation immediately
        bzero_and_free(decompressed);

        // Check that the new blob has a higher version number:
        // This check prevents the server maliciously returning an old blob
        const uint64_t new_version = new_data[USER_VERSION];
        const uint64_t current_version = get_user_version();
        GDK_LOG(info) << "Load blob ver " << new_version << " over " << current_version;
        if (m_server_is_mandatory) {
            // Check that the client version doesn't regress. This can only
            // be checked if the server is mandatory
            // Allow to load a v1 blob over a v1 blob for initial creation races
            const bool is_newer = new_version >= current_version || (current_version == 1 && new_version == 1);
            GDK_RUNTIME_ASSERT_MSG(is_newer, "Server returned an outdated client blob");
        }

        if (!m_requires_merge) {
            m_data.swap(new_data);
            m_hmac = hmac;
            m_is_modified = false;
            return;
        }
        // Merge the existing metadata into the current blob
        auto subaccounts_data = get_subaccounts_data();
        auto xpubs = get_xpubs();
        auto tx_memos = get_tx_memos();
        const auto version = get_user_version();
        m_data.swap(new_data);
        update_subaccounts_data(subaccounts_data, xpubs);
        update_tx_memos(tx_memos);
        m_is_modified = version != get_user_version();
        if (m_is_modified) {
            set_user_version(version + 1);
        }
        // Do not update m_requires_merge, it will be reset once the blob is saved
        m_hmac = hmac;
    }

    std::pair<std::vector<unsigned char>, nlohmann::json> client_blob::save() const
    {
        GDK_RUNTIME_ASSERT(m_key.has_value());

        // Dump out data to msgpack format and compress it, prepending PREFIX
        auto msgpack_data{ nlohmann::json::to_msgpack(m_data) };
        auto compressed{ compress(PREFIX, msgpack_data) };

        // Clear and free the uncompressed representation immediately
        bzero_and_free(msgpack_data);

        // Encrypt the compressed representation
        std::vector<unsigned char> encrypted(aes_gcm_encrypt_get_length(compressed));
        GDK_RUNTIME_ASSERT(aes_gcm_encrypt(*m_key, compressed, encrypted) == encrypted.size());

        // Clear and free the compressed representation immediately
        bzero_and_free(compressed);

        // Compute and return base64 encoded data and its HMAC
        nlohmann::json details = { { "hmac", compute_hmac(encrypted) }, { "blob", base64_from_bytes(encrypted) } };
        return std::make_pair(std::move(encrypted), std::move(details));
    }

} // namespace green
