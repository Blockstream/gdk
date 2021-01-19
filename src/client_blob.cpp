#include "client_blob.hpp"
#include "containers.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static const std::string ZERO_HMAC_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        // Types of data stored in the client blob
        constexpr uint32_t USER_VERSION = 0; // User incremented version number
        constexpr uint32_t SA_NAMES = 1; // Subaccount names
        constexpr uint32_t TX_MEMOS = 2; // Transaction memos

        // blob prefix: 1 byte version, 3 reserved bytes
        static const std::array<unsigned char, 4> PREFIX{ 1, 0, 0, 0 };

        static void increment_version(nlohmann::json& data)
        {
            auto& p = data[USER_VERSION];
            uint64_t version = p;
            p = version + 1;
        }
    } // namespace

    client_blob::client_blob()
        : m_data()
    {
        m_data[SA_NAMES] = nlohmann::json();
        m_data[TX_MEMOS] = nlohmann::json();
        m_data[USER_VERSION] = static_cast<uint64_t>(0);
    }

    void client_blob::set_user_version(uint64_t version) { m_data[USER_VERSION] = version; }

    uint64_t client_blob::get_user_version() const { return m_data[USER_VERSION]; }

    bool client_blob::set_subaccount_name(uint32_t subaccount, const std::string& name)
    {
        bool changed = json_add_non_default(m_data[SA_NAMES], std::to_string(subaccount), name);
        if (changed) {
            increment_version(m_data);
        }
        return changed;
    }

    std::string client_blob::get_subaccount_name(uint32_t subaccount) const
    {
        return json_get_value(m_data[SA_NAMES], std::to_string(subaccount));
    }

    bool client_blob::set_tx_memo(const std::string& txhash_hex, const std::string& memo)
    {
        bool changed = json_add_non_default(m_data[TX_MEMOS], txhash_hex, memo);
        if (changed) {
            increment_version(m_data);
        }
        return changed;
    }

    std::string client_blob::get_tx_memo(const std::string& txhash_hex) const
    {
        return json_get_value(m_data[TX_MEMOS], txhash_hex);
    }

    bool client_blob::is_zero_hmac(const std::string& hmac) { return hmac == ZERO_HMAC_BASE64; }

    std::string client_blob::compute_hmac(byte_span_t hmac_key, byte_span_t data)
    {
        return base64_from_bytes(hmac_sha256(hmac_key, data));
    }

    void client_blob::load(byte_span_t key, byte_span_t data)
    {
        // Decrypt the encrypted data
        std::vector<unsigned char> decrypted(aes_gcm_decrypt_get_length(data));
        GDK_RUNTIME_ASSERT(decrypted.size() > PREFIX.size());
        GDK_RUNTIME_ASSERT(aes_gcm_decrypt(key, data, decrypted) == decrypted.size());

        // Only one fixed prefix value is currently allowed, check we match it
        GDK_RUNTIME_ASSERT(memcmp(decrypted.data(), PREFIX.data(), PREFIX.size()) == 0);

        // Decompress the compressed representation excluding PREFIX
        const auto decompressed = decompress(gsl::make_span(decrypted).subspan(PREFIX.size()));

        // Clear and free the decrypted representation immediately
        bzero_and_free(decrypted);

        // Load our blob data from the uncompressed data in msgpack format
        auto new_data = nlohmann::json::from_msgpack(decompressed.begin(), decompressed.end());

        // Check that the new blob has a higher version number:
        // This check prevents the server maliciously returning an old blob
        const uint64_t new_version = new_data[USER_VERSION];
        const uint64_t current_version = get_user_version();
        GDK_LOG_SEV(log_level::info) << "Load blob ver " << new_version << " over " << current_version;
        // Allow to load a v1 blob over a v1 blob for initial creation races
        const bool is_newer = new_version > current_version || (current_version == 1 && new_version == 1);
        GDK_RUNTIME_ASSERT_MSG(is_newer, "Server returned an outdated client blob");

        m_data.swap(new_data);
    }

    std::pair<std::vector<unsigned char>, std::string> client_blob::save(byte_span_t key, byte_span_t hmac_key) const
    {
        // Dump out data to msgpack format and compress it, prepending PREFIX
        auto msgpack_data{ nlohmann::json::to_msgpack(m_data) };
        auto compressed{ compress(PREFIX, msgpack_data) };

        // Clear and free the uncompressed representation immediately
        bzero_and_free(msgpack_data);

        // Encrypt the compressed representation
        std::vector<unsigned char> encrypted(aes_gcm_encrypt_get_length(compressed));
        GDK_RUNTIME_ASSERT(aes_gcm_encrypt(key, compressed, encrypted) == encrypted.size());

        // Clear and free the compressed representation immediately
        bzero_and_free(compressed);

        // Compute hmac of the final representation and return it with the encrypted data
        auto hmac{ compute_hmac(hmac_key, encrypted) };
        return std::make_pair(std::move(encrypted), std::move(hmac));
    }

} // namespace sdk
} // namespace ga
