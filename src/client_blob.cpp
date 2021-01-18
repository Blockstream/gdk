#include "client_blob.hpp"
#include "containers.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "utils.hpp"

// FIXME:
// - Store user version in blob to prevent server old blob replay

namespace ga {
namespace sdk {

    namespace {
        static const std::string ZERO_HMAC_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        constexpr uint32_t SA_NAMES = 0; // Subaccount names
        constexpr uint32_t TX_MEMOS = 1; // Transaction memos

        // blob prefix: 1 byte version, 3 reserved bytes
        static const std::array<unsigned char, 4> PREFIX{ 1, 0, 0, 0 };
    } // namespace

    client_blob::client_blob()
        : m_data()
    {
        m_data[SA_NAMES] = nlohmann::json();
        m_data[TX_MEMOS] = nlohmann::json();
    }

    void client_blob::set_subaccount_name(uint32_t subaccount, const std::string& name)
    {
        json_add_non_default(m_data[SA_NAMES], std::to_string(subaccount), name);
    }

    std::string client_blob::get_subaccount_name(uint32_t subaccount) const
    {
        return json_get_value(m_data[SA_NAMES], std::to_string(subaccount));
    }

    void client_blob::set_tx_memo(const std::string& txhash_hex, const std::string& memo)
    {
        json_add_non_default(m_data[TX_MEMOS], txhash_hex, memo);
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
        m_data = nlohmann::json::from_msgpack(decompressed.begin(), decompressed.end());
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
