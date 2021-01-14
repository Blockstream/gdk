#include "client_blob.hpp"
#include "containers.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "utils.hpp"

// FIXME:
// - Use smarter (binary) serialisation with versioning
// - Store user version in blob to prevent server old blob replay
// - Compress and encrypt binary blob data when loading/storing
// - Serialize memos so they compress better

namespace ga {
namespace sdk {

    namespace {
        static const std::string ZERO_HMAC_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        constexpr uint32_t SA_NAMES = 0; // Subaccount names
        constexpr uint32_t TX_MEMOS = 1; // Transaction memos
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

    std::string client_blob::compute_hmac(const pbkdf2_hmac512_t& key, const byte_span_t& data)
    {
        return base64_from_bytes(hmac_sha256(key, data));
    }

    void client_blob::load(const byte_span_t& data) { m_data = nlohmann::json::parse(data.begin(), data.end()); }

    std::pair<std::vector<unsigned char>, std::string> client_blob::save(const pbkdf2_hmac512_t& key) const
    {
        const std::string data = m_data.dump();
        const auto data_span = ustring_span(data);
        return std::make_pair(
            std::vector<unsigned char>(data_span.begin(), data_span.end()), compute_hmac(key, data_span));
    }

} // namespace sdk
} // namespace ga
