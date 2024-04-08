#ifndef GDK_CLIENT_BLOB_HPP
#define GDK_CLIENT_BLOB_HPP
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>

#include "ga_wally.hpp"
#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {

    // Client-only data, stored on a server as a server-unreadable blob
    class client_blob final {
    public:
        client_blob();
        client_blob(const client_blob&) = delete;
        client_blob& operator=(const client_blob&) = delete;
        client_blob(client_blob&&) = delete;
        client_blob& operator=(client_blob&&) = delete;

        void reset();

        void set_user_version(uint64_t version);
        uint64_t get_user_version() const;

        bool update_subaccount_data(uint32_t subaccount, const nlohmann::json& details, const nlohmann::json& xpubs);
        nlohmann::json get_subaccount_data(uint32_t subaccount) const;

        bool set_tx_memo(const std::string& txhash_hex, const std::string& memo);
        std::string get_tx_memo(const std::string& txhash_hex) const;

        bool set_master_blinding_key(const std::string& master_blinding_key_hex);
        std::string get_master_blinding_key() const;
        bool is_master_blinding_key_denied() const;

        bool set_wo_data(const std::string& username, const nlohmann::json& xpubs);
        bool set_xpubs(const nlohmann::json& xpubs);
        std::string get_wo_username() const;
        nlohmann::json get_xpubs() const;

        void load(byte_span_t key, byte_span_t data);
        std::pair<std::vector<unsigned char>, std::string> save(byte_span_t key, byte_span_t hmac_key) const;

        static const std::string& get_zero_hmac();
        static const std::string& get_one_hmac();
        static std::string compute_hmac(byte_span_t hmac_key, byte_span_t data);

    private:
        bool is_key_encrypted(uint32_t key) const;

        nlohmann::json m_data;
    };

} // namespace sdk
} // namespace ga

#endif
