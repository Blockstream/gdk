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

    // Client-only data, stored on the server as a server-unreadable blob
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

        bool set_subaccount_name(uint32_t subaccount, const std::string& name, const nlohmann::json& xpubs);
        std::string get_subaccount_name(uint32_t subaccount) const;

        bool set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        bool get_subaccount_hidden(uint32_t subaccount) const;

        bool set_tx_memo(const std::string& txhash_hex, const std::string& memo);
        std::string get_tx_memo(const std::string& txhash_hex) const;

        bool set_master_blinding_key(const std::string& master_blinding_key_hex);
        std::string get_master_blinding_key() const;
        bool is_master_blinding_key_denied() const;

        bool set_wo_data(const std::string& username, const nlohmann::json& xpubs);
        std::string get_wo_username() const;
        nlohmann::json get_xpubs() const;

        void load(byte_span_t key, byte_span_t data);
        std::pair<std::vector<unsigned char>, std::string> save(byte_span_t key, byte_span_t hmac_key) const;

        static bool is_zero_hmac(const std::string& hmac);
        static std::string compute_hmac(byte_span_t hmac_key, byte_span_t data);

    private:
        bool is_key_encrypted(uint32_t key) const;

        nlohmann::json m_data;
    };

} // namespace sdk
} // namespace ga

#endif
