#ifndef GDK_CLIENT_BLOB_HPP
#define GDK_CLIENT_BLOB_HPP
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>

#include "ga_wally.hpp"
#include <nlohmann/json.hpp>

namespace green {

    // Client-only data, stored on a server as a server-unreadable blob
    class client_blob final {
    public:
        client_blob();
        client_blob(const client_blob&) = delete;
        client_blob& operator=(const client_blob&) = delete;
        client_blob(client_blob&&) = delete;
        client_blob& operator=(client_blob&&) = delete;

        void reset();

        // Compute the client id to use
        void compute_client_id(const std::string& network, byte_span_t key);
        auto get_client_id() const { return m_client_id; }

        // Set the encryption key
        void set_key(pbkdf2_hmac256_t key);
        // Compute the encryption and HMAC keys from a privately derived public key
        void compute_keys(byte_span_t public_key);

        bool has_key() const;
        pbkdf2_hmac256_t get_key() const;
        bool has_hmac_key() const;

        void set_hmac(const std::string& hmac) { m_hmac = hmac; }
        const std::string& get_hmac() const { return m_hmac; }

        bool get_server_is_mandatory() { return m_server_is_mandatory; }
        void set_server_is_mandatory() { m_server_is_mandatory = true; }

        bool is_outdated() const { return m_is_outdated; }
        void set_is_outdated() { m_is_outdated = true; }
        void unset_is_outdated() { m_is_outdated = false; }

        bool is_modified() const { return m_is_modified; }
        void set_is_modified() { m_is_modified = true; }
        void unset_is_modified() { m_is_modified = true; }

        bool get_requires_merge() const { return m_requires_merge; }
        void set_requires_merge() { m_requires_merge = true; }
        void unset_requires_merge() { m_requires_merge = false; }

        // Mark the blob outdated if the new_hmac is not our current hmac.
        bool on_update(const std::string& new_hmac);

        void set_user_version(uint64_t version);
        uint64_t get_user_version() const;

        bool update_subaccounts_data(const nlohmann::json& subaccounts, const nlohmann::json& xpubs);
        nlohmann::json get_subaccounts_data() const;
        nlohmann::json get_subaccount_data(uint32_t subaccount) const;

        bool set_tx_memo(const std::string& txhash_hex, const std::string& memo);
        bool update_tx_memos(const nlohmann::json& memos);
        std::string get_tx_memo(const std::string& txhash_hex) const;
        nlohmann::json get_tx_memos() const;

        bool set_master_blinding_key(const std::string& master_blinding_key_hex);
        std::string get_master_blinding_key() const;
        bool is_master_blinding_key_denied() const;

        bool set_wo_data(const std::string& username, const nlohmann::json& xpubs);
        bool set_xpubs(const nlohmann::json& xpubs);
        std::string get_wo_username() const;
        nlohmann::json get_xpubs() const;

        void load(byte_span_t data, const std::string& hmac);

        std::pair<std::vector<unsigned char>, nlohmann::json> save() const;

        static const std::string& get_zero_hmac();
        static const std::string& get_one_hmac();
        std::string compute_hmac(byte_span_t data) const;

    private:
        bool is_key_encrypted(uint32_t key) const;

        bool merge_xpubs(const nlohmann::json& xpubs);

        nlohmann::json m_data;
        // Client id for talking to a blobserver
        std::string m_client_id;
        // Key for encrypting the client blob contents
        std::optional<pbkdf2_hmac256_t> m_key;
        // Key for generating blob HMAC. Only set if the
        // client blob is writable.
        std::optional<pbkdf2_hmac256_t> m_hmac_key;
        // The hmac of the last saved/loaded blob contents
        std::string m_hmac;
        // True if the blob is (or may be) outdated with respect to
        // any stored server blob.
        bool m_is_outdated;
        // True if the blob is modified locally from the last loaded state
        bool m_is_modified;
        // True if the blob has been modified while unsynced, and so must
        // be merged when next synced.
        bool m_requires_merge;
        // True if the blobserver connection is mandatory (i.e. if using the
        // Green server to provide the client blob
        bool m_server_is_mandatory;
    };

} // namespace green

#endif
