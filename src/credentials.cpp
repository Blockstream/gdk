
#include <algorithm>
#include <nlohmann/json.hpp>

#include "assertion.hpp"
#include "credentials.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "json_utils.hpp"
#include "utils.hpp"

namespace green {
    namespace {

        struct ToJsonVisitor {
            nlohmann::json& json;
            void operator()(const std::monostate&) const
            {
                // Hardware wallet or remote service
            }
            void operator()(const wo_credentials& wo_credentials) const
            {
                json["username"] = wo_credentials.username;
                json["password"] = wo_credentials.password;
                json["raw_watch_only_data"] = wo_credentials.raw_data;
                json["watch_only_data"] = wo_credentials.data;
            }
            void operator()(const mnemonic_credentials& mnemonic_credentials) const
            {
                json["mnemonic"] = mnemonic_credentials.mnemonic;
                json["seed"] = b2h(mnemonic_credentials.seed);
                if (mnemonic_credentials.passphrase.has_value()) {
                    json["bip39_passphrase"] = mnemonic_credentials.passphrase.value();
                }
            }
            void operator()(const seed_credentials& seed_credentials) const
            {
                json["seed"] = b2h(seed_credentials.seed);
            }
            void operator()(const core_descriptors_credentials& core_descs) const
            {
                json["core_descriptors"] = core_descs.descriptors;
            }
            void operator()(const slip132_credentials& slip132_credentials) const
            {
                json["slip132_extended_pubkeys"] = slip132_credentials.xpubs;
            }
        };
    } // namespace

    struct wo_credentials wo_credentials::normalize_credentials(const nlohmann::json& blob)
    {
        const auto& username = j_strref(blob, "username");
        const auto& password = j_strref(blob, "password");
        struct wo_credentials ret;
        ret.username = username;
        ret.password = password;
        auto raw_data = j_str_or_empty(blob, "raw_watch_only_data");
        auto data = j_str_or_empty(blob, "watch_only_data");
        if (!raw_data.empty() || !data.empty()) {
            // Blobserver rich watch-only login
            const auto entropy = compute_watch_only_entropy(username, password);
            if (raw_data.empty()) {
                raw_data = b2h(decrypt_watch_only_data(entropy, data));
            } else if (data.empty()) {
                data = encrypt_watch_only_data(entropy, h2b(raw_data));
            }
            constexpr auto expected_size = (pub_key_t().size() + pbkdf2_hmac256_t().size()) * 2;
            if (raw_data.size() != expected_size) {
                // Decrypted to the wrong length: invalid username, password
                // or watch-only data.
                throw user_error(res::id_user_not_found_or_invalid);
            }
            ret.raw_data = std::move(raw_data);
            ret.data = std::move(data);
        }
        return ret;
    }

    void to_json(nlohmann::json& json, const credentials& credentials)
    {
        std::visit(ToJsonVisitor{ json }, credentials);
    }

    void from_json(const nlohmann::json& blob, credentials& creds)
    {
        if (blob.empty()) {
            // Hardware wallet or remote service
            creds = std::monostate{};
            return;
        }

        const std::optional<std::string> username = j_str(blob, "username");
        if (username) {
            // Watch-only login
            creds = wo_credentials::normalize_credentials(blob);
            return;
        }

        std::optional<std::string> user_mnemonic = j_str(blob, "mnemonic");
        if (user_mnemonic) {
            // Mnemonic, or a hex seed
            std::string mnemonic = user_mnemonic.value();
            std::optional<std::string> bip39_passphrase = j_str(blob, "bip39_passphrase");
            if (bip39_passphrase.value_or(std::string()).empty()) {
                // for the sake of parsing, empty passphrase equals to no passphrase
                bip39_passphrase = std::nullopt;
            }
            if (mnemonic.find(' ') != std::string::npos) {
                // Mnemonic, possibly encrypted
                std::optional<std::string> password = j_str(blob, "password");
                GDK_RUNTIME_ASSERT_MSG(!(password && bip39_passphrase), "cannot use bip39_passphrase and password");
                mnemonic = decrypt_mnemonic(mnemonic, password.value_or(std::string()));
                std::vector<uint8_t> seed = bip39_mnemonic_to_seed(mnemonic, bip39_passphrase.value_or(std::string()));
                creds = mnemonic_credentials{ mnemonic, seed, bip39_passphrase };
                return;
            }
            if (mnemonic.size() == 129u && mnemonic.back() == 'X') {
                // Hex seed (a 512 bit bip32 seed encoding in hex with 'X' appended)
                GDK_RUNTIME_ASSERT_MSG(!bip39_passphrase, "cannot use bip39_passphrase and hex seed");
                mnemonic.pop_back();
                creds = seed_credentials{ h2b(mnemonic) };
                return;
            }
        }

        const auto slip132_xpubs = j_array(blob, "slip132_extended_pubkeys");
        const auto descriptors = j_array(blob, "core_descriptors");
        GDK_RUNTIME_ASSERT_MSG(
            !(descriptors && slip132_xpubs), "cannot use slip132_extended_pubkeys and core_descriptors");

        if (descriptors) {
            core_descriptors_credentials descs;
            descs.descriptors.resize(descriptors->size());
            std::transform(descriptors->begin(), descriptors->end(), descs.descriptors.begin(),
                [](const nlohmann::json& desc) { return desc.get<std::string>(); });
            creds = descs;
            return;
        }

        if (slip132_xpubs) {
            slip132_credentials xpubs;
            xpubs.xpubs.resize(slip132_xpubs->size());
            std::transform(slip132_xpubs->begin(), slip132_xpubs->end(), xpubs.xpubs.begin(),
                [](const nlohmann::json& xpub) { return xpub.get<std::string>(); });
            creds = xpubs;
            return;
        }
        throw user_error("Invalid credentials");
    }
} // namespace green
