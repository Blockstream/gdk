
#include <algorithm>
#include <nlohmann/json.hpp>

#include "assertion.hpp"
#include "credentials.hpp"
#include "exception.hpp"
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
            void operator()(const core_descriptors_credentials& core_desc_credentials) const
            {
                json["core_descriptors"] = core_desc_credentials.descriptors;
            }
            void operator()(const slip132_credentials& slip132_credentials) const
            {
                json["slip132_extended_pubkeys"] = slip132_credentials.xpubs;
            }
        };

    } // namespace

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
        if (username.has_value()) {
            // Watch-only login
            creds = wo_credentials{ username.value(), j_strref(blob, "password") };
            return;
        }
        std::optional<std::string> mnemonic_opt = j_str(blob, "mnemonic");
        if (mnemonic_opt.has_value()) {
            // Mnemonic login
            std::string mnemonic = mnemonic_opt.value();
            const std::optional<std::string> password = j_str(blob, "password");
            std::optional<std::string> passphrase = j_str(blob, "bip39_passphrase");
            if (passphrase.value_or(std::string()).empty()) {
                // for the sake of parsing, empty passphrase equals to no passphrase
                passphrase = std::nullopt;
            }
            GDK_RUNTIME_ASSERT_MSG(
                !(password.has_value() && passphrase.has_value()), "cannot use bip39_passphrase and password");
            if (mnemonic.size() == 129u && mnemonic.back() == 'X') {
                GDK_RUNTIME_ASSERT_MSG(!passphrase.has_value(), "cannot use bip39_passphrase and hex seed");
                mnemonic.pop_back();
                creds = seed_credentials{ h2b(mnemonic) };
                return;
            }
            mnemonic = decrypt_mnemonic(mnemonic, password.value_or(std::string()));
            creds = mnemonic_credentials{ mnemonic,
                bip39_mnemonic_to_seed(mnemonic, passphrase.value_or(std::string())), passphrase };
            return;
        }
        const auto descriptors = j_array(blob, "core_descriptors");
        const auto slip132_xpubs = j_array(blob, "slip132_extended_pubkeys");
        GDK_RUNTIME_ASSERT_MSG(!(descriptors.has_value() && slip132_xpubs.has_value()),
            "You can only provide either 'core_descriptors' or 'slip132_extended_pubkeys', not both");
        if (descriptors.has_value()) {
            // Core descriptors login
            core_descriptors_credentials descs;
            std::transform(descriptors->begin(), descriptors->end(), std::back_inserter(descs.descriptors),
                [](const nlohmann::json& desc) { return desc.get<std::string>(); });
            creds = descs;
            return;
        }
        if (slip132_xpubs.has_value()) {
            // SLIP-132 extended public keys login
            slip132_credentials xpubs;
            std::transform(slip132_xpubs->begin(), slip132_xpubs->end(), std::back_inserter(xpubs.xpubs),
                [](const nlohmann::json& xpub) { return xpub.get<std::string>(); });
            creds = xpubs;
            return;
        }
        throw user_error("Invalid credentials");
    }

} // namespace green
