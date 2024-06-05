#pragma once

#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace green {

    struct wo_credentials {
        std::string username;
        std::string password;
        std::string raw_data;
        std::string data;

        static struct wo_credentials normalize_credentials(const nlohmann::json& blob);
    };

    struct mnemonic_credentials {
        std::string mnemonic;
        std::vector<uint8_t> seed;
        std::optional<std::string> passphrase;
    };

    struct seed_credentials {
        std::vector<uint8_t> seed;
    };

    struct core_descriptors_credentials {
        std::vector<std::string> descriptors;
    };

    struct slip132_credentials {
        std::vector<std::string> xpubs;
    };

    using credentials = std::variant<std::monostate, wo_credentials, mnemonic_credentials, seed_credentials,
        core_descriptors_credentials, slip132_credentials>;

    void to_json(nlohmann::json&, const credentials&);
    void from_json(const nlohmann::json&, credentials&);
} // namespace green
