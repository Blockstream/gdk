#ifndef GDK_JSON_UTILS_HPP
#define GDK_JSON_UTILS_HPP
#include <cstdint>
#pragma once

#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <string_view>
#include <vector>

namespace ga {
namespace sdk {
    class amount;
    using json_array_t = std::vector<nlohmann::json>;

    // JSON fetch helpers:
    // j_fooref:      get a const reference to a foo (or by value for value types). Throw if not found.
    // j_foo:         get an optional<foo>, empty if not found.
    // j_foo_or_bar:  get a foo, or bar if not found

    // string
    const std::string& j_strref(const nlohmann::json& src, std::string_view key);
    std::optional<std::string> j_str(const nlohmann::json& src, std::string_view key);
    std::string j_str_or_empty(const nlohmann::json& src, std::string_view key);
    // Returns true if key is missing, or present and an empty string
    bool j_str_is_empty(const nlohmann::json& src, std::string_view key);

    // array
    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key);
    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key, size_t expected_size);
    std::optional<json_array_t> j_array(const nlohmann::json& src, std::string_view key);

    // amount
    amount j_amountref(const nlohmann::json& src, std::string_view key = "satoshi");
    std::optional<amount> j_amount(const nlohmann::json& src, std::string_view key = "satoshi");
    amount j_amount_or_zero(const nlohmann::json& src, std::string_view key = "satoshi");

    // hex asset id, or "btc" for bitcoin
    std::string j_assetref(bool is_liquid, const nlohmann::json& src, std::string_view key = "asset_id");

    // bool
    bool j_boolref(const nlohmann::json& src, std::string_view key);
    std::optional<bool> j_bool(const nlohmann::json& src, std::string_view key);
    bool j_bool_or_false(const nlohmann::json& src, std::string_view key);

    // uint32_t
    uint32_t j_uint32ref(const nlohmann::json& src, std::string_view key);
    std::optional<uint32_t> j_uint32(const nlohmann::json& src, std::string_view key);
    uint32_t j_uint32_or_zero(const nlohmann::json& src, std::string_view key);
} // namespace sdk
} // namespace ga
#endif
