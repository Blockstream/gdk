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

    const std::string& j_strref(const nlohmann::json& src, std::string_view key);
    std::optional<std::string> j_str(const nlohmann::json& src, std::string_view key);

    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key);
    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key, size_t expected_size);
    std::optional<json_array_t> j_array(const nlohmann::json& src, std::string_view key);

    std::optional<amount> j_amount(const nlohmann::json& src, std::string_view key);

    std::optional<bool> j_bool(const nlohmann::json& src, std::string_view key);

    std::optional<uint32_t> j_uint32(const nlohmann::json& src, std::string_view key);
} // namespace sdk
} // namespace ga
#endif
