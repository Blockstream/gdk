#include "json_utils.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <type_traits>

#include "amount.hpp"
#include "exception.hpp"

namespace {
template <typename T> static std::optional<T> get_optional(const nlohmann::json& src, std::string_view key)
{
    auto it = src.find(key);
    if (it == src.end()) {
        return {};
    }
    return it->get<T>();
}
} // namespace

namespace ga {
namespace sdk {

    const std::string& j_strref(const nlohmann::json& src, std::string_view key)
    {
        return src.at(key).get_ref<const std::string&>();
    }
    std::optional<std::string> j_str(const nlohmann::json& src, std::string_view key)
    {
        return get_optional<std::string>(src, key);
    }

    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key)
    {
        static_assert(
            std::is_same_v<json_array_t, nlohmann::json::array_t>, "json_array_t must be nlohmann::json::array_t");
        return src.at(key).get_ref<const nlohmann::json::array_t&>();
    }

    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key, size_t expected_size)
    {
        const auto& array = j_arrayref(src, key);
        if (array.size() != expected_size) {
            std::string error_message = std::string("unexpected array size for key ") + std::string(key)
                + " expecting size " + std::to_string(expected_size) + " got size " + std::to_string(array.size());
            throw assertion_error(error_message);
        }
        return array;
    }

    std::optional<json_array_t> j_array(const nlohmann::json& src, std::string_view key)
    {
        return get_optional<nlohmann::json::array_t>(src, key);
    }

    std::optional<amount> j_amount(const nlohmann::json& src, std::string_view key)
    {
        auto value = get_optional<amount::value_type>(src, key);
        if (!value.has_value()) {
            return std::nullopt;
        }
        return std::optional<amount>(value.value());
    }

    std::optional<bool> j_bool(const nlohmann::json& src, std::string_view key) { return get_optional<bool>(src, key); }

    std::optional<uint32_t> j_uint32(const nlohmann::json& src, std::string_view key)
    {
        return get_optional<uint32_t>(src, key);
    }
} // namespace sdk
} // namespace ga
