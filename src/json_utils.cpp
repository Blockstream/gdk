#include "json_utils.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <type_traits>

#include "amount.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_wally.hpp"

namespace {
static auto find(const nlohmann::json& src, std::string_view key)
{
    if (src.is_null()) {
        return src.end();
    }
    auto it = src.find(key);
    if (it == src.end() || it->is_null()) {
        return src.end();
    }
    return it;
}
static auto get_or_throw(const nlohmann::json& src, std::string_view key)
{
    auto it = find(src, key);
    if (it == src.end()) {
        std::string error_message = std::string("key ") + std::string(key) + " not found";
        throw ::ga::sdk::user_error(error_message);
    }
    return it;
}
template <typename T> static std::optional<T> get_optional(const nlohmann::json& src, std::string_view key)
{
    auto it = find(src, key);
    if (it == src.end()) {
        return {};
    }
    return it->get<T>();
}
template <typename T> static T get_or_default(const nlohmann::json& src, std::string_view key)
{
    auto it = find(src, key);
    return it == src.end() ? T() : it->get<T>();
}
} // namespace

namespace ga {
namespace sdk {

    const std::string& j_strref(const nlohmann::json& src, std::string_view key)
    {
        return get_or_throw(src, key)->get_ref<const std::string&>();
    }

    std::optional<std::string> j_str(const nlohmann::json& src, std::string_view key)
    {
        return get_optional<std::string>(src, key);
    }

    std::string j_str_or_empty(const nlohmann::json& src, std::string_view key)
    {
        return get_or_default<std::string>(src, key);
    }

    bool j_str_is_empty(const nlohmann::json& src, std::string_view key)
    {
        const auto it = find(src, key);
        return it == src.end() ? true : it->get_ref<const std::string&>().empty();
    }

    const json_array_t& j_arrayref(const nlohmann::json& src, std::string_view key)
    {
        static_assert(
            std::is_same_v<json_array_t, nlohmann::json::array_t>, "json_array_t must be nlohmann::json::array_t");
        return get_or_throw(src, key)->get_ref<const nlohmann::json::array_t&>();
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

    amount j_amountref(const nlohmann::json& src, std::string_view key)
    {
        return amount(get_or_throw(src, key)->get<amount::value_type>());
    }

    std::optional<amount> j_amount(const nlohmann::json& src, std::string_view key)
    {
        auto value = get_optional<amount::value_type>(src, key);
        if (!value.has_value()) {
            return {};
        }
        return std::optional<amount>(value.value());
    }

    amount j_amount_or_zero(const nlohmann::json& src, std::string_view key)
    {
        return amount(get_or_default<amount::value_type>(src, key));
    }

    std::string j_assetref(bool is_liquid, const nlohmann::json& src, std::string_view key)
    {
        auto asset_id_hex = j_str_or_empty(src, key);
        const bool is_empty = asset_id_hex.empty();
        if (is_liquid) {
            if (is_empty || !validate_hex(asset_id_hex, 32)) {
                // Must be a valid hex asset id
                throw user_error(res::id_invalid_asset_id);
            }
            return asset_id_hex;
        }
        if (!is_empty) {
            throw user_error(res::id_assets_cannot_be_used_on_bitcoin);
        }
        return "btc";
    }

    bool j_boolref(const nlohmann::json& src, std::string_view key) { return get_or_throw(src, key)->get<bool>(); }

    std::optional<bool> j_bool(const nlohmann::json& src, std::string_view key) { return get_optional<bool>(src, key); }

    bool j_bool_or_false(const nlohmann::json& src, std::string_view key) { return get_or_default<bool>(src, key); }

    uint32_t j_uint32ref(const nlohmann::json& src, std::string_view key)
    {
        return get_or_throw(src, key)->get<uint32_t>();
    }

    std::optional<uint32_t> j_uint32(const nlohmann::json& src, std::string_view key)
    {
        return get_optional<uint32_t>(src, key);
    }

    uint32_t j_uint32_or_zero(const nlohmann::json& src, std::string_view key)
    {
        return get_or_default<uint32_t>(src, key);
    }
} // namespace sdk
} // namespace ga
