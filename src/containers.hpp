#ifndef GDK_CONTAINERS_HPP
#define GDK_CONTAINERS_HPP
#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace ga {
namespace sdk {

    // Rename from_key to to_key in the given JSON object
    bool json_rename_key(nlohmann::json& data, const std::string& from_key, const std::string& to_key);

    // Add a value to a JSON object if one is not already present under the given key
    template <typename T>
    T json_add_if_missing(nlohmann::json& data, const std::string& key, const T& value, bool or_null = false)
    {
        const auto p = data.find(key);
        if (p == data.end() || (or_null && p->is_null())) {
            data[key] = value;
            return value;
        }
        return *p;
    }

    // Set a value to a JSON object if it is non-default, otherwise remove any existing value.
    // This saves space storing the value if a default value is returned when its fetched.
    // Returns true if the JSON object was changed.
    template <typename T = std::string>
    bool json_add_non_default(
        nlohmann::json& data, const std::string& key, const T& value, const T& default_value = T())
    {
        const bool is_default = value == default_value;
        const auto p = data.find(key);
        const bool found = p != data.end();
        if (is_default) {
            if (found) {
                data.erase(p); // Remove existing value
                return true;
            }
            return false;
        }
        if (found) {
            if (*p == value) {
                return false;
            }
            *p = value; // Overwrite existing value
            return true;
        }
        data[key] = value; // Insert new value
        return true;
    }

    // Get a value if present and not null, otherwise return a default value
    template <typename T = std::string>
    T json_get_value(const nlohmann::json& data, const std::string& key, const T& default_value = T())
    {
        const auto p = data.find(key);
        if (p == data.end() || p->is_null()) {
            return default_value;
        }
        return *p;
    }

    // Filter items from json based on a predicate function `filter`.
    // Returns the keys of the items removed
    template <typename FN> std::vector<std::string> json_filter(nlohmann::json& data, FN&& filter)
    {
        std::vector<std::string> to_remove;
        for (auto& item : data.items()) {
            if (filter(item)) {
                to_remove.emplace_back(item.key());
            }
        }
        for (const auto& key : to_remove) {
            data.erase(key);
        }
        return to_remove;
    }

    // Filter items without a valid asset id key (32 byte/64 char hex string)
    std::vector<std::string> json_filter_bad_asset_ids(nlohmann::json& data);

    // Expand minimal asset data into the full asset data format
    void json_expand_asset_info(nlohmann::json& data);

} // namespace sdk
} // namespace ga

#endif
