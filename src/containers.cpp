#include <queue>
#include <thread>

#include "boost_wrapper.hpp"

#include "containers.hpp"
#include "ga_wally.hpp"

namespace ga {
namespace sdk {

    bool json_rename_key(nlohmann::json& data, const std::string& from_key, const std::string& to_key)
    {
        auto p = data.find(from_key);
        if (p == data.end()) {
            return false;
        }
        data[to_key] = *p;
        data.erase(p);
        return true;
    }

    // Due to bad data in the prod asset registry, we need to call this from a few places.
    std::vector<std::string> json_filter_bad_asset_ids(nlohmann::json& data)
    {
        auto&& filter_fn = [](const auto& item) { return !validate_hex(item.key(), ASSET_TAG_LEN); };
        return json_filter(data, filter_fn);
    }

    void json_expand_asset_info(nlohmann::json& data)
    {
        for (auto& item : data.items()) {
            nlohmann::json entity{ { "domain", std::move(item.value().at(0)) } };
            nlohmann::json new_value = { { "asset_id", item.key() }, { "ticker", std::move(item.value().at(1)) },
                { "name", std::move(item.value().at(2)) }, { "precision", std::move(item.value().at(3)) },
                { "entity", std::move(entity) } };
            item.value().swap(new_value);
        }
    }

} // namespace sdk
} // namespace ga
