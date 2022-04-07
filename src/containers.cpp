#include <queue>
#include <thread>

#include "boost_wrapper.hpp"

#include "containers.hpp"
#include "ga_wally.hpp"

namespace ga {
namespace sdk {
    // We filter out the mainnet policy asset id to prevent it being returned
    // in regtest (the mainnet minimal asset registry returns it). We insert
    // the actual policy asset in the results after filtering.
    static const std::string MAINNET_ASSET = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

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
    std::vector<std::string> json_filter_bad_asset_ids(nlohmann::json& data, const std::string& key)
    {
        if (key == "assets") {
            return json_filter(data, [](const auto& item) {
                return !validate_hex(item.key(), ASSET_TAG_LEN) || item.key() == MAINNET_ASSET;
            });
        } else {
            return json_filter(data, [](const auto& item) { return !validate_hex(item.key(), ASSET_TAG_LEN); });
        }
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
