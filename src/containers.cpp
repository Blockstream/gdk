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

} // namespace sdk
} // namespace ga
