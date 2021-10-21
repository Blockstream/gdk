#include <string>
#include <vector>

#include "assertion.hpp"
#include "generated_assets.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"
#include "version.h"

namespace ga {
namespace sdk {
    namespace {

    } // namespace

    nlohmann::json get_inbuilt_data(const network_parameters& /*net_params*/, const std::string& key)
    {
        std::vector<unsigned char> base_data;
        if (key == "assets") {
            base_data = decompress({ inbuilt_assets, sizeof(inbuilt_assets) });
        } else if (key == "icons") {
            base_data = decompress({ inbuilt_icons, sizeof(inbuilt_icons) });
        } else {
            // TODO: Add support for SPV checkpoint data
            GDK_RUNTIME_ASSERT(false);
        }
        auto result = nlohmann::json::from_msgpack(base_data.begin(), base_data.end());

        return result;
    }

    std::string get_inbuilt_data_timestamp(const network_parameters& /*net_params*/, const std::string& key)
    {
        if (key == "assets") {
            return inbuilt_assets_modified;
        } else if (key == "icons") {
            return inbuilt_icons_modified;
        }
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

} // namespace sdk
} // namespace ga
