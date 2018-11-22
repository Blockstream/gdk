#include <queue>
#include <thread>

#include "boost_wrapper.hpp"

#include "containers.hpp"

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

} // namespace sdk
} // namespace ga
