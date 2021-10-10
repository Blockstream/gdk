#ifndef GDK_INBUILT_HPP
#define GDK_INBUILT_HPP
#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace ga {
namespace sdk {
    class network_parameters;

    // Return compiled-in data such as assets and icons
    nlohmann::json get_inbuilt_data(const network_parameters& net_params, const std::string& key);

    // Return the timestamp for compiled-in data
    std::string get_inbuilt_data_timestamp(const network_parameters& net_params, const std::string& key);

} // namespace sdk
} // namespace ga

#endif
