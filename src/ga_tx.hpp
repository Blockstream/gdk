#ifndef GDK_GA_TX_HPP
#define GDK_GA_TX_HPP
#pragma once

#include "containers.hpp"
#include "network_parameters.hpp"
#include "session.hpp"

namespace ga {
namespace sdk {

    nlohmann::json create_ga_transaction(
        session& session, const network_parameters& net_params, const nlohmann::json& details);

    std::vector<nlohmann::json> get_ga_signing_inputs(const nlohmann::json& details);

    nlohmann::json sign_ga_transaction(session& session, const nlohmann::json& details);

} // namespace sdk
} // namespace ga

#endif
