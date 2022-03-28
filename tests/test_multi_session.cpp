#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include <assert.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>

int main()
{
    nlohmann::json init_config;
    init_config["datadir"] = ".";
    init_config["log_level"] = "debug";

    nlohmann::json net_params;
    net_params["use_tor"] = true;
    // net_params["proxy"] = "localhost:9050";
    net_params["name"] = "testnet";

    ga::sdk::init(init_config);
    {
        ga::sdk::session session;
        session.connect(net_params);
        ga::sdk::session session2;
        session2.connect(net_params);
    }
}
