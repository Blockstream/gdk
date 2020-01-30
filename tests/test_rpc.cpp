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

    const char *username = getenv("BITCOIN_RPCUSER");
    const char *password = getenv("BITCOIN_RPCPASS");
    const char *rpcport = getenv("BITCOIN_RPCPORT");
    const char *mnemonic = getenv("BITCOIN_MNEMONIC");

    if (rpcport == nullptr)
        rpcport = "18332";

    if (mnemonic == nullptr)
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    nlohmann::json net_params;
    net_params["log_level"] = "debug";
    net_params["use_tor"] = false;
    net_params["rpc_url"] = "http://localhost:" + std::string(rpcport);
    net_params["username"] = username? username : "username";
    net_params["password"] = password? password : "password";
    // net_params["proxy"] = "localhost:9050";
    net_params["name"] = "rpc-testnet";

    ga::sdk::init(init_config);
    {
        nlohmann::json details;
        ga::sdk::session session;

        session.connect(net_params);
        session.login(mnemonic, "");

        std::string a1 = session.get_receive_address(nlohmann::json{})["address"];
        std::string a2 = session.get_receive_address(nlohmann::json{})["address"];

        assert(a1 != a2);

        auto ret = session.get_transactions(details);
        auto tx = ret.size() > 0 ? ret[0] : ret;

        printf("transactions (%ld): \n%s\naddr1: %s\naddr2: %s\n",
               ret.size(),
               tx.dump().c_str(),
               a1.c_str(),
               a2.c_str()
               );

        nlohmann::json balance_details;
        balance_details["num_confs"] = 0;
        auto res = session.get_balance(balance_details);

        printf("balance %s\n", res.dump().c_str());
    }



    return 0;
}
