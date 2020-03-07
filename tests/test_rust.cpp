#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include <assert.h>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>

// #define CHECK_OK assert(ret)

void test_receive_addresses(ga::sdk::session& session) {
    std::string a1 = session.get_receive_address(nlohmann::json{})["address"];
    std::string a2 = session.get_receive_address(nlohmann::json{})["address"];

    assert(a1 != a2);

    printf("addr1: %s\naddr2: %s\n", a1.c_str(), a2.c_str());
}

void test_get_transactions(ga::sdk::session& session) {
    nlohmann::json details;
    auto ret = session.get_transactions(details);
    auto tx = ret.size() > 0 ? ret[0] : ret;

    printf("transactions (%ld): \n%s", ret.size(), tx.dump().c_str());
}

void test_get_balance(ga::sdk::session& session) {
    nlohmann::json balance_details;
    balance_details["num_confs"] = 0;
    auto res = session.get_balance(balance_details);

    assert(res["btc"] >= 0);
}


void test_get_fee_estimates(ga::sdk::session& session) {
    auto res = session.get_fee_estimates();
    auto fees = res["fees"];

    assert(fees.size() > 0);
    assert(fees[0].get<double>() >= 0);

    // printf("estimates %s\n", res.dump().c_str());
}

void test_create_sign_transaction(ga::sdk::session& session) {
    nlohmann::json addressees = {{{ "address", "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b"}, { "satoshi", 2000} }};
    nlohmann::json create_tx = {
      { "addressees",  addressees},
      { "subaccount", 0 },
      { "fee_rate", 1000 }
    };

    printf("create_tx %s\n", create_tx.dump().c_str());
    auto tx_created = session.create_transaction(create_tx);
    printf("tx_created %s\n", tx_created.dump().c_str());
    auto tx_signed = session.sign_transaction(tx_created);
    printf("tx_signed %s\n", tx_signed.dump().c_str());

    printf("\nok test_create_sign_transaction\n\n", tx_signed.dump().c_str());
}

void test_get_mnemonic_passphrase(ga::sdk::session& session) {
    auto mnemonic = session.get_mnemonic_passphrase("");
    //auto enc_mnemonic = session.get_mnemonic_passphrase("password");

    //assert(mnemonic != enc_mnemonic);
    // printf("\nok test_get_mnemonic_passphrase\n\n");
}

int main()
{
    const char *mnemonic = getenv("BITCOIN_MNEMONIC");
    const char *datadir = getenv("DATADIR");
    const char *network = getenv("GDK_NETWORK");
    const char *url = getenv("GDK_NETWORK_URL");
    const char *tls = getenv("GDK_TLS");

    if (mnemonic == nullptr)
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    if (network == nullptr)
        network = "electrum-testnet";

    std::string state_dir = datadir? datadir : "/tmp/gdk-" + std::string(network);
    nlohmann::json init_config;
    init_config["datadir"] = state_dir;

    nlohmann::json net_params;
    net_params["log_level"] = "debug";
    net_params["use_tor"] = false;

    // TODO: test defaults
    if (url != nullptr)
        net_params["url"] = url;
    net_params["name"] = network;
    net_params["validate_electrum_domain"] = false;
    if (tls != nullptr)
        net_params["tls"] = std::string(tls) == "true" ? true : false;

    printf("====================================\n");
    printf("testing with network(%s) url(%s) state_dir(%s)\n",
           network, url, state_dir.c_str());
    printf("====================================\n");

    ga::sdk::init(init_config);
    {
        ga::sdk::session session;

        session.connect(net_params);
        session.login(mnemonic, "");

        // auto net = session.get_network_parameters().get(network);
        // auto is_regtest = net["development"].get<bool>();

        test_receive_addresses(session);
        test_get_transactions(session);
        test_get_balance(session);
        test_get_fee_estimates(session);
        test_create_sign_transaction(session);
        test_get_mnemonic_passphrase(session);
    }

    return 0;
}
