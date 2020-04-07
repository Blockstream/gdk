#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include "src/amount.hpp"
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>

static int test_number = 0;
static int ok_tests = 0;

#define ASSERT(ok, msg) do { bool okres=!!(ok); print_test_res(okres, msg, #ok); if (!okres) return false; } while (0)
#define TEST_OK(name) do { printf("ok %d " name "\n", ++test_number); ok_tests++; } while(0)
#define TEST(fn) do { try{ printf("# " #fn "\n"); fn; } catch (const std::exception &e) { print_test_res(false, "exception in " #fn, e.what()); } } while(0)

static void print_test_res(bool res, const char *name, const char *assert) {
    if (res) ok_tests++;
    const char *n = res? "" : "not ";
    printf("%sok %d - %s\n", n, ++test_number, name);

    if (!res) {
        printf("  ---\n");
        printf("    assert: %s\n", assert);
        printf("  ...\n\n");
    }
}

// #define CHECK_OK ASSERT(ret)

bool test_receive_addresses(ga::sdk::session& session) {
    std::string a1 = session.get_receive_address(nlohmann::json{})["address"];
    std::string a2 = session.get_receive_address(nlohmann::json{})["address"];

    ASSERT(a1 != a2, "should get different receive addresses");

    printf("addr1: %s\naddr2: %s\n", a1.c_str(), a2.c_str());
    return true;
}

bool test_get_transactions(ga::sdk::session& session) {
    nlohmann::json details;
    auto ret = session.get_transactions(details);
    auto tx = ret.size() > 0 ? ret[0] : ret;

    printf("transactions (%ld): %s\n", ret.size(), tx.dump().c_str());
    return true;
}

bool test_get_balance(ga::sdk::session& session) {
    nlohmann::json balance_details;
    balance_details["num_confs"] = 0;
    auto res = session.get_balance(balance_details);

    printf("get_balance: %s\n", res.dump().c_str());
    ASSERT(res["btc"] >= 0, "should have non-empty balance");
    return true;
}


bool test_get_fee_estimates(ga::sdk::session& session) {
    auto res = session.get_fee_estimates();
    auto fees = res["fees"];

    ASSERT(fees.size() > 0, "empty fees");
    ASSERT(fees[0].get<double>() >= 0, "first fee entry isnt 0");

    printf("estimates %s\n", res.dump().c_str());
    return true;
}

bool test_create_transaction(ga::sdk::session& session) {
    auto address = "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b";
    nlohmann::json addressees = {{{ "address", address}, { "satoshi", 2000} }};
    nlohmann::json create_tx = {
      { "addressees",  addressees},
      { "subaccount", 0 },
      { "fee_rate", 1000 }
    };

    printf("create_tx %s\n", create_tx.dump().c_str());
    auto tx_created = session.create_transaction(create_tx);
    auto error = session.is_liquid() ? "id_invalid_address" : ""; 
    ASSERT(tx_created.value("error", "") == error, "invalid liquid address");

    address = "VJLEPoiNtivvKcXtmcFVBPzaL4DukwSjjk3c8kyfczeAFMgQoKbie1AZbB1YiuBAZgdRH6TwCBBPGSBW";
    addressees = {{{ "address", address}, { "satoshi", 2000} }};
    create_tx = {
      { "addressees",  addressees},
      { "subaccount", 0 },
      { "fee_rate", 1000 }
    };

    printf("create_tx %s\n", create_tx.dump().c_str());
    tx_created = session.create_transaction(create_tx);
    error = session.is_liquid() ? "" : "id_invalid_address"; 
    ASSERT(tx_created.value("error", "") == error, "invalid bitcoin address");

    return true;
}

bool test_sign_transaction(ga::sdk::session& session) {
    auto address = session.is_liquid() ? "VJLEPoiNtivvKcXtmcFVBPzaL4DukwSjjk3c8kyfczeAFMgQoKbie1AZbB1YiuBAZgdRH6TwCBBPGSBW" : "2NFHMw7GbqnQ3kTYMrA7MnHiYDyLy4EQH6b";
    nlohmann::json addressees = {{{ "address", address}, { "satoshi", 2000} }};

    nlohmann::json create_tx = {
      { "addressees",  addressees},
      { "subaccount", 0 },
      { "fee_rate", 1000 }
    };

    auto tx_created = session.create_transaction(create_tx);
    auto tx_signed = session.sign_transaction(tx_created);
    printf("tx_signed %s\n", tx_signed.dump().c_str());

    return true;
}
bool test_get_mnemonic_passphrase(ga::sdk::session& session) {
    bool threw = false;
    auto mnemonic = session.get_mnemonic_passphrase("");

    try {
        session.get_mnemonic_passphrase("password");
    }
    catch (const std::exception &e) {
        threw = true;
    }

    ASSERT(threw, "expected get_mnemonic_passphrase with password to throw");
    return true;
}

// TODO: switch to amount::convert instead of doing things in rust
bool test_convert_amount(ga::sdk::session& session) {
    printf("test_convert_amount\n");
    auto details = nlohmann::json({{"satoshi", 10000}});
    auto result = session.convert_amount(details);

    printf("test_convert_amount #1: {satoshi: 10000} %s\n", result.dump().c_str());

    // fiat rate works ok
    ASSERT(result.value("fiat", "") != "", "expected non-empty fiat field");
    ASSERT(result.value("fiat_rate", "") != "", "expected non-empty fiat_rate");
    ASSERT(result.value("fiat_currency", "") != "", "expected non-empty fiat_currency");

    ASSERT(result["bits"] == "100.00", "bits is converted correctly");
    ASSERT(result["ubtc"] == "100.00", "ubtc is the same as bits");
    ASSERT(result["btc"] == "0.00010000", "btc is converted correctly");

    details = nlohmann::json({{"btc", "0.1284502"}});
    result = session.convert_amount(details);

    printf("test_convert_amount #2: {btc: 0.1284502} %s\n", result.dump().c_str());

    ASSERT(result["sats"] == "12845020", "tricky btc to sats is correct");
    ASSERT(result["bits"] == "128450.20", "tricky btc to bits is correct");
    ASSERT(result["btc"] == "0.12845020", "tricky btc to btc is correct");

    return true;
}

int main()
{
    const char *mnemonic = getenv("BITCOIN_MNEMONIC");
    const char *datadir = getenv("DATADIR");
    const char *network = getenv("GDK_NETWORK");
    const char *url = getenv("GDK_NETWORK_URL");
    const char *tls = getenv("GDK_TLS");

    // Test Anything Protocol
    printf("TAP version 13\n");

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

    // T
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


        TEST(test_receive_addresses(session));
        TEST(test_get_transactions(session));
        TEST(test_get_balance(session));
        // test_get_fee_estimates(session);
        TEST(test_create_transaction(session));
        TEST(test_get_mnemonic_passphrase(session));
        TEST(test_convert_amount(session));

        // Try fee estimates with two different electrs
        session.disconnect();
        printf("testing regular electrs fee estimates\n");
        net_params["url"] = "electrum2.hodlister.co:50002";
        session.connect(net_params);
        TEST(test_get_fee_estimates(session));

        session.disconnect();
        printf("testing blockstream electrs fee estimates\n");
        net_params["url"] = "blockstream.info:700";
        session.connect(net_params);
        TEST(test_get_fee_estimates(session));
    }

    printf("1..%d\n", test_number);
    printf("# tests %d\n# pass %d\n# fail %d\n", test_number, ok_tests, test_number-ok_tests);

    return 0;
}
