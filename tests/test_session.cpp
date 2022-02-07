// A simple test to call session methods in a valgrindable environment
#include "src/ga_auth_handlers.hpp"
#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include "src/session_impl.hpp"
#include <assert.h>
#include <cstdlib>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>

using namespace ga;

static std::string envstr(const char* name, const std::string& default_)
{
    const auto p = std::getenv(name);
    return p ? std::string(p) : default_;
}

#if 0
static uint64_t envnum(const char* name, const uint64_t default_)
{
    const auto p = std::getenv(name);
    return p ? boost::lexical_cast<uint64_t>(p) : default_;
}
#endif

static nlohmann::json process_auth(sdk::auth_handler& handler)
{
    while (true) {
        const auto status_json = handler.get_status();
        const std::string status = status_json.at("status");
        if (status == "error") {
            throw std::runtime_error(status_json.at("error"));
        } else if (status == "call") {
            handler.operator()();
        } else if (status == "request_code") {
            // Request a code using the first availale 2fa method
            const std::string method = status_json.at("methods").at(0);
            handler.request_code(method);
        } else if (status == "resolve_code") {
            // TODO: Only works for localtest environments
            handler.resolve_code("555555");
        } else if (status == "done") {
            return status_json.at("result");
        }
    }
}

int main()
{
    using namespace std::chrono_literals;

    nlohmann::json init_config;
    init_config["datadir"] = ".";
    init_config["log_level"] = "info";
    sdk::init(init_config);

    nlohmann::json net_params;
    net_params["name"] = envstr("GA_NETWORK", "localtest");

    sdk::session session;
    session.connect(net_params);

    // Login
    const auto mnemonic = envstr("GA_MNEMONIC", std::string());
    if (mnemonic.empty()) {
        std::cout << "Set GA_NETWORK/GA_MNEMONIC to run test" << std::endl;
        return 0; // Do not fail
    }
    const nlohmann::json details({ { "mnemonic", mnemonic } });
    sdk::auto_auth_handler login_call(new sdk::login_user_call(session, nlohmann::json(), details));
    std::cout << process_auth(login_call) << std::endl;

#if 1
    // Get subaccounts/ Get subaccount
    std::vector<uint32_t> subaccounts;
    {
        std::unique_ptr<sdk::auth_handler> call{ new sdk::get_subaccounts_call(session, nlohmann::json()) };
        const auto result = process_auth(*call);
        std::cout << result << std::endl;
        for (const auto& sa : result["subaccounts"]) {
            subaccounts.push_back(sa["pointer"]);
            std::unique_ptr<sdk::auth_handler> call{ new sdk::get_subaccount_call(session, sa["pointer"]) };
            std::cout << process_auth(*call) << std::endl;
        }
    }

    for (const auto subaccount : subaccounts) {
        for (auto num_confs = 0u; num_confs <= 1u; ++num_confs) {
            const nlohmann::json utxo_details({ { "subaccount", subaccount }, { "num_confs", num_confs } });

            // Balance
            {
                sdk::auto_auth_handler call(new sdk::get_balance_call(session, utxo_details));
                std::cout << process_auth(call) << std::endl;
            }

            // UTXOs
            {
                sdk::auto_auth_handler call(new sdk::get_unspent_outputs_call(session, utxo_details));
                std::cout << process_auth(call) << std::endl;
            }
        }

        // Transactions
        {
            const nlohmann::json tx_details({ { "subaccount", subaccount }, { "first", 0 }, { "count", 99999 } });
            sdk::auto_auth_handler call(new sdk::get_transactions_call(session, tx_details));
            std::cout << process_auth(call) << std::endl;
        }
    }
#endif

#if 0
    // Test disconnecting a session while an auth handler is in progress
    // Create a thread fetching transactions on the session in a loop
    std::thread t([&session] {
        const nlohmann::json tx_details({ { "subaccount", 0 }, { "first", 0 }, { "count", 99999 } });
        for (size_t i = 0; i < 1000u; ++i) {
            std::this_thread::yield();
            std::this_thread::sleep_for(1ms);
            try {
                sdk::auto_auth_handler call(new sdk::get_transactions_call(session, tx_details));
                process_auth(call);
            } catch (const std::exception& ex) {
                // std::cout << "get_transactions_call exception: " << ex.what() << std::endl;
                break;
            }
        }
    });

    // Let the thread start, then disconnect the session and wait for the thread to finish
    std::this_thread::yield();
    std::this_thread::sleep_for(100ms);
    session.reconnect_hint(nlohmann::json({{ "hint", "disconnect" }}));
    t.join();
#endif

#if 0
    // Try continuing an auth handler following disconnect()
    bool exception_caught = false;
    {
        const nlohmann::json tx_details({ { "subaccount", 0 }, { "first", 0 }, { "count", 99999 } });
        auto tx_call = new sdk::get_transactions_call(session, tx_details);
        session.reconnect_hint(nlohmann::json({ { "hint", "disconnect" } }));
        try {
            sdk::auto_auth_handler call(tx_call);
            process_auth(call);
        } catch (const std::exception&) {
            exception_caught = true;
        }
    }
    GDK_RUNTIME_ASSERT(exception_caught);
#endif

    return 0;
}
