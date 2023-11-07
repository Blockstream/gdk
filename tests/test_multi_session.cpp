#include "src/ga_auth_handlers.hpp"
#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include "src/utils.hpp"
#include <assert.h>
#include <chrono>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

using namespace ga;

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

static void test_two_sessions(nlohmann::json net_params)
{
    // Create 2 sessions connected to the same backend.
    // NOTE: this isn't a supported operation, both sessions must have
    //       distinct data directories otherwise they may corrupt each
    //       others caches.
    ga::sdk::session session;
    session.connect(net_params);
    ga::sdk::session session2;
    session2.connect(net_params);
}

static void test_async_disconnect(nlohmann::json net_params)
{
    // Test asynchronously disconnecting a connection attempt.
    // If GA_MNEMONIC is set, reconnect and login to verify the
    // session remains usable.
    const auto mnemonic = std::getenv("GA_MNEMONIC");

    for (size_t i = 0; i < 1; ++i) {
        sdk::session session;

        // The delay to use is random in order to provoke cancellation
        // to happen at various points in the connection logic. Increase
        // the number of loop iterations to test exhaustively against a
        // local server.
        uint32_t delay;
        sdk::get_random_bytes(sizeof(delay), &delay, sizeof(delay));
        const auto delay_ms = std::chrono::milliseconds(delay % 100);

        // First thread connects in the background
        auto connect_thread = std::thread([&] {
            try {
                std::cout << "connecting\n";
                session.connect(net_params);
                std::cout << "connected\n";
            } catch (const std::exception& ex) {
                std::cout << "connect: " << ex.what() << std::endl;
                if (ex.what() != std::string("timeout error")) {
                    // Something went wrong
                    abort();
                }
            }
        });

        // Second thread waits for the random delay then disconnects
        auto cancel_thread = std::thread([&] {
            std::this_thread::sleep_for(delay_ms);
            try {
                std::cout << "disconnecting\n";
                session.reconnect_hint({ { "hint", "disconnect" } });
                std::cout << "disconnected\n";
            } catch (const std::exception& ex) {
                std::cout << "session.reconnect_hint: " << ex.what() << std::endl;
            }
        });

        // Wait for the cancel then connect thread to finish.
        cancel_thread.join();
        std::cout << "joined cancel_thread\n";
        connect_thread.join();
        std::cout << "joined connect_thread\n";

        // Now ask the session to reconnect aynchronously
        std::this_thread::sleep_for(std::chrono::seconds(1));
        session.reconnect_hint({ { "hint", "connect" } });

        if (!mnemonic) {
            std::cout << "set GA_MNEMONIC to test login after reconnect\n";
            continue;
        }

        {
            // Log in the session now that it has reconnected
            const nlohmann::json details({ { "mnemonic", mnemonic } });
            sdk::auto_auth_handler login_call(new sdk::login_user_call(session, nlohmann::json(), details));
            std::cout << process_auth(login_call) << std::endl;
        }

        // Verify that the session works to call server methods on
        std::unique_ptr<sdk::auth_handler> call{ new sdk::get_subaccounts_call(session, nlohmann::json()) };
        std::cout << process_auth(*call) << std::endl;

        // session dtor fires here and disconnects/destroys the session
    }
}

int main()
{
    nlohmann::json init_config;
    init_config["datadir"] = ".";
    init_config["log_level"] = "info";
    sdk::init(init_config);

    nlohmann::json net_params;
    net_params["use_tor"] = false; // Set to true to test tor
    // net_params["proxy"] = "localhost:9050";
    net_params["name"] = "testnet";

    test_two_sessions(net_params);
    test_async_disconnect(net_params);
    return 0;
}
