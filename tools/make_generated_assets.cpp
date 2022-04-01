// Create compressed asset data for pre-caching in gdk
#include "src/containers.hpp"
#include "src/ga_auth_handlers.hpp"
#include "src/ga_session.hpp"
#include "src/session.hpp"
#include "src/utils.hpp"
#include <assert.h>
#include <fstream>
#include <nlohmann/json.hpp>

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
        } else if (status == "done") {
            return status_json.at("result");
        } else {
            abort(); // Should not be run with a real wallet or 2FA set
        }
    }
}

static std::string get_code(const std::string& name, const std::vector<uint8_t>& compressed, const std::string& modified)
{
    std::ostringstream os;
    os << "static const std::string inbuilt_" << name << "_modified{\""  << modified << "\"};\n\n";
    os << std::setfill('0');
    os << "static const uint8_t inbuilt_" << name << "[" << compressed.size() << "] = {" << std::hex;
    for (size_t i = 0; i < compressed.size(); ++i) {
        if (i % 24 == 0) {
            os << "\n    ";
        }
        os << "0x" << std::setw(2) << std::hex << static_cast<int>(compressed[i]) << ",";
    }
    std::string text = os.str();
    text.pop_back(); // Remove last comma
    return text + "\n};\n";
}

static std::string generate(sdk::session& session, const std::string& page, const std::string& key)
{
    const std::string minimal_page = page == "index" ? "index.minimal" : page;
    const auto url = session.get_network_parameters().get_registry_connection_string() + "/" + minimal_page + ".json";
    auto data = session.http_request({ { "method", "GET" }, { "urls", { url } }, { "accept", "json" } });
    data.at("headers").erase("date"); // Make the generated data reproducible
    ::ga::sdk::json_filter_bad_asset_ids(data.at("body")); // Remove any bad keys

#if 0 // Enable to mutate the generated asset data so patching can be tested
    if (key == "assets") {
        // Change the modified header so refreshing causes an update
        data.at("headers")["last-modified"] = "Wed, 07 Jul 2021 01:01:01 GMT";
        // Rename one asset, refreshing should patch it back
        const auto start_asset = "002452cb8f56a0a5628240edfb3d1e966c9b1959adcfb95b5726e5e9688611bf";
        const auto end_asset =   "0001000100010001000100010001000100010001000100010001000100010001";
        auto &body = data.at("body");
        auto p = body.find(start_asset);
        GDK_RUNTIME_ASSERT(p != body.end());
        body[end_asset].swap(*p);
        body.erase(p);
        // Update an assets precision, refreshing should revert it
        body["005302fd8aa65fec1883ba93911dd1fb28763650205c67109fee66017c90899c"].at(3) = 2;
    }
#endif
    auto compressed = sdk::compress(sdk::byte_span_t(), nlohmann::json::to_msgpack(data));
    return get_code(key, compressed, data.at("headers").at("last-modified"));
}

int main()
{
    sdk::init({ { "datadir", "." }, { "log_level", "info" } });
    sdk::session session;
    session.connect({ { "name", "liquid" } });

    const auto mnemonic_env = std::getenv("GA_MNEMONIC");
    GDK_RUNTIME_ASSERT_MSG(mnemonic_env, "Set GA_MNEMONIC to generate assets");
    const nlohmann::json details({ { "mnemonic", mnemonic_env } });
    sdk::auto_auth_handler login_call(new sdk::login_user_call(session, nlohmann::json(), details));
    process_auth(login_call);

    std::ostringstream os;
    os << "// GENERATED FILE: DO NOT EDIT!\n"
       << "// clang-format off\n"
       << "namespace ga {\n"
       << "namespace sdk {\n";

    os << generate(session, "index", "assets") << "\n";
    os << generate(session, "icons", "icons");

    std::ofstream out("src/generated_assets.hpp", std::ios::trunc | std::ios::out);
    out << os.str() << "}\n}\n" << std::endl;

    return 0;
}
