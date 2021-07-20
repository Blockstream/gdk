// Create compressed asset data for pre-caching in gdk
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
    os << "extern const std::string inbuilt_" << name << "_modified{\""  << modified << "\"};\n\n";
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
    const auto url = session.get_network_parameters().get_registry_connection_string() + "/" + page + ".json";
    auto data = session.http_request({ { "method", "GET" }, { "urls", { url } }, { "accept", "json" } });
    data.at("headers").erase("date"); // Make the generated data reproducible
    auto compressed = sdk::compress(sdk::byte_span_t(), nlohmann::json::to_msgpack(data));
    return get_code(key, compressed, data.at("headers").at("last-modified"));
}

int main()
{
    sdk::init(nlohmann::json::object());
    sdk::session session;
    session.connect({ { "name", "liquid" }, { "log_level", "info" } });

    const auto mnemonic_env = std::getenv("GA_MNEMONIC");
    GDK_RUNTIME_ASSERT_MSG(mnemonic_env, "Set GA_MNEMONIC to generate assets");
    const nlohmann::json details({ { "mnemonic", mnemonic_env } });
    std::unique_ptr<sdk::auth_handler> login_call{ sdk::get_login_call(session, nlohmann::json(), details) };
    process_auth(*login_call);

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
