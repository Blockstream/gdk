#include <mutex>

#include "assertion.hpp"
#include "containers.hpp"
#include "network_parameters.hpp"

// TODO: Use std::string_view when its fully supported

namespace {

// TODO: generate these from pem file?
// https://www.identrust.com/certificates/trustid/root-download-x3.html
static const char* IDENTX3 = R"(
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----)";

// https://letsencrypt.org/certs/isrgrootx1.pems.txt
static const char* LEX1 = R"(
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----)";

static std::map<std::string, std::shared_ptr<nlohmann::json>> registered_networks = {
    { "localtest",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Localtest" }, { "network", "localtest" }, { "wamp_url", "ws://localhost:8080/v2/ws" },
                { "wamp_onion_url", std::string() }, { "wamp_cert_pins", nlohmann::json::array() },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, LEX1 } },
                { "address_explorer_url", std::string() }, { "tx_explorer_url", std::string() },
                { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
                { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 111u }, { "p2sh_version", 196u },
                { "bech32_prefix", "bcrt" }, { "mainnet", false }, { "liquid", false }, { "development", true },
                { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } }, { "bip21_prefix", "bitcoin" },
                { "server_type", "green" } })) },

    { "liquid",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Liquid" }, { "network", "liquid" }, { "wamp_url", "wss://liquidwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://liquidbtc7u746j4.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "a74b0c32b65b95fe2c4f8f098947a68b695033bed0b51dd8b984ecae89571bb6" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, LEX1 } },
                { "address_explorer_url", "https://blockstream.info/liquid/address/" },
                { "asset_registry_url", "https://assets.blockstream.info" },
                { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
                { "tx_explorer_url", "https://blockstream.info/liquid/tx/" },
                { "service_pubkey", "02c408c3bb8a3d526103fb93246f54897bdd997904d3e18295b49a26965cb41b7f" },
                { "service_chain_code", "02721cc509aa0c2f4a90628e9da0391b196abeabc6393ed4789dd6222c43c489" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 57u }, { "p2sh_version", 39u },
                { "bech32_prefix", "ex" }, { "mainnet", true }, { "liquid", true }, { "development", false },
                { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
                { "blinded_prefix", 12u }, { "ct_exponent", 0 }, { "ct_bits", 52 }, { "blech32_prefix", "lq" },
                { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } }, { "bip21_prefix", "liquidnetwork" },
                { "server_type", "green" } })) },

    { "localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Localtest Liquid" },
            { "network", "localtest-liquid" }, { "wamp_url", "ws://localhost:8080/v2/ws" },
            { "wamp_onion_url", std::string() }, { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, LEX1 } }, { "address_explorer_url", std::string() },
            { "tx_explorer_url", std::string() }, { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 235u }, { "p2sh_version", 75u },
            { "bech32_prefix", "ert" }, { "mainnet", false }, { "liquid", true }, { "development", true },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "blinded_prefix", 4u }, { "ct_exponent", 0 }, { "ct_bits", 52 }, { "blech32_prefix", "el" },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 25920, 51840, 65535 } },
            { "bip21_prefix", "liquidnetwork" }, { "server_type", "green" } })) },

    { "mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Bitcoin" }, { "network", "mainnet" }, { "wamp_url", "wss://prodwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://s7a4rvc6425y72d2.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "a74b0c32b65b95fe2c4f8f098947a68b695033bed0b51dd8b984ecae89571bb6" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, LEX1 } },
                { "address_explorer_url", "https://blockstream.info/address/" },
                { "tx_explorer_url", "https://blockstream.info/tx/" },
                { "service_pubkey", "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f" },
                { "service_chain_code", "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 0u }, { "p2sh_version", 5u },
                { "bech32_prefix", "bc" }, { "mainnet", true }, { "liquid", false }, { "development", false },
                { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } }, { "bip21_prefix", "bitcoin" },
                { "server_type", "green" } })) },

    { "testnet",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Testnet" }, { "network", "testnet" }, { "wamp_url", "wss://testwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://gu5ke7a2aguwfqhz.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "a74b0c32b65b95fe2c4f8f098947a68b695033bed0b51dd8b984ecae89571bb6" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, LEX1 } },
                { "address_explorer_url", "https://blockstream.info/testnet/address/" },
                { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
                { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
                { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 111u }, { "p2sh_version", 196u },
                { "bech32_prefix", "tb" }, { "mainnet", false }, { "liquid", false }, { "development", false },
                { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } }, { "bip21_prefix", "bitcoin" },
                { "server_type", "green" } })) },

    { "regtest",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Regtest" }, { "network", "regtest" },
            { "wamp_url", "ws://10.0.2.2:8080/v2/ws" }, { "wamp_onion_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() }, { "wamp_cert_roots", nlohmann::json::array() },
            { "address_explorer_url", "http://192.168.56.1:8080/address/" },
            { "tx_explorer_url", "http://192.168.56.1:8080/tx/" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "default_peers", std::vector<std::string>{ { "192.168.56.1:19000" } } }, { "p2pkh_version", 111u },
            { "p2sh_version", 196u }, { "bech32_prefix", "bcrt" }, { "mainnet", false }, { "liquid", false },
            { "development", true }, { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } },
            { "bip21_prefix", "bitcoin" }, { "server_type", "green" } })) },

    { "liquid-rpc-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "RPC Liquid" }, { "network", "liquid-rpc-mainnet" },
            { "address_explorer_url", "https://blockstream.info/liquid/address/" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" }, { "default_peers", nlohmann::json::array() },
            { "p2pkh_version", 57u }, { "p2sh_version", 39u }, { "bech32_prefix", "lq" }, { "mainnet", true },
            { "liquid", true }, { "development", false },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "blinded_prefix", 12u }, { "ct_exponent", 0 }, { "ct_bits", 36 },
            { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } }, { "bip21_prefix", "liquidnetwork" },
            { "server_type", "rpc" } })) },

    { "rpc-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "RPC Mainnet" }, { "network", "rpc-mainnet" },
            { "address_explorer_url", "https://blockstream.info/address/" },
            { "tx_explorer_url", "https://blockstream.info/tx/" }, { "p2pkh_version", 0u }, { "p2sh_version", 5u },
            { "bech32_prefix", "bc" }, { "mainnet", true }, { "liquid", false }, { "development", false },
            { "bip21_prefix", "bitcoin" }, { "server_type", "rpc" } })) },

    { "rpc-testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "RPC Testnet" }, { "network", "rpc-testnet" },
            { "wamp_url", "wss://testwss.greenaddress.it/v2/ws" },
            { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" }, { "p2pkh_version", 111u },
            { "p2sh_version", 196u }, { "bech32_prefix", "tb" }, { "mainnet", false }, { "liquid", false },
            { "bip21_prefix", "bitcoin" }, { "development", false }, { "server_type", "rpc" } })) },

    { "rpc-regtest",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "RPC Regtest" }, { "network", "rpc-regtest" },
            { "address_explorer_url", "http://192.168.56.1:8080/address/" },
            { "tx_explorer_url", "http://192.168.56.1:8080/tx/" }, { "p2pkh_version", 111u }, { "p2sh_version", 196u },
            { "bech32_prefix", "bcrt" }, { "mainnet", false }, { "liquid", false }, { "development", true },
            { "bip21_prefix", "bitcoin" }, { "server_type", "rpc" } })) },

    { "liquid-electrum-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Liquid" },
            { "network", "liquid-electrum-mainnet" },
            { "address_explorer_url", "https://blockstream.info/liquid/address/" }, { "url", "blockstream.info:995" },
            { "tls", true }, { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" }, { "default_peers", nlohmann::json::array() },
            { "mainnet", true }, { "liquid", true }, { "development", false },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "ct_min_value", 1 }, { "ct_exponent", 0 }, { "ct_bits", 52 }, { "bip21_prefix", "liquidnetwork" },
            { "server_type", "electrum" } })) },

    { "electrum-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Mainnet" },
            { "network", "electrum-mainnet" }, { "address_explorer_url", "https://blockstream.info/address/" },
            { "url", "blockstream.info:700" }, { "tls", true }, { "tx_explorer_url", "https://blockstream.info/tx/" },
            { "mainnet", true }, { "liquid", false }, { "development", false }, { "bip21_prefix", "bitcoin" },
            { "server_type", "electrum" } })) },

    { "electrum-testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Testnet" },
            { "network", "electrum-testnet" }, { "wamp_url", "wss://testwss.greenaddress.it/v2/ws" },
            { "address_explorer_url", "https://blockstream.info/testnet/address/" }, { "url", "blockstream.info:993" },
            { "tls", true }, { "tx_explorer_url", "https://blockstream.info/testnet/tx/" }, { "mainnet", false },
            { "liquid", false }, { "bip21_prefix", "bitcoin" }, { "development", false },
            { "server_type", "electrum" } })) },

    { "electrum-regtest",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Regtest" },
            { "network", "electrum-regtest" }, { "address_explorer_url", "http://127.0.0.1:8080/address/" },
            { "tx_explorer_url", "http://127.0.0.1:8080/tx/" }, { "mainnet", false }, { "liquid", false },
            { "development", true }, { "bip21_prefix", "bitcoin" }, { "server_type", "electrum" } })) },

};

static std::mutex registered_networks_mutex;
} // namespace

namespace ga {
namespace sdk {

    network_parameters::network_parameters(const nlohmann::json& details)
        : m_details(details)
    {
    }

    network_parameters::~network_parameters() = default;

    void network_parameters::add(const std::string& name, const nlohmann::json& details)
    {
        std::unique_lock<std::mutex> l{ registered_networks_mutex };

        const auto p = registered_networks.find(name);
        const bool found = p != registered_networks.end();
        if (details.is_null() || details.empty()) {
            // Remove
            if (found) {
                registered_networks.erase(p);
            }
        } else {
            // Validate and add, overwriting any existing entry
            auto np = std::make_shared<nlohmann::json>(network_parameters(details).get_json());
            registered_networks[name] = np;
        }
    }

    nlohmann::json network_parameters::get_all()
    {
        // We manually order mainnet/liquid/testnet first for nice wallet/UX display ordering
        std::vector<std::string> all_networks{ "mainnet", "liquid", "testnet" };
        nlohmann::json ret;

        std::unique_lock<std::mutex> l{ registered_networks_mutex };
        all_networks.reserve(registered_networks.size());
        for (const auto p : registered_networks) {
            ret[p.first] = *p.second;
            if (std::find(all_networks.begin(), all_networks.end(), p.first) == all_networks.end()) {
                all_networks.emplace_back(p.first);
            }
        }
        ret["all_networks"] = all_networks;
        return ret;
    }

    nlohmann::json network_parameters::get(const std::string& name)
    {
        std::unique_lock<std::mutex> l{ registered_networks_mutex };

        const auto p = registered_networks.find(name);
        GDK_RUNTIME_ASSERT_MSG(p != registered_networks.end(), "Unknown network");
        return *p->second;
    }
} // namespace sdk
} // namespace ga
