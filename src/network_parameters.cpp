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

// https://letsencrypt.org/certificates/
static const char* IDENTR3 = R"(
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMUpMghjISpDBbN3zANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0MFoXDTIxMDkyOTE5MjE0MFow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwIVKMz2oJTTDxLs
jVWSw/iC8ZmmekKIp10mqrUrucVMsa+Oa/l1yKPXD0eUFFU1V4yeqKI5GfWCPEKp
Tm71O8Mu243AsFzzWTjn7c9p8FoLG77AlCQlh/o3cbMT5xys4Zvv2+Q7RVJFlqnB
U840yFLuta7tj95gcOKlVKu2bQ6XpUA0ayvTvGbrZjR8+muLj1cpmfgwF126cm/7
gcWt0oZYPRfH5wm78Sv3htzB2nFd1EbjzK0lwYi8YGd1ZrPxGPeiXOZT/zqItkel
/xMY6pgJdz+dU/nPAeX1pnAXFK9jpP+Zs5Od3FOnBv5IhR2haa4ldbsTzFID9e1R
oYvbFQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYf
r52LFMLGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEA2UzgyfWEiDcx27sT4rP8i2tiEmxYt0l+PAK3qB8oYevO4C5z70kH
ejWEHx2taPDY/laBL21/WKZuNTYQHHPD5b1tXgHXbnL7KqC401dk5VvCadTQsvd8
S8MXjohyc9z9/G2948kLjmE6Flh9dDYrVYA9x2O+hEPGOaEOa1eePynBgPayvUfL
qjBstzLhWVQLGAkXXmNs+5ZnPBxzDJOLxhF2JIbeQAcH5H0tZrUlo5ZYyOqA7s9p
O5b85o3AM/OJ+CktFBQtfvBhcJVd9wvlwPsk+uyOy2HI7mNxKKgsBTt375teA2Tw
UdHkhVNcsAKX1H7GNNLOEADksd86wuoXvg==
-----END CERTIFICATE-----)";

// backup
static const char* IDENTR4 = R"(
-----BEGIN CERTIFICATE-----
MIIEZTCCA02gAwIBAgIQQAF1BIMlO+Rkt3exI9CKgjANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0NVoXDTIxMDkyOTE5MjE0NVow
MjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT
AlI0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsyjcdynT55G+87cK
AMf78lULJSJjUzav6Qgg3w2vKD7NxqtXtp2kJRml0jJtSaYIuccvoZuTxSBAa4Qx
IKKOMGAlYO/ZGok/H2lxstrqP3NBxJBvZv19nljYd8/NWXVEyaEKe58/Gw46Zm+2
dc+Ly6+dwHDF/9KCCq9dzeLonIWUpOYANeh+TjmBxyGJYHfqHZbyi4N7R8RtMsBS
fiMeRbVx7qPvF8IDqZOJ3fWf27rx2uB+l4dxgR4aglbkPnwYogjlFl+o+qjgSFFN
GBSgDKPltsqztVUSa3LHWn87jPnn2dGOEk0zMwMq8RPhQjzCLllgLm3gB0czZd/S
Z8pNhQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E
BAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p
ZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE
p7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE
AYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0
LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFDadPuCxQPYnLHy/jZ0x
ivZUpkYmMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B
AQsFAAOCAQEAN4CpgPmK2C5pq/RdV9gEdWcvPnPfT9ToucrAMTcn//wyWBWF2wG4
hvPBQxxuqPECZsi4nLQ45VJpyC1NDd0GqGQIMqNdC4N4TLDtd7Yhy8v5JsfEMUbb
6xW4sKeeeKy3afOkel60Xg1/7ndSmppiHqdh+TdJML1hptRgdxGiB8LMpHuW/oM8
akfyt4TkBhA8+Wu8MM6dlJyJ7nHBVnEUFQ4Ni+GzNC/pQSL2+Y9Mq4HHIk2ZFy0W
B8KsVwdeNrERPL+LjhhLde1Et0aL9nlv4CqwXHML2LPgk38j/WllbQ/8HRd2VpB+
JW6Z8JNhcnuBwATHMCeJVCFapoZsPfQQ6Q==
-----END CERTIFICATE-----)";

static const char* IDENTE1 = R"(
-----BEGIN CERTIFICATE-----
MIICxjCCAk2gAwIBAgIRALO93/inhFu86QOgQTWzSkUwCgYIKoZIzj0EAwMwTzEL
MAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNo
IEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjAwOTA0MDAwMDAwWhcN
MjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5j
cnlwdDELMAkGA1UEAxMCRTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQkXC2iKv0c
S6Zdl3MnMayyoGli72XoprDwrEuf/xwLcA/TmC9N/A8AmzfwdAVXMpcuBe8qQyWj
+240JxP2T35p0wKZXuskR5LBJJvmsSGPwSSB/GjMH2m6WPUZIvd0xhajggEIMIIB
BDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFrz7Sv8NsI3eblSMOpUb89V
yy6sMB8GA1UdIwQYMBaAFHxClq7eS0g7+pL4nozPbYupcjeVMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gyLmkubGVuY3Iub3JnLzAnBgNVHR8E
IDAeMBygGqAYhhZodHRwOi8veDIuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYG
Z4EMAQIBMA0GCysGAQQBgt8TAQEBMAoGCCqGSM49BAMDA2cAMGQCMHt01VITjWH+
Dbo/AwCd89eYhNlXLr3pD5xcSAQh8suzYHKOl9YST8pE9kLJ03uGqQIwWrGxtO3q
YJkgsTgDyj2gJrjubi1K9sZmHzOa25JK1fUpE8ZwYii6I4zPPS/Lgul/
-----END CERTIFICATE-----)";

// backup
static const char* IDENTE2 = R"(
-----BEGIN CERTIFICATE-----
MIICxjCCAkygAwIBAgIQTtI99q9+x/mwxHJv+VEqdzAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw0y
NTA5MTUxNjAwMDBaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNy
eXB0MQswCQYDVQQDEwJFMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABCOaLO3lixmN
YVWex+ZVYOiTLgi0SgNWtU4hufk50VU4Zp/LbBVDxCsnsI7vuf4xp4Cu+ETNggGE
yBqJ3j8iUwe5Yt/qfSrRf1/D5R58duaJ+IvLRXeASRqEL+VkDXrW3qOCAQgwggEE
MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw
EgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUbZkq9U0C6+MRwWC6km+NPS7x
6kQwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5UwMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMCcGA1UdHwQg
MB4wHKAaoBiGFmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wIgYDVR0gBBswGTAIBgZn
gQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZIzj0EAwMDaAAwZQIxAPJCN9qpyDmZ
tX8K3m8UYQvK51BrXclM6WfrdeZlUBKyhTXUmFAtJw4X6A0x9mQFPAIwJa/No+KQ
UAM1u34E36neL/Zba7ombkIOchSgx1iVxzqtFWGddgoG+tppRPWhuhhn
-----END CERTIFICATE-----)";

static std::map<std::string, std::shared_ptr<nlohmann::json>> registered_networks = {
    { "localtest",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Localtest" }, { "network", "localtest" }, { "wamp_url", "ws://localhost:8080/v2/ws" },
                { "wamp_onion_url", std::string() }, { "wamp_cert_pins", nlohmann::json::array() },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, IDENTR3, IDENTR4, IDENTE1, IDENTE2 } },
                { "address_explorer_url", std::string() }, { "tx_explorer_url", std::string() },
                { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
                { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 111u }, { "p2sh_version", 196u },
                { "bech32_prefix", "bcrt" }, { "mainnet", false }, { "liquid", false }, { "development", true },
                { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } }, { "bip21_prefix", "bitcoin" },
                { "electrum_url", "localhost:19002" }, { "tls", false }, { "server_type", "green" },
                { "spv_enabled", false }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "liquid",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Liquid" }, { "network", "liquid" }, { "wamp_url", "wss://liquidwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://liquidbtc7u746j4.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "730c1bdcd85f57ce5dc0bba733e5f1ba5a925b2a771d640a26f7a454224dad3b",
                        "46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda",
                        "5a8f16fda448d783481cca57a2428d174dad8c60943ceb28f661ae31fd39a5fa",
                        "b42688d73bac5099d9cf4fdb7b05f5e54e98c5aa8ab56ee06c297a9a84d2d5f1" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, IDENTR3, IDENTR4, IDENTE1, IDENTE2 } },
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
                { "electrum_url", "blockstream.info:995" }, { "spv_enabled", false }, { "tls", true },
                { "server_type", "green" }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Localtest Liquid" },
            { "network", "localtest-liquid" }, { "wamp_url", "ws://localhost:8080/v2/ws" },
            { "wamp_onion_url", std::string() }, { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, IDENTR3, IDENTR4, IDENTE1, IDENTE2 } },
            { "address_explorer_url", std::string() }, { "tx_explorer_url", std::string() },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 235u }, { "p2sh_version", 75u },
            { "bech32_prefix", "ert" }, { "mainnet", false }, { "liquid", true }, { "development", true },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "blinded_prefix", 4u }, { "ct_exponent", 0 }, { "ct_bits", 52 }, { "blech32_prefix", "el" },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 25920, 51840, 65535 } },
            { "electrum_url", "localhost:50001" }, { "spv_enabled", false }, { "tls", false },
            { "bip21_prefix", "liquidnetwork" }, { "server_type", "green" }, { "spv_cross_validation", false },
            { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Bitcoin" }, { "network", "mainnet" }, { "wamp_url", "wss://prodwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://s7a4rvc6425y72d2.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "730c1bdcd85f57ce5dc0bba733e5f1ba5a925b2a771d640a26f7a454224dad3b",
                        "46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda",
                        "5a8f16fda448d783481cca57a2428d174dad8c60943ceb28f661ae31fd39a5fa",
                        "b42688d73bac5099d9cf4fdb7b05f5e54e98c5aa8ab56ee06c297a9a84d2d5f1" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, IDENTR3, IDENTR4, IDENTE1, IDENTE2 } },
                { "address_explorer_url", "https://blockstream.info/address/" },
                { "tx_explorer_url", "https://blockstream.info/tx/" },
                { "service_pubkey", "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f" },
                { "service_chain_code", "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 0u }, { "p2sh_version", 5u },
                { "bech32_prefix", "bc" }, { "mainnet", true }, { "liquid", false }, { "development", false },
                { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } }, { "bip21_prefix", "bitcoin" },
                { "electrum_url", "blockstream.info:700" }, { "spv_enabled", false }, { "tls", true },
                { "server_type", "green" }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "testnet",
        std::make_shared<nlohmann::json>(nlohmann::json(
            { { "name", "Testnet" }, { "network", "testnet" }, { "wamp_url", "wss://testwss.greenaddress.it/v2/ws" },
                { "wamp_onion_url", "ws://gu5ke7a2aguwfqhz.onion/v2/ws" },
                { "wamp_cert_pins",
                    std::vector<std::string>{ "25847d668eb4f04fdd40b12b6b0740c567da7d024308eb6c2c96fe41d9de218d",
                        "730c1bdcd85f57ce5dc0bba733e5f1ba5a925b2a771d640a26f7a454224dad3b",
                        "46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda",
                        "5a8f16fda448d783481cca57a2428d174dad8c60943ceb28f661ae31fd39a5fa",
                        "b42688d73bac5099d9cf4fdb7b05f5e54e98c5aa8ab56ee06c297a9a84d2d5f1" } },
                { "wamp_cert_roots", std::vector<std::string>{ IDENTX3, IDENTR3, IDENTR4, IDENTE1, IDENTE2 } },
                { "address_explorer_url", "https://blockstream.info/testnet/address/" },
                { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
                { "electrum_url", "blockstream.info:993" }, { "spv_enabled", false }, { "tls", true },
                { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
                { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
                { "default_peers", nlohmann::json::array() }, { "p2pkh_version", 111u }, { "p2sh_version", 196u },
                { "bech32_prefix", "tb" }, { "mainnet", false }, { "liquid", false }, { "development", false },
                { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } }, { "bip21_prefix", "bitcoin" },
                { "server_type", "green" }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

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
            { "electrum_url", "localhost:3000" }, { "spv_enabled", false }, { "tls", false },
            { "bip21_prefix", "bitcoin" }, { "server_type", "green" }, { "spv_cross_validation", false },
            { "spv_cross_validation_servers", nlohmann::json::array() } })) },

#ifdef BUILD_GDK_RUST
    { "liquid-electrum-mainnet",
        std::make_shared<nlohmann::json>(
            nlohmann::json({ { "name", "Electrum Liquid" }, { "network", "liquid-electrum-mainnet" },
                { "address_explorer_url", "https://blockstream.info/liquid/address/" },
                { "electrum_url", "blockstream.info:995" }, { "spv_enabled", false }, { "tls", true },
                { "asset_registry_url", "https://assets.blockstream.info" },
                { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" },
                { "tx_explorer_url", "https://blockstream.info/liquid/tx/" }, { "mainnet", true }, { "liquid", true },
                { "development", false },
                { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
                { "ct_exponent", 0 }, { "ct_bits", 52 }, { "bip21_prefix", "liquidnetwork" },
                { "server_type", "electrum" }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "liquid-electrum-regtest",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Liquid Regtest" },
            { "network", "liquid-electrum-regtest" }, { "url", "localhost:50001" }, { "spv_enabled", false },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://vi5flmr4z3h3luup.onion" }, { "tls", false }, { "mainnet", false },
            { "liquid", true }, { "development", true },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "ct_exponent", 0 }, { "ct_bits", 52 }, { "bip21_prefix", "liquidregtestnetwork" },
            { "server_type", "electrum" }, { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "electrum-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Mainnet" },
            { "network", "electrum-mainnet" }, { "address_explorer_url", "https://blockstream.info/address/" },
            { "electrum_url", "blockstream.info:700" }, { "spv_enabled", false }, { "tls", true },
            { "tx_explorer_url", "https://blockstream.info/tx/" }, { "mainnet", true }, { "liquid", false },
            { "development", false }, { "bip21_prefix", "bitcoin" }, { "server_type", "electrum" },
            { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "electrum-testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Testnet" },
            { "network", "electrum-testnet" }, { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "electrum_url", "blockstream.info:993" }, { "spv_enabled", false }, { "tls", true },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" }, { "mainnet", false }, { "liquid", false },
            { "bip21_prefix", "bitcoin" }, { "development", false }, { "server_type", "electrum" },
            { "spv_cross_validation", false }, { "spv_cross_validation_servers", nlohmann::json::array() } })) },

    { "electrum-regtest",
        std::make_shared<nlohmann::json>(nlohmann::json({ { "name", "Electrum Regtest" },
            { "network", "electrum-regtest" }, { "address_explorer_url", "http://127.0.0.1:8080/address/" },
            { "tx_explorer_url", "http://127.0.0.1:8080/tx/" }, { "mainnet", false }, { "liquid", false },
            { "electrum_url", "localhost:50001" }, { "spv_enabled", false }, { "tls", false }, { "development", true },
            { "bip21_prefix", "bitcoin" }, { "server_type", "electrum" }, { "spv_cross_validation", false },
            { "spv_cross_validation_servers", nlohmann::json::array() } })) },
#endif

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
        for (const auto& p : registered_networks) {
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
