#include <boost/algorithm/string/predicate.hpp>
#include <mutex>

#include "assertion.hpp"
#include "exception.hpp"
#include "json_utils.hpp"
#include "network_parameters.hpp"
#include "session.hpp" // TODO: gdk_config() doesn't belong in session

// TODO: Use std::string_view when its fully supported

// clang-format off
namespace {

static std::vector<std::string> default_wamp_cert_roots = {

// TODO: generate these from pem file?
// https://www.identrust.com/certificates/trustid/root-download-x3.html

// subject: '/C=US/O=Let's Encrypt/CN=E1'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
// not before: Fri Sep  4 00:00:00 2020
// not after: Mon Sep 15 16:00:00 2025
R"(
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
-----END CERTIFICATE-----)",

// backup
//
// subject: '/C=US/O=Let's Encrypt/CN=E2'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
// not before: Fri Sep  4 00:00:00 2020
// not after: Mon Sep 15 16:00:00 2025
R"(
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
-----END CERTIFICATE-----)",

// subject: '/C=US/O=Google Trust Services LLC/CN=GTS Root R1'
// issuer: '/C=US/O=Google Trust Services LLC/CN=GTS Root R1'
// not before: Wed Jun 22 00:00:00 2016
// not after: Sun Jun 22 00:00:00 2036
R"(
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgIQbkepxUtHDA3sM9CJuRz04TANBgkqhkiG9w0BAQwFADBH
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIy
MDAwMDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNl
cnZpY2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaM
f/vo27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vX
mX7wCl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7
zUjwTcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0P
fyblqAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtc
vfaHszVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4
Zor8Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUsp
zBmkMiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOO
Rc92wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYW
k70paDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+
DVrNVjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgF
lQIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBADiW
Cu49tJYeX++dnAsznyvgyv3SjgofQXSlfKqE1OXyHuY3UjKcC9FhHb8owbZEKTV1
d5iyfNm9dKyKaOOpMQkpAWBz40d8U6iQSifvS9efk+eCNs6aaAyC58/UEBZvXw6Z
XPYfcX3v73svfuo21pdwCxXu11xWajOl40k4DLh9+42FpLFZXvRq4d2h9mREruZR
gyFmxhE+885H7pwoHyXa/6xmld01D1zvICxi/ZG6qcz8WpyTgYMpl0p8WnK0OdC3
d8t5/Wk6kjftbjhlRn7pYL15iJdfOBL07q9bgsiG1eGZbYwE8na6SfZu6W0eX6Dv
J4J2QPim01hcDyxC2kLGe4g0x8HYRZvBPsVhHdljUEn2NIVq4BjFbkerQUIpm/Zg
DdIx02OYI5NaAIFItO/Nis3Jz5nu2Z6qNuFoS3FJFDYoOj0dzpqPJeaAcWErtXvM
+SUWgeExX6GjfhaknBZqlxi9dnKlC54dNuYvoS++cJEPqOba+MSSQGwlfnuzCdyy
F62ARPBopY+Udf90WuioAnwMCeKpSwughQtiue+hMZL77/ZRBIls6Kl0obsXs7X9
SQ98POyDGCBDTtWTurQ0sR8WNh8M5mQ5Fkzc4P4dyKliPUDqysU0ArSuiYgzNdws
E3PYJ/HQcu51OyLemGhmW/HGY0dVHLqlCFF1pkgl
-----END CERTIFICATE-----)",

// subject: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
// issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
// not before: Thu Jun  4 11:04:38 2015
// not after: Mon Jun  4 11:04:38 2035
R"(
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
-----END CERTIFICATE-----)",
};

static std::vector<std::string> default_wamp_cert_pins = {
    // subject: '/C=US/O=Let's Encrypt/CN=E1'
    // issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X2'
    // not before: Fri Sep  4 00:00:00 2020
    // not after: Mon Sep 15 16:00:00 2025
    "46494e30379059df18be52124305e606fc59070e5b21076ce113954b60517cda",

    // subject: '/C=US/O=Let's Encrypt/CN=R3'
    // issuer: '/C=US/O=Internet Security Research Group/CN=ISRG Root X1'
    // not before: Fri Sep  4 00:00:00 2020
    // not after: Mon Sep 15 16:00:00 2025
    "67add1166b020ae61b8f5fc96813c04c2aa589960796865572a3c7e737613dfd",

    // subject: 'C=US, O=Google Trust Services LLC, CN=GTS CA 1D4'
    // issuer: 'C=US, O=Google Trust Services LLC, CN=GTS Root R1'
    // not before: 'Aug 13 00:00:42 2020 GMT'
    // not after: 'Sep 30 00:00:42 2027 GMT'
    "64e286b76063602a372efd60cde8db2656a49ee15e84254b3d6eb5fe38f4288b",

    // Google Intermediate certs
    "812c212e9e45dc5005c7f47411183f5fb2ff1baee184d3354b2e93d78c280164",
    "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522",
    "64e286b76063602a372efd60cde8db2656a49ee15e84254b3d6eb5fe38f4288b",
    "02609e88979fc6862ea1571f3bc6df6c70f2fe9277473e43fe04c3597c43431d",
    "97d42003e132552946097f20ef955f5b1cd570aa4372d780033a65efbe69758d",
    "11c697878732056de17c1da134e9d2b6d23cf1de95b3fb0a4d18a517ab63230a",
    "edbcdd01698d83eafa1e3d38f017b3ad96b2d8d88e746c58011cee0ef106939c",
    "f5d12415a12c07fde93bd6f9e4e4588e03d20596e4f8a5e9d213a83364bcee71",
    "3647aac2b282bc941fe7a642e3dcb99cfc5b3c6dce944a1e96f8028e89b7b090",
    "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5",
    "76b27b80a58027dc3cf1da68dac17010ed93997d0b603e2fadbe85012493b5a7",
    "bdf40c618e862d9b6b52718a1fb35bb951dfdbd2428b17d8a3fc64df9e5df355",
    "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96",
    "a287ffab762cc69a26d482037edf701f653ce899025c62a7e5cb88bb9b419cbb",
    "9c3f2fd11c57d7c649ad5a0932c0f0d29756f6a0a1c74c43e1e89a62d64cd320",
    "54f8ca858bcc7591f28d8dc3772e9bc581717f3a23a288bfd405939c36208de5",
    "9f819a4c876e12dc84e6fe0e37c1a69b137094b453fa98449398f4b71f4d0092",
    "54c660da29d75fc81f07ad6dc8bb7aee2258e071e8b1077544fa5622ff44c99d",
    "d0c97e56c7b0ba812d944ad771f7799b5d4144a2327a4e416554f7ee2aa0aeae",
    "9d5e86906a1680a86be278cf76e3d2b62b775186101461d303cee910d94ce13a",
    "847409e63526f162753ac49f75218efaafa7d5c94ade9095ce72e7f6b6e3ac99",
    "b10b6f00e609509e8700f6d34687a2bfce38ea05a8fdf1cdc40c3a2a0d0d0e45",
    "e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4",
    "2fe357db13751ff9160e87354975b3407498f41c9bd16a48657866e6e5a9b4c7",
    "dc9416c2f855126d6de977677538f2f967ff4998e90dfa435a17219be077fc06",
    "ae0fc852280f1b87cedaf73cfb84cf106efec88e8294253af352ed4034460d7b",
};

static std::map<std::string, std::shared_ptr<nlohmann::json>> registered_networks = {
    { "localtest",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "address_explorer_onion_url", std::string() },
            { "bech32_prefix", "bcrt" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 20, 144, 4320, 51840 } },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:19002" },
            { "electrum_onion_url", std::string() },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "http://localhost:8080/prices" },
            { "price_onion_url", std::string() },
            { "liquid", false },
            { "mainnet", false },
            { "max_reorg_blocks", 7 * 144u },
            { "min_fee_rate", nullptr },
            { "name", "Localtest" },
            { "network", "localtest" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "tx_explorer_onion_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "ws://localhost:8080/v2/ws" },
            { "wamp_onion_url", std::string() },
        })) },

    { "liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/liquid/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquid/address/" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion" },
            { "bech32_prefix", "ex" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "lq" },
            { "blinded_prefix", 12u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 65535 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "elements-mainnet.blockstream.info:50002" },
            { "electrum_onion_url", "liqm3aeuthw4eacn2gssv4qg4zfhmy24rmtghp3vujintldu7jaxqyid.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-mainnet.blockstream.com/prices" },
            { "price_onion_url", "http://greenv32e5p4rax6dmfgb4zzl7kq2fbmizd7miyava2actplmipyx2qd.onion/prices" },
            { "liquid", true },
            { "mainnet", true },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Liquid" },
            { "network", "liquid" },
            { "p2pkh_version", 57u },
            { "p2sh_version", 39u },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "server_type", "green" },
            { "service_chain_code", "02721cc509aa0c2f4a90628e9da0391b196abeabc6393ed4789dd6222c43c489" },
            { "service_pubkey", "02c408c3bb8a3d526103fb93246f54897bdd997904d3e18295b49a26965cb41b7f" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquid/tx/" },
            { "wamp_cert_pins", nlohmann::json::array({"default"}) },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "wss://green-liquid-mainnet.blockstream.com/v2/ws" },
            { "wamp_onion_url", "ws://liquidbtcgecscpokecnr5uwg2de55shdq7dnvlpzeju7tnefbekicqd.onion/v2/ws" },
        })) },

    { "localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "address_explorer_onion_url", std::string() },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion" },
            { "bech32_prefix", "ert" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "el" },
            { "blinded_prefix", 4u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 20, 1440, 65535 } },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:19002" },
            { "electrum_onion_url", std::string() },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "http://localhost:8080/prices" },
            { "price_onion_url", std::string() },
            { "liquid", true },
            { "mainnet", false },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Localtest Liquid" },
            { "network", "localtest-liquid" },
            { "p2pkh_version", 235u },
            { "p2sh_version", 75u },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "tx_explorer_onion_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "ws://localhost:8080/v2/ws" },
            { "wamp_onion_url", std::string() },
        })) },

    { "testnet-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://esplora.blockstream.com/liquidtestnet/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquidtestnet/address/" },
            { "asset_registry_url", "https://assets-testnet.blockstream.info/" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion/testnet/" },
            { "bech32_prefix", "tex" },
            { "bip21_prefix", "liquidtestnet" },
            { "blech32_prefix", "tlq" },
            { "blinded_prefix", 23u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 1440, 65535 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "elements-testnet.blockstream.info:50002" },
            { "electrum_onion_url", "liqtzdv3soz7onazmbqzvzbrcgz73bdqlcuhbqlkucjj7i6irbdmoryd.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-testnet.blockstream.com/prices" },
            { "price_onion_url", "http://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion/prices" },
            { "liquid", true },
            { "mainnet", false },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Testnet Liquid" },
            { "network", "testnet-liquid" },
            { "p2pkh_version", 36u },
            { "p2sh_version", 19u },
            { "policy_asset", "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49" },
            { "server_type", "green" },
            { "service_chain_code", "c660eec6d9c536f4121854146da22e02d4c91d72af004d41729b9a592f0788e5" },
            { "service_pubkey", "02c47d84a5b256ee3c29df89642d14b6ed73d17a2b8af0aca18f6f1900f1633533" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://esplora.blockstream.com/liquidtestnet/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquidtestnet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "wss://green-liquid-testnet.blockstream.com/v2/ws" },
            { "wamp_onion_url", "ws://liqtestulh46kwla3mgenugrcogvjjvzr2qdto663hujwnbaewzpkoad.onion/v2/ws" },
        })) },

    { "mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/address/" },
            { "bech32_prefix", "bc" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "bitcoin-mainnet.blockstream.info:50002" },
            { "electrum_onion_url", "btcmxqzlrigojf2sdp6ekwjibucdqifpw34yidjez3x7ecdtbkuzavid.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-mainnet.blockstream.com/prices" },
            { "price_onion_url", "http://greenv32e5p4rax6dmfgb4zzl7kq2fbmizd7miyava2actplmipyx2qd.onion/prices" },
            { "liquid", false },
            { "mainnet", true },
            { "max_reorg_blocks", 144u },
            { "min_fee_rate", nullptr },
            { "name", "Bitcoin" },
            { "network", "mainnet" },
            { "p2pkh_version", 0u },
            { "p2sh_version", 5u },
            { "server_type", "green" },
            { "service_chain_code", "e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d" },
            { "service_pubkey", "0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/tx/" },
            { "wamp_cert_pins", nlohmann::json::array({"default"}) },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "wss://green-bitcoin-mainnet.blockstream.com/v2/ws" },
            { "wamp_onion_url", "ws://greenv32e5p4rax6dmfgb4zzl7kq2fbmizd7miyava2actplmipyx2qd.onion:80/v2/ws" },
        })) },

    { "testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/testnet/address/" },
            { "bech32_prefix", "tb" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>{ 144, 4320, 51840 } },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "bitcoin-testnet.blockstream.info:50002" },
            { "electrum_onion_url", "btctxun5igzd4bv7t42ayifqsfugkfevfdly2543ddadl2634s2ortyd.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-testnet.blockstream.com/prices" },
            { "price_onion_url", "http://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion/prices" },
            { "liquid", false },
            { "mainnet", false },
            { "max_reorg_blocks", 7 * 144u },
            { "min_fee_rate", nullptr },
            { "name", "Testnet" },
            { "network", "testnet" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "green" },
            { "service_chain_code", "b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04" },
            { "service_pubkey", "036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3" },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/testnet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", "wss://green-bitcoin-testnet.blockstream.com/v2/ws" },
            { "wamp_onion_url", "ws://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion:80/v2/ws" },
        })) },

    { "electrum-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/liquid/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquid/address/" },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion" },
            { "bech32_prefix", "ex" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "lq" },
            { "blinded_prefix", 12u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "elements-mainnet.blockstream.info:50002" },
            { "electrum_onion_url", "liqm3aeuthw4eacn2gssv4qg4zfhmy24rmtghp3vujintldu7jaxqyid.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-mainnet.blockstream.com/prices" },
            { "price_onion_url", "http://greenv32e5p4rax6dmfgb4zzl7kq2fbmizd7miyava2actplmipyx2qd.onion/prices" },
            { "liquid", true },
            { "mainnet", true },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Liquid (Electrum)" },
            { "network", "electrum-liquid" },
            { "p2pkh_version", 57u },
            { "p2sh_version", 39u },
            { "policy_asset", "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d" },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/liquid/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquid/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-localtest-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", std::string() },
            { "address_explorer_onion_url", std::string() },
            { "asset_registry_url", "https://assets.blockstream.info" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion" },
            { "bech32_prefix", "ert" },
            { "bip21_prefix", "liquidnetwork" },
            { "blech32_prefix", "el" },
            { "blinded_prefix", 4u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:19002" },
            { "electrum_onion_url", std::string() },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "http://localhost:8080/prices" },
            { "price_onion_url", std::string() },
            { "liquid", true },
            { "mainnet", false },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Localtest Liquid (Electrum)" },
            { "network", "electrum-localtest-liquid" },
            { "p2pkh_version", 235u },
            { "p2sh_version", 75u },
            { "policy_asset", "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225" },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", std::string() },
            { "tx_explorer_onion_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-mainnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/address/" },
            { "bech32_prefix", "bc" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "bitcoin-mainnet.blockstream.info:50002" },
            { "electrum_onion_url", "btcmxqzlrigojf2sdp6ekwjibucdqifpw34yidjez3x7ecdtbkuzavid.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-mainnet.blockstream.com/prices" },
            { "price_onion_url", "http://greenv32e5p4rax6dmfgb4zzl7kq2fbmizd7miyava2actplmipyx2qd.onion/prices" },
            { "liquid", false },
            { "mainnet", true },
            { "max_reorg_blocks", 144u },
            { "min_fee_rate", nullptr },
            { "name", "Bitcoin (Electrum)" },
            { "network", "electrum-mainnet" },
            { "p2pkh_version", 0u },
            { "p2sh_version", 5u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-testnet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/testnet/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/testnet/address/" },
            { "bech32_prefix", "tb" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "bitcoin-testnet.blockstream.info:50002" },
            { "electrum_onion_url", "btctxun5igzd4bv7t42ayifqsfugkfevfdly2543ddadl2634s2ortyd.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-testnet.blockstream.com/prices" },
            { "price_onion_url", "http://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion/prices" },
            { "liquid", false },
            { "mainnet", false },
            { "max_reorg_blocks", 7 * 144u },
            { "min_fee_rate", nullptr },
            { "name", "Testnet (Electrum)" },
            { "network", "electrum-testnet" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/testnet/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/testnet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-signet",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://mempool.space/signet/address/" },
            { "address_explorer_onion_url", "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/address/" },
            { "bech32_prefix", "tb" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "mempool.space:60602" },
            { "electrum_onion_url", "mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion:60602" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-testnet.blockstream.com/prices" },
            { "price_onion_url", "http://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion/prices" },
            { "liquid", false },
            { "mainnet", false },
            { "max_reorg_blocks", 7 * 144u },
            { "min_fee_rate", nullptr },
            { "name", "Signet (Electrum)" },
            { "network", "electrum-signet" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://mempool.space/signet/tx/" },
            { "tx_explorer_onion_url", "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion/signet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-localtest",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "http://127.0.0.1:8080/address/" },
            { "address_explorer_onion_url", std::string() },
            { "bech32_prefix", "bcrt" },
            { "bip21_prefix", "bitcoin" },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", true },
            { "electrum_tls", false },
            { "electrum_url", "localhost:19002" },
            { "electrum_onion_url", std::string() },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "http://localhost:8080/prices" },
            { "price_onion_url", std::string() },
            { "liquid", false },
            { "mainnet", false },
            { "max_reorg_blocks", 7 * 144u },
            { "min_fee_rate", nullptr },
            { "name", "Localtest (Electrum)" },
            { "network", "electrum-localtest" },
            { "p2pkh_version", 111u },
            { "p2sh_version", 196u },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "http://127.0.0.1:8080/tx/" },
            { "tx_explorer_onion_url", std::string() },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },

    { "electrum-testnet-liquid",
        std::make_shared<nlohmann::json>(nlohmann::json({
            { "address_explorer_url", "https://blockstream.info/liquidtestnet/address/" },
            { "address_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquidtestnet/address/" },
            { "asset_registry_url", "https://assets-testnet.blockstream.info/" },
            { "asset_registry_onion_url", "http://lhquhzzpzg5tyymcqep24fynpzzqqg3m3rlh7ascnw5cpqsro35bfxyd.onion/testnet/" },
            { "bech32_prefix", "tex" },
            { "bip21_prefix", "liquidtestnet" },
            { "blech32_prefix", "tlq" },
            { "blinded_prefix", 23u },
            { "blob_server_url", std::string() },
            { "blob_server_onion_url", std::string() },
            { "csv_buckets", std::vector<uint32_t>() },
            { "development", false },
            { "electrum_tls", true },
            { "electrum_url", "elements-testnet.blockstream.info:50002" },
            { "electrum_onion_url", "liqtzdv3soz7onazmbqzvzbrcgz73bdqlcuhbqlkucjj7i6irbdmoryd.onion:50001" },
            { "pin_server_url", "https://jadepin.blockstream.com" },
            { "pin_server_onion_url", "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion" },
            { "pin_server_public_key", "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547" },
            { "price_url", "https://green-bitcoin-testnet.blockstream.com/prices" },
            { "price_onion_url", "http://greent5yfxruca52pkqjtgo2qdxijscqlastnv3jwzpmavvffdldm2yd.onion/prices" },
            { "liquid", true },
            { "mainnet", false },
            { "max_reorg_blocks", 2 },
            { "min_fee_rate", nullptr },
            { "name", "Testnet Liquid (Electrum)" },
            { "network", "electrum-testnet-liquid" },
            { "p2pkh_version", 36u },
            { "p2sh_version", 19u },
            { "policy_asset", "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49" },
            { "server_type", "electrum" },
            { "service_chain_code", std::string() },
            { "service_pubkey", std::string() },
            { "spv_multi", false },
            { "spv_servers", nlohmann::json::array() },
            { "spv_enabled", false },
            { "tx_explorer_url", "https://blockstream.info/liquidtestnet/tx/" },
            { "tx_explorer_onion_url", "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion/liquidtestnet/tx/" },
            { "wamp_cert_pins", nlohmann::json::array() },
            { "wamp_cert_roots", nlohmann::json::array({"default"}) },
            { "wamp_url", std::string() },
            { "wamp_onion_url", std::string() },
        })) },
};
    // clang-format on

    static std::mutex registered_networks_mutex;
} // namespace

namespace green {

    namespace {
        static std::string get_url(
            const nlohmann::json& details, const char* url_key, const char* onion_key, bool use_tor)
        {
            if (use_tor) {
                std::string onion = details.at(onion_key);
                if (!onion.empty()) {
                    return onion;
                }
            }
            return details.at(url_key);
        }

        template <typename T>
        static void set_override(
            nlohmann::json& ret, const std::string& key, const nlohmann::json& src, const T& default_)
        {
            // Use the users provided value, else the registered value, else `default_`
            ret[key] = src.value(key, ret.value(key, default_));
        }

        static auto get_network_overrides(const nlohmann::json& user_overrides, nlohmann::json& defaults)
        {
            const std::string empty;
            // Set override-able settings from the users parameters
            set_override(defaults, "asset_registry_onion_url", user_overrides, empty);
            set_override(defaults, "asset_registry_url", user_overrides, empty);
            set_override(defaults, "cert_expiry_threshold", user_overrides, 1);
            set_override(defaults, "electrum_onion_url", user_overrides, empty);
            set_override(defaults, "electrum_tls", user_overrides, false);
            set_override(defaults, "electrum_url", user_overrides, empty);
            set_override(defaults, "pin_server_onion_url", user_overrides, empty);
            set_override(defaults, "pin_server_url", user_overrides, empty);
            set_override(defaults, "price_onion_url", user_overrides, empty);
            set_override(defaults, "price_url", user_overrides, empty);
            set_override(defaults, "proxy", user_overrides, empty);
            set_override(defaults, "spv_enabled", user_overrides, false);
            set_override(defaults, "spv_multi", user_overrides, false);
            set_override(defaults, "spv_servers", user_overrides, nlohmann::json::array());
            set_override(defaults, "use_tor", user_overrides, false);
            set_override(defaults, "user_agent", user_overrides, empty);
            set_override(defaults, "blob_server_onion_url", user_overrides, empty);
            set_override(defaults, "blob_server_url", user_overrides, empty);
            set_override(defaults, "gap_limit", user_overrides, 20);
            set_override(defaults, "address_explorer_url", user_overrides, empty);
            set_override(defaults, "address_explorer_onion_url", user_overrides, empty);
            set_override(defaults, "tx_explorer_url", user_overrides, empty);
            set_override(defaults, "tx_explorer_onion_url", user_overrides, empty);

            defaults["state_dir"] = gdk_config().value("datadir", empty) + "/state";

            // Handle min fee rate specifically; it is null by default
            auto fee_rate = j_uint32(user_overrides, "min_fee_rate");
            if (fee_rate) {
                defaults["min_fee_rate"] = *fee_rate; // User wants a value
            } else if (user_overrides.contains("fee_rate") || !defaults.contains("min_fee_rate")) {
                defaults["min_fee_rate"] = nullptr; // User wants null, or no default
            }
            return defaults;
        }
    } // namespace

    network_parameters::network_parameters(const nlohmann::json& details)
        : m_details(details)
    {
        GDK_RUNTIME_ASSERT_MSG(
            !is_main_net() || get_blob_server_url().empty(), "Blobserver is not yet enabled on mainnet");
    }

    network_parameters::network_parameters(const nlohmann::json& user_overrides, nlohmann::json& defaults)
        : m_details(get_network_overrides(user_overrides, defaults))
    {
    }

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
        std::vector<std::string> all_networks{ "mainnet", "liquid", "testnet", "testnet-liquid" };
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
        if (p == registered_networks.end()) {
            throw user_error("Unknown network");
        }
        return *p->second;
    }

    std::string network_parameters::network() const { return m_details.at("network"); }
    std::string network_parameters::gait_wamp_url(const std::string& config_prefix) const
    {
        return m_details.at(config_prefix + "_url");
    }
    std::vector<std::string> network_parameters::gait_wamp_cert_pins() const
    {
        auto certificates = m_details.value("wamp_cert_pins", std::vector<std::string>{});
        auto pos = std::find(certificates.cbegin(), certificates.cend(), "default");
        if (pos == certificates.cend()) {
            return certificates;
        }
        certificates.erase(pos);
        std::copy(default_wamp_cert_pins.cbegin(), default_wamp_cert_pins.cend(), std::back_inserter(certificates));
        return certificates;
    }
    std::vector<std::string> network_parameters::gait_wamp_cert_roots() const
    {
        auto certificates = m_details.value("wamp_cert_roots", std::vector<std::string>{});
        auto pos = std::find(certificates.cbegin(), certificates.cend(), "default");
        if (pos == certificates.cend()) {
            return certificates;
        }
        certificates.erase(pos);
        std::copy(default_wamp_cert_roots.cbegin(), default_wamp_cert_roots.cend(), std::back_inserter(certificates));
        return certificates;
    }
    std::string network_parameters::block_explorer_address() const
    {
        return get_url(m_details, "address_explorer_url", "address_explorer_onion_url", use_tor());
    }
    std::string network_parameters::block_explorer_tx() const
    {
        return get_url(m_details, "tx_explorer_url", "tx_explorer_onion_url", use_tor());
    }
    std::string network_parameters::chain_code() const { return m_details.at("service_chain_code"); }
    bool network_parameters::electrum_tls() const { return m_details.at("electrum_tls"); }
    std::string network_parameters::electrum_url() const
    {
        return get_url(m_details, "electrum_url", "electrum_onion_url", use_tor());
    }
    std::string network_parameters::get_pin_server_url() const
    {
        return get_url(m_details, "pin_server_url", "pin_server_onion_url", use_tor());
    }
    std::string network_parameters::get_pin_server_public_key() const { return m_details.at("pin_server_public_key"); }
    std::string network_parameters::get_blob_server_url() const
    {
        return get_url(m_details, "blob_server_url", "blob_server_onion_url", use_tor());
    }
    std::string network_parameters::pub_key() const { return m_details.at("service_pubkey"); }
    std::string network_parameters::gait_onion(const std::string& config_prefix) const
    {
        return m_details.at(config_prefix + "_onion_url");
    }
    std::string network_parameters::get_policy_asset() const { return m_details.value("policy_asset", "btc"); }
    std::string network_parameters::bip21_prefix() const { return m_details.at("bip21_prefix"); }
    std::string network_parameters::bech32_prefix() const { return m_details.at("bech32_prefix"); }
    std::string network_parameters::blech32_prefix() const { return m_details.value("blech32_prefix", std::string()); }
    unsigned char network_parameters::btc_version() const { return m_details.at("p2pkh_version"); }
    unsigned char network_parameters::btc_p2sh_version() const { return m_details.at("p2sh_version"); }
    uint32_t network_parameters::blinded_prefix() const { return m_details.at("blinded_prefix"); }
    bool network_parameters::is_main_net() const { return m_details.at("mainnet"); }
    bool network_parameters::is_liquid() const { return m_details.value("liquid", false); }
    bool network_parameters::is_development() const { return m_details.at("development"); }
    bool network_parameters::is_electrum() const { return m_details.value("server_type", std::string()) == "electrum"; }
    bool network_parameters::use_tor() const { return m_details.value("use_tor", false); }
    bool network_parameters::is_spv_enabled() const { return m_details.at("spv_enabled"); }
    std::string network_parameters::user_agent() const { return m_details.value("user_agent", std::string()); }
    std::string network_parameters::get_connection_string(const std::string& config_prefix) const
    {
        return use_tor() ? gait_onion(config_prefix) : gait_wamp_url(config_prefix);
    }
    std::string network_parameters::get_registry_connection_string() const
    {
        return get_url(m_details, "asset_registry_url", "asset_registry_onion_url", use_tor());
    }
    bool network_parameters::is_tls_connection(const std::string& config_prefix) const
    {
        return boost::algorithm::starts_with(get_connection_string(config_prefix), "wss://");
    }
    bool network_parameters::are_matching_csv_buckets(const nlohmann::json::array_t& buckets) const
    {
        return j_arrayref(m_details, "csv_buckets") == buckets;
    }

    bool network_parameters::is_valid_csv_value(uint32_t csv_blocks) const
    {
        const auto& buckets = j_arrayref(m_details, "csv_buckets");
        return std::find(buckets.begin(), buckets.end(), csv_blocks) != buckets.end();
    }

    uint32_t network_parameters::cert_expiry_threshold() const { return m_details.at("cert_expiry_threshold"); }
    // max_reorg_blocks indicates the maximum number of blocks that gdk will expect to re-org on-chain.
    // In the event that a re-org is larger than this value, AND the user has a tx re-orged in a block
    // older than the current tip minus max_reorg_blocks, cached data may become out of date and will
    // need to be removed. The values chosen are designed to make this scenario extremely unlikely:
    // Liquid does not have re-orgs beyond possibly the tip so is set to 2 blocks.
    // BTC mainnet is set to one day (144 blocks), more than 2x the largest ever (53 block) re-org seen.
    // BTC testnet/regtest are set to one week (7 * 144 blocks), this allows regtest test runs under
    // a weeks worth of blocks without cache deletion, and for testnet still allows cache finalization
    // testing while being unnaffected by normal chain operation.
    uint32_t network_parameters::get_max_reorg_blocks() const { return m_details.at("max_reorg_blocks"); }
    std::optional<uint32_t> network_parameters::get_min_fee_rate() const { return j_uint32(m_details, "min_fee_rate"); }
    std::string network_parameters::get_price_url() const
    {
        return get_url(m_details, "price_url", "price_onion_url", use_tor());
    }

} // namespace green
