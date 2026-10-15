#include "src/ga_wally.hpp"
#include "src/network_parameters.hpp"
#include "src/session.hpp"
#include "src/transaction_utils.hpp"
#include "src/xpub_hdkey.hpp"
#include <iostream>
#include <nlohmann/json.hpp>

// Verify the multisig subaccount descriptors describe the same scripts that
// the Green script generation produces for the same keys and pointers.

using namespace green;

namespace {
    constexpr size_t MAX_SCRIPT_LEN = 520; // Enough for any script described here
    constexpr uint32_t SUBACCOUNT = 1;

    size_t failures = 0;

    // Test user and recovery subaccount xpubs, per network
    const std::string USER_XPUB_TEST("tpubD6NzVbkrYhZ4XVPn5tSFsjZbYcAnoDizTifqiqFEU18GcLzJMMPeYkBL1tkPT94oxPpu"
                                     "aWeTrMnCoXqFcAwRUn83HeM9SSwZyeAg3J62ssn");
    const std::string RECOVERY_XPUB_TEST("tpubD6NzVbkrYhZ4X1Sw55pnA5AGTv3zokw5Fdy7Ltaga4pGskYYhLmG8Fu29nPofWCXe"
                                         "UjFKqax63ka7GyStmyGwmt9Tbwp8msCqnY1KnNpCkU");
    std::string USER_XPUB_MAIN;
    std::string RECOVERY_XPUB_MAIN;

    // Return the scriptpubkey a descriptor produces for the given child number
    std::vector<unsigned char> descriptor_scriptpubkey(
        const network_parameters& net_params, const std::string& descriptor, uint32_t child_num)
    {
        const uint32_t network
            = net_params.is_main_net() ? WALLY_NETWORK_BITCOIN_MAINNET : WALLY_NETWORK_BITCOIN_TESTNET;
        struct wally_descriptor* d;
        GDK_VERIFY(wally_descriptor_parse(descriptor.c_str(), nullptr, network, 0, &d));
        std::unique_ptr<struct wally_descriptor> parsed{ d };
        std::vector<unsigned char> script(MAX_SCRIPT_LEN);
        size_t written;
        GDK_VERIFY(
            wally_descriptor_to_script(parsed.get(), 0, 0, 0, 0, child_num, 0, script.data(), script.size(), &written));
        GDK_RUNTIME_ASSERT(written && written <= script.size());
        script.resize(written);
        return script;
    }

    // Wrap a Green multisig script in its p2sh scriptpubkey, as addresses are generated
    std::vector<unsigned char> wrap_script(const std::string& addr_type, const std::vector<unsigned char>& script)
    {
        if (addr_type == address_type::p2sh) {
            return scriptpubkey_p2sh_from_hash160(hash160(script));
        }
        return scriptpubkey_p2sh_from_hash160(hash160(witness_script(script, WALLY_SCRIPT_SHA256)));
    }

    void check_network(
        const std::string& network_name, const std::string& user_xpub, const std::string& recovery_xpub, bool is_2of3)
    {
        const network_parameters net_params(network_parameters::get(network_name));
        const std::string sa_type = is_2of3 ? "2of3" : "2of2";

        // Build the key collections the signing code uses, so that the expected
        // scripts come from gdk itself rather than from this test
        const std::array<uint32_t, 32> gait_path{ { 0 } }; // Any path, both sides use the same one
        green_pubkeys service_keys(net_params, gait_path);
        green_user_pubkeys user_keys(net_params);
        green_recovery_pubkeys recovery_keys(net_params);
        user_keys.add_subaccount(SUBACCOUNT, user_xpub);
        if (is_2of3) {
            recovery_keys.add_subaccount(SUBACCOUNT, recovery_xpub);
        }

        const auto descriptors
            = get_multisig_descriptors(net_params, sa_type, service_keys.get_subaccount(SUBACCOUNT).to_base58(),
                user_keys.get_subaccount(SUBACCOUNT).to_base58(), {}, {}, is_2of3 ? recovery_xpub : std::string());

        const auto csv_buckets = net_params.csv_buckets();
        const size_t expected = is_2of3 ? 2 : 2 + csv_buckets.size();
        GDK_RUNTIME_ASSERT(descriptors.size() == expected);

        for (uint32_t pointer = 0; pointer < 3; ++pointer) {
            for (size_t i = 0; i < descriptors.size(); ++i) {
                std::string addr_type;
                uint32_t subtype = 0;
                if (i == 0) {
                    addr_type = address_type::p2wsh;
                } else if (i == 1) {
                    addr_type = address_type::p2sh;
                } else {
                    addr_type = address_type::csv;
                    subtype = csv_buckets.at(i - 2);
                }
                const nlohmann::json utxo = { { "subaccount", SUBACCOUNT }, { "pointer", pointer },
                    { "address_type", addr_type }, { "subtype", subtype } };
                const auto green_script
                    = multisig_output_script_from_utxo(net_params, service_keys, user_keys, recovery_keys, utxo);
                const auto expected_script = wrap_script(addr_type, green_script);
                const auto script = descriptor_scriptpubkey(net_params, descriptors.at(i), pointer);
                if (script != expected_script) {
                    std::cerr << network_name << " " << sa_type << " " << addr_type << " pointer " << pointer
                              << ": descriptor does not match the Green script" << std::endl;
                    std::cerr << "  " << descriptors.at(i) << std::endl;
                    ++failures;
                }
            }
        }
    }

    // Derive a mainnet test xpub from a testnet one, so both networks are covered
    std::string to_main_net(const std::string& bip32_xpub)
    {
        const xpub_hdkey key(bip32_xpub);
        return xpub_hdkey(true, key.get_public_key(), key.get_chain_code()).to_base58();
    }
} // namespace

int main()
{
    nlohmann::json init_config;
    init_config["datadir"] = ".";
    gdk_init(init_config);

    USER_XPUB_MAIN = to_main_net(USER_XPUB_TEST);
    RECOVERY_XPUB_MAIN = to_main_net(RECOVERY_XPUB_TEST);

    for (const bool is_2of3 : { false, true }) {
        check_network("testnet", USER_XPUB_TEST, RECOVERY_XPUB_TEST, is_2of3);
        check_network("mainnet", USER_XPUB_MAIN, RECOVERY_XPUB_MAIN, is_2of3);
    }

    const network_parameters net_params(network_parameters::get("testnet"));
    const std::array<uint32_t, 32> gait_path{ { 0 } };
    green_pubkeys service_keys(net_params, gait_path);
    green_user_pubkeys user_keys(net_params);
    user_keys.add_subaccount(SUBACCOUNT, USER_XPUB_TEST);
    const auto service_xpub = service_keys.get_subaccount(SUBACCOUNT).to_base58();
    const auto user_xpub = user_keys.get_subaccount(SUBACCOUNT).to_base58();

    // The key origin is included when a fingerprint is given
    const std::vector<unsigned char> fingerprint{ 0xa1, 0xb2, 0xc3, 0xd4 };
    const std::vector<uint32_t> user_path{ harden(3), harden(SUBACCOUNT), 1 };
    auto descriptors
        = get_multisig_descriptors(net_params, "2of2", service_xpub, user_xpub, fingerprint, user_path, std::string());
    if (descriptors.at(0).find("[a1b2c3d4/3'/1'/1]" + user_xpub + "/*") == std::string::npos) {
        std::cerr << "missing or malformed key origin: " << descriptors.at(0) << std::endl;
        ++failures;
    }

    // The main account has an empty path, so the origin is the fingerprint alone
    descriptors = get_multisig_descriptors(net_params, "2of2", service_xpub, user_xpub, fingerprint, {}, std::string());
    if (descriptors.at(0).find("[a1b2c3d4]" + user_xpub + "/*") == std::string::npos) {
        std::cerr << "missing or malformed main account key origin: " << descriptors.at(0) << std::endl;
        ++failures;
    }

    // A subaccount whose type and keys disagree is not described at all
    if (!get_multisig_descriptors(net_params, "2of3", service_xpub, user_xpub, {}, {}, std::string()).empty()) {
        std::cerr << "a 2of3 without a recovery key must not be described" << std::endl;
        ++failures;
    }
    if (!get_multisig_descriptors(net_params, "2of2", service_xpub, user_xpub, {}, {}, RECOVERY_XPUB_TEST).empty()) {
        std::cerr << "a 2of2 with a recovery key must not be described" << std::endl;
        ++failures;
    }
    if (!get_multisig_descriptors(net_params, "2of2_no_recovery", service_xpub, user_xpub, {}, {}, std::string())
            .empty()) {
        std::cerr << "only 2of2 and 2of3 subaccounts can be described" << std::endl;
        ++failures;
    }

    return failures ? 1 : 0;
}
