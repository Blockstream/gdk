#include "signer.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static wally_ext_key_ptr derive(const wally_ext_key_ptr& hdkey, uint32_span_t path)
        {
            // FIXME: Private keys should be derived into mlocked memory
            return bip32_key_from_parent_path_alloc(hdkey, path, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH);
        }

        static nlohmann::json get_hw_device_json(const nlohmann::json& hw_device)
        {
            GDK_RUNTIME_ASSERT(!hw_device.empty());

            // FIXME: Remove key rename when the wallets are upgraded to use "supports_ae_protocol"
            nlohmann::json ret = hw_device;
            json_rename_key(ret, "ae_protocol_support_level", "supports_ae_protocol");
            const bool overwrite_null = true;
            json_add_if_missing(ret, "supports_low_r", false, overwrite_null);
            json_add_if_missing(ret, "supports_arbitrary_scripts", false, overwrite_null);
            json_add_if_missing(ret, "supports_liquid", liquid_support_level::none, overwrite_null);
            json_add_if_missing(ret, "supports_ae_protocol", ae_protocol_support_level::none, overwrite_null);
            return ret;
        }

        static const nlohmann::json SOFTWARE_DEVICE_JSON{ { "supports_low_r", true },
            { "supports_arbitrary_scripts", true }, { "supports_liquid", liquid_support_level::lite },
            { "supports_ae_protocol", ae_protocol_support_level::none } };
    } // namespace

    const std::array<uint32_t, 1> signer::LOGIN_PATH{ { 0x4741b11e } };
    const std::array<uint32_t, 1> signer::CLIENT_SECRET_PATH{ { harden(0x70617373) } }; // 'pass'
    const std::array<unsigned char, 8> signer::PASSWORD_SALT = {
        { 0x70, 0x61, 0x73, 0x73, 0x73, 0x61, 0x6c, 0x74 } // 'passsalt'
    };
    const std::array<unsigned char, 8> signer::BLOB_SALT = {
        { 0x62, 0x6c, 0x6f, 0x62, 0x73, 0x61, 0x6c, 0x74 } // 'blobsalt'
    };

    signer::signer(const network_parameters& net_params)
        : m_is_main_net(net_params.is_main_net())
        , m_is_liquid(net_params.is_liquid())
        , m_btc_version(net_params.btc_version())
    {
    }

    signer::~signer() = default;

    std::string signer::get_mnemonic(const std::string& password)
    {
        (void)password;
        return std::string(); // Not available
    }

    bool signer::supports_low_r() const
    {
        return false; // assume not unless overridden
    }

    bool signer::supports_arbitrary_scripts() const
    {
        return false; // assume not unless overridden
    }

    liquid_support_level signer::get_liquid_support() const
    {
        return liquid_support_level::none; // assume none unless overridden
    }

    ae_protocol_support_level signer::get_ae_protocol_support() const
    {
        return ae_protocol_support_level::none; // assume not unless overridden
    }

    bool signer::is_hw_device() const { return false; }

    nlohmann::json signer::get_hw_device() const
    {
        return nlohmann::json::object(); // No HW device unless we are a HW signer
    }

    priv_key_t signer::get_blinding_key_from_script(byte_span_t script)
    {
        (void)script;
        GDK_RUNTIME_ASSERT(false);
        return priv_key_t();
    }

    std::vector<unsigned char> signer::get_blinding_pubkey_from_script(byte_span_t script)
    {
        return ec_public_key_from_private_key(get_blinding_key_from_script(script));
    }

    //
    // Watch-only signer
    //
    watch_only_signer::watch_only_signer(const network_parameters& net_params)
        : signer(net_params)
    {
    }

    watch_only_signer::~watch_only_signer() = default;

    // Watch-only can only sign sweep txs, which are low r
    bool watch_only_signer::supports_low_r() const { return true; }
    bool watch_only_signer::supports_arbitrary_scripts() const { return true; }

    liquid_support_level watch_only_signer::get_liquid_support() const
    {
        return liquid_support_level::none;
    } // we don't support Liquid in watch-only

    ae_protocol_support_level watch_only_signer::get_ae_protocol_support() const
    {
        return ae_protocol_support_level::none;
    } // we don't support ae-protocol in watch-only

    std::string watch_only_signer::get_challenge()
    {
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    xpub_t watch_only_signer::get_xpub(uint32_span_t path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return xpub_t();
    }

    std::string watch_only_signer::get_bip32_xpub(uint32_span_t path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    ecdsa_sig_t watch_only_signer::sign_hash(uint32_span_t path, byte_span_t hash)
    {
        (void)path;
        (void)hash;
        GDK_RUNTIME_ASSERT(false);
        return ecdsa_sig_t();
    }

    //
    // Hardware signer
    //
    hardware_signer::hardware_signer(const network_parameters& net_params, const nlohmann::json& hw_device)
        : signer(net_params)
        , m_hw_device(get_hw_device_json(hw_device))
    {
    }

    hardware_signer::~hardware_signer() = default;

    bool hardware_signer::supports_low_r() const
    {
        if (get_ae_protocol_support() != ae_protocol_support_level::none) {
            return false; // Always use AE if the HW supports it
        }
        return m_hw_device["supports_low_r"];
    }

    bool hardware_signer::supports_arbitrary_scripts() const { return m_hw_device["supports_arbitrary_scripts"]; }

    liquid_support_level hardware_signer::get_liquid_support() const { return m_hw_device["supports_liquid"]; }

    ae_protocol_support_level hardware_signer::get_ae_protocol_support() const
    {
        return m_hw_device["supports_ae_protocol"];
    }

    bool hardware_signer::is_hw_device() const { return true; }

    nlohmann::json hardware_signer::get_hw_device() const { return m_hw_device; }

    std::string hardware_signer::get_challenge()
    {
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    xpub_t hardware_signer::get_xpub(uint32_span_t path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return xpub_t();
    }

    std::string hardware_signer::get_bip32_xpub(uint32_span_t path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    ecdsa_sig_t hardware_signer::sign_hash(uint32_span_t path, byte_span_t hash)
    {
        (void)path;
        (void)hash;
        GDK_RUNTIME_ASSERT(false);
        return ecdsa_sig_t();
    }

    priv_key_t hardware_signer::get_blinding_key_from_script(byte_span_t script)
    {
        (void)script;
        GDK_RUNTIME_ASSERT(false);
        return priv_key_t();
    }

    //
    // Software signer
    //
    software_signer::software_signer(const network_parameters& net_params, const std::string& mnemonic_or_xpub)
        : hardware_signer(net_params, SOFTWARE_DEVICE_JSON)
    {
        // FIXME: Allocate m_master_key in mlocked memory
        if (mnemonic_or_xpub.find(' ') != std::string::npos) {
            // mnemonic
            // FIXME: secure_array
            m_mnemonic = mnemonic_or_xpub;
            const auto seed = bip39_mnemonic_to_seed(mnemonic_or_xpub);
            const uint32_t version = m_is_main_net ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (m_is_liquid) {
                m_master_blinding_key = asset_blinding_key_from_seed(seed);
            }
        } else if (mnemonic_or_xpub.size() == 129 && mnemonic_or_xpub[128] == 'X') {
            // hex seed (a 512 bits bip32 seed encoding in hex with 'X' appended)
            // FIXME: Some previously supported HWs do not have bip39 support.
            // Entering the hex seed in the recover phase should provide access
            // to the wallet. A better approach could be to separate the bip32
            // seed derivation from 'mnemonic to seed' derivation, which should
            // facilitate non-bip39 mnemonic future integration. For these
            // reasons this is a temporary solution.
            const auto seed = h2b(mnemonic_or_xpub.substr(0, 128));
            const uint32_t version = m_is_main_net ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (m_is_liquid) {
                m_master_blinding_key = asset_blinding_key_from_seed(seed);
            }
        } else {
            // xpub
            m_master_key = bip32_public_key_from_bip32_xpub(mnemonic_or_xpub);
        }
    }

    software_signer::~software_signer()
    {
        if (m_master_blinding_key) {
            wally_bzero(m_master_blinding_key->data(), m_master_blinding_key->size());
        }
    }

    std::string software_signer::get_mnemonic(const std::string& password)
    {
        if (m_mnemonic.empty()) {
            return std::string(); // Not available
        }
        return password.empty() ? m_mnemonic : encrypt_mnemonic(m_mnemonic, password);
    }

    bool software_signer::supports_low_r() const { return true; }
    bool software_signer::supports_arbitrary_scripts() const { return true; }
    liquid_support_level software_signer::get_liquid_support() const { return liquid_support_level::lite; }
    ae_protocol_support_level software_signer::get_ae_protocol_support() const
    {
        return ae_protocol_support_level::none;
    }

    nlohmann::json software_signer::get_hw_device() const
    {
        return nlohmann::json::object(); // No HW device unless we are a HW signer
    }

    std::string software_signer::get_challenge()
    {
        std::array<unsigned char, 1 + sizeof(m_master_key->hash160)> vpkh;
        vpkh[0] = m_btc_version;
        std::copy(std::begin(m_master_key->hash160), std::end(m_master_key->hash160), vpkh.data() + 1);
        return base58check_from_bytes(vpkh);
    }

    xpub_t software_signer::get_xpub(uint32_span_t path)
    {
        wally_ext_key_ptr derived;
        ext_key* hdkey = m_master_key.get();
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        }
        return make_xpub(hdkey);
    }

    std::string software_signer::get_bip32_xpub(uint32_span_t path)
    {
        wally_ext_key_ptr derived;
        ext_key* hdkey = m_master_key.get();
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        }
        return base58check_from_bytes(bip32_key_serialize(*hdkey, BIP32_FLAG_KEY_PUBLIC));
    }

    ecdsa_sig_t software_signer::sign_hash(uint32_span_t path, byte_span_t hash)
    {
        wally_ext_key_ptr derived = derive(m_master_key, path);
        return ec_sig_from_bytes(gsl::make_span(derived->priv_key).subspan(1), hash);
    }

    priv_key_t software_signer::get_blinding_key_from_script(byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(m_master_blinding_key.has_value());
        return asset_blinding_key_to_ec_private_key(*m_master_blinding_key, script);
    }

} // namespace sdk
} // namespace ga
