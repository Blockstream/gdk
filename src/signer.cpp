#include "signer.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static wally_ext_key_ptr derive(const wally_ext_key_ptr& hdkey, gsl::span<const uint32_t> path)
        {
            // FIXME: Private keys should be derived into mlocked memory
            return bip32_key_from_parent_path_alloc(hdkey, path, BIP32_FLAG_KEY_PRIVATE | BIP32_FLAG_SKIP_HASH);
        }
    } // namespace

    signer::signer(const network_parameters& net_params)
        : m_net_params(net_params)
    {
    }

    signer::~signer() = default;

    bool signer::supports_low_r() const
    {
        return false; // assume not unless overridden
    }

    bool signer::supports_arbitrary_scripts() const
    {
        return false; // assume not unless overridden
    }

    nlohmann::json signer::get_hw_device() const
    {
        return nlohmann::json(); // No HW device unless we are a HW signer
    }

    priv_key_t signer::get_blinding_key_from_script(__attribute__((unused)) byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    priv_key_t signer::derive_master_blinding_key(__attribute__((unused)) byte_span_t seed)
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    std::vector<unsigned char> signer::get_public_key_from_blinding_key(byte_span_t script)
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
    bool watch_only_signer::supports_arbitrary_scripts() const { return true; };

    std::string watch_only_signer::get_challenge()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    xpub_t watch_only_signer::get_xpub(gsl::span<const uint32_t> path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    std::string watch_only_signer::get_bip32_xpub(gsl::span<const uint32_t> path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    ecdsa_sig_t watch_only_signer::sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash)
    {
        (void)path;
        (void)hash;
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    //
    // Software signer
    //
    software_signer::software_signer(const network_parameters& net_params, const std::string& mnemonic_or_xpub)
        : signer(net_params)
    {
        // FIXME: Allocate m_master_key in mlocked memory
        if (mnemonic_or_xpub.find(' ') != std::string::npos) {
            // mnemonic
            // FIXME: secure_array
            const auto seed = bip39_mnemonic_to_seed(mnemonic_or_xpub);
            const uint32_t version = m_net_params.main_net() ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (net_params.liquid()) {
                m_master_blinding_key = derive_master_blinding_key(seed);
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
            const uint32_t version = m_net_params.main_net() ? BIP32_VER_MAIN_PRIVATE : BIP32_VER_TEST_PRIVATE;
            m_master_key = bip32_key_from_seed_alloc(seed, version, 0);
            if (net_params.liquid()) {
                m_master_blinding_key = derive_master_blinding_key(seed);
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

    bool software_signer::supports_low_r() const { return true; }
    bool software_signer::supports_arbitrary_scripts() const { return true; };

    std::string software_signer::get_challenge()
    {
        std::array<unsigned char, 1 + sizeof(m_master_key->hash160)> vpkh;
        vpkh[0] = m_net_params.btc_version();
        std::copy(std::begin(m_master_key->hash160), std::end(m_master_key->hash160), vpkh.data() + 1);
        return base58check_from_bytes(vpkh);
    }

    xpub_t software_signer::get_xpub(gsl::span<const uint32_t> path)
    {
        wally_ext_key_ptr derived;
        ext_key* hdkey = m_master_key.get();
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = derived.get();
        }
        return make_xpub(hdkey);
    }

    std::string software_signer::get_bip32_xpub(gsl::span<const uint32_t> path)
    {
        wally_ext_key_ptr derived;
        wally_ext_key_ptr* hdkey = &m_master_key;
        if (!path.empty()) {
            derived = derive(m_master_key, path);
            hdkey = &derived;
        }
        return base58check_from_bytes(bip32_key_serialize(*hdkey, BIP32_FLAG_KEY_PUBLIC));
    }

    ecdsa_sig_t software_signer::sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash)
    {
        wally_ext_key_ptr derived = derive(m_master_key, path);
        return ec_sig_from_bytes(gsl::make_span(derived->priv_key).subspan(1), hash);
    }

    priv_key_t software_signer::get_blinding_key_from_script(byte_span_t script)
    {
        GDK_RUNTIME_ASSERT(m_master_blinding_key.has_value());
        const auto blinding_key = hmac_sha256(gsl::make_span(m_master_blinding_key.get()), script);
        GDK_RUNTIME_ASSERT(ec_private_key_verify(blinding_key));
        return blinding_key;
    }

    priv_key_t software_signer::derive_master_blinding_key(byte_span_t seed)
    {
        GDK_RUNTIME_ASSERT(m_net_params.liquid());

        const std::string domain_str{ "Symmetric key seed" };
        const auto domain = ustring_span(domain_str);
        auto root = hmac_sha512(domain, seed);

        const std::string label_str{ "SLIP-0077" };
        const auto label_str_span = ustring_span(label_str);
        std::vector<unsigned char> label(1 + label_str.size());
        std::copy(std::begin(label_str_span), std::end(label_str_span), std::begin(label) + 1);
        label[0] = 0x0;
        auto node = hmac_sha512(gsl::make_span(root).first(EC_PRIVATE_KEY_LEN), label);

        auto cleanup = gsl::finally([&] {
            wally_bzero(root.data(), root.size());
            wally_bzero(node.data(), node.size());
        });

        priv_key_t master_blinding_key;
        std::copy(std::begin(node) + EC_PRIVATE_KEY_LEN, std::end(node), std::begin(master_blinding_key));
        GDK_RUNTIME_ASSERT(ec_private_key_verify(master_blinding_key));

        return master_blinding_key;
    }

    //
    // Hardware signer
    //
    hardware_signer::hardware_signer(const network_parameters& net_params, const nlohmann::json& hw_device)
        : signer(net_params)
        , m_hw_device(hw_device)
    {
    }

    hardware_signer::~hardware_signer() = default;

    bool hardware_signer::supports_low_r() const { return json_get_value(m_hw_device, "supports_low_r", false); }
    bool hardware_signer::supports_arbitrary_scripts() const
    {
        return json_get_value(m_hw_device, "supports_arbitrary_scripts", false);
    }

    nlohmann::json hardware_signer::get_hw_device() const { return m_hw_device; }

    std::string hardware_signer::get_challenge()
    {
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    xpub_t hardware_signer::get_xpub(gsl::span<const uint32_t> path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return xpub_t();
    }

    std::string hardware_signer::get_bip32_xpub(gsl::span<const uint32_t> path)
    {
        (void)path;
        GDK_RUNTIME_ASSERT(false);
        return std::string();
    }

    ecdsa_sig_t hardware_signer::sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash)
    {
        (void)path;
        (void)hash;
        GDK_RUNTIME_ASSERT(false);
        return ecdsa_sig_t();
    }

} // namespace sdk
} // namespace ga
