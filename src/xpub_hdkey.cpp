#include <cstring>

#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace green {

    namespace {
        static const unsigned char GAIT_GENERATION_NONCE[30] = { 'G', 'r', 'e', 'e', 'n', 'A', 'd', 'd', 'r', 'e', 's',
            's', '.', 'i', 't', ' ', 'H', 'D', ' ', 'w', 'a', 'l', 'l', 'e', 't', ' ', 'p', 'a', 't', 'h' };
    } // namespace

    xpub_hdkey::xpub_hdkey(const std::string& xpub)
        : m_ext_key(*bip32_public_key_from_bip32_xpub(xpub))
    {
    }

    xpub_hdkey::xpub_hdkey(bool is_main_net, byte_span_t public_key, byte_span_t chain_code)
    {
        std::array<unsigned char, WALLY_BIP32_CHAIN_CODE_LEN> empty;
        if (chain_code.empty()) {
            empty.fill(0);
            chain_code = empty; // Wally requires the chain code, pass it as zeros
        }
        GDK_VERIFY(wally_ec_public_key_verify(public_key.data(), public_key.size()));
        const uint32_t version = is_main_net ? BIP32_VER_MAIN_PUBLIC : BIP32_VER_TEST_PUBLIC;
        m_ext_key = *bip32_key_init_alloc(version, 0, 0, chain_code, public_key);
    }

    xpub_hdkey::~xpub_hdkey() { wally_bzero(&m_ext_key, sizeof(m_ext_key)); }

    bool xpub_hdkey::operator==(const xpub_hdkey& rhs) const
    {
        return !memcmp(m_ext_key.pub_key, rhs.m_ext_key.pub_key, sizeof(m_ext_key.pub_key))
            && !memcmp(m_ext_key.chain_code, rhs.m_ext_key.chain_code, sizeof(m_ext_key.chain_code));
    }

    xpub_hdkey xpub_hdkey::derive(uint32_span_t path) const
    {
        if (path.empty()) {
            return *this;
        }
        return xpub_hdkey(bip32_public_key_from_parent_path(m_ext_key, path));
    }

    pub_key_t xpub_hdkey::get_public_key() const
    {
        pub_key_t ret;
        std::copy(m_ext_key.pub_key, m_ext_key.pub_key + ret.size(), ret.begin());
        return ret;
    }

    chain_code_t xpub_hdkey::get_chain_code() const
    {
        chain_code_t ret;
        std::copy(m_ext_key.chain_code, m_ext_key.chain_code + ret.size(), ret.begin());
        return ret;
    }

    std::vector<unsigned char> xpub_hdkey::get_fingerprint() const
    {
        auto copy = m_ext_key;
        return bip32_key_get_fingerprint(copy);
    }

    std::string xpub_hdkey::to_base58() const { return bip32_key_to_base58(&m_ext_key, BIP32_FLAG_KEY_PUBLIC); }

    std::string xpub_hdkey::to_hashed_identifier(const std::string& network) const
    {
        // Return a hashed id from which the xpub cannot be extracted
        const auto key_data = bip32_key_serialize(m_ext_key, BIP32_FLAG_KEY_PUBLIC);
        const auto hashed = pbkdf2_hmac_sha512_256(key_data, ustring_span(network));
        return b2h(hashed);
    }

    xpub_hdkeys::xpub_hdkeys(const network_parameters& net_params)
        : m_is_main_net(net_params.is_main_net())
        , m_is_liquid(net_params.is_liquid())
    {
    }

    void xpub_hdkeys::clear() { m_subaccounts.clear(); }

    xpub_hdkey xpub_hdkeys::derive(uint32_t subaccount, uint32_t pointer, std::optional<bool> is_internal)
    {
        std::vector<uint32_t> path;
        if (is_internal.has_value()) {
            path.push_back(*is_internal ? 1u : 0u);
        }
        path.push_back(pointer);
        return get_subaccount(subaccount).derive(path);
    }

    green_pubkeys::green_pubkeys(const network_parameters& net_params, uint32_span_t gait_path)
        : xpub_hdkeys(net_params)
        , m_master_xpub(m_is_main_net, h2b(net_params.pub_key()), h2b(net_params.chain_code()))
    {
        GDK_RUNTIME_ASSERT(static_cast<size_t>(gait_path.size()) == m_gait_path.size());
        std::copy(std::begin(gait_path), std::end(gait_path), m_gait_path.begin());
        get_subaccount(0); // Initialize main account
    }

    std::vector<uint32_t> green_pubkeys::get_subaccount_root_path(uint32_t subaccount) const
    {
        // Note: This assumes address version v1+.
        // Version 0 addresses are not derived from the users gait_path
        const uint32_t path_prefix = subaccount != 0 ? 3 : 1;
        std::vector<uint32_t> path(m_gait_path.size() + 1);
        init_container(path, gsl::make_span(&path_prefix, 1), m_gait_path);
        if (subaccount != 0) {
            path.push_back(subaccount);
        }
        return path;
    }

    std::vector<uint32_t> green_pubkeys::get_subaccount_full_path(
        uint32_t subaccount, uint32_t pointer, bool /*is_internal*/) const
    {
        auto path = get_subaccount_root_path(subaccount);
        path.push_back(pointer);
        return path;
    }

    xpub_hdkey green_pubkeys::get_subaccount(uint32_t subaccount)
    {
        // Note unlike user pubkeys, the Green key is not privately derived,
        // since the user must be able to derive it from the Green service xpub.
        const auto p = m_subaccounts.find(subaccount);
        if (p != m_subaccounts.end()) {
            return p->second;
        }
        const auto path = get_subaccount_root_path(subaccount);
        return m_subaccounts.emplace(subaccount, m_master_xpub.derive(path)).first->second;
    }

    std::array<unsigned char, HMAC_SHA512_LEN> green_pubkeys::get_gait_path_bytes(const xpub_hdkey& gait_key)
    {
        std::array<unsigned char, sizeof(chain_code_t) + sizeof(pub_key_t)> path_data;
        init_container(path_data, gait_key.get_chain_code(), gait_key.get_public_key());
        return hmac_sha512(GAIT_GENERATION_NONCE, path_data);
    }

    green_user_pubkeys::green_user_pubkeys(const network_parameters& net_params)
        : user_pubkeys(net_params)
    {
    }

    std::vector<uint32_t> green_user_pubkeys::get_subaccount_root_path(uint32_t subaccount) const
    {
        if (subaccount != 0u) {
            return std::vector<uint32_t>({ harden(3), harden(subaccount) });
        }
        return std::vector<uint32_t>();
    }

    std::vector<uint32_t> green_user_pubkeys::get_subaccount_full_path(
        uint32_t subaccount, uint32_t pointer, bool /*is_internal*/) const
    {
        if (subaccount != 0u) {
            return std::vector<uint32_t>({ harden(3), harden(subaccount), 1, pointer });
        }
        return std::vector<uint32_t>({ 1, pointer });
    }

    bool green_user_pubkeys::have_subaccount(uint32_t subaccount)
    {
        return m_subaccounts.find(subaccount) != m_subaccounts.end();
    }

    void green_user_pubkeys::add_subaccount(uint32_t subaccount, const std::string& bip32_xpub)
    {
        std::array<uint32_t, 1> path{ { 1 } };
        auto user_key = xpub_hdkey(bip32_xpub).derive(path);
        const auto ret = m_subaccounts.emplace(subaccount, user_key);
        if (!ret.second) {
            // Subaccount is already present; xpub must match whats already there
            GDK_RUNTIME_ASSERT(ret.first->second == user_key);
        }
    }

    void green_user_pubkeys::remove_subaccount(uint32_t subaccount)
    {
        // Removing subaccounts is not supported for Green multisig wallets
        (void)subaccount;
        GDK_RUNTIME_ASSERT(false);
    }

    xpub_hdkey green_user_pubkeys::get_subaccount(uint32_t subaccount)
    {
        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT(p != m_subaccounts.end());
        return p->second;
    }

    bip44_pubkeys::bip44_pubkeys(const network_parameters& net_params)
        : user_pubkeys(net_params)
    {
    }

    std::vector<uint32_t> bip44_pubkeys::get_subaccount_root_path(uint32_t subaccount) const
    {
        const std::array<uint32_t, 3> purpose_lookup{ 49, 84, 44 };
        const uint32_t purpose = purpose_lookup.at(subaccount % 16);
        const uint32_t coin_type = m_is_main_net ? (m_is_liquid ? 1776 : 0) : 1;
        const uint32_t account = subaccount / 16;
        return std::vector<uint32_t>{ harden(purpose), harden(coin_type), harden(account) };
    }

    std::vector<uint32_t> bip44_pubkeys::get_subaccount_full_path(
        uint32_t subaccount, uint32_t pointer, bool is_internal) const
    {
        auto path = get_subaccount_root_path(subaccount);
        path.emplace_back(is_internal ? 1 : 0);
        path.emplace_back(pointer);
        return path;
    }

    bool bip44_pubkeys::have_subaccount(uint32_t subaccount)
    {
        return m_subaccounts.find(subaccount) != m_subaccounts.end();
    }

    void bip44_pubkeys::add_subaccount(uint32_t subaccount, const std::string& bip32_xpub)
    {
        xpub_hdkey user_key(bip32_xpub);
        const auto ret = m_subaccounts.emplace(subaccount, user_key);
        if (!ret.second) {
            // Subaccount is already present; xpub must match whats already there
            GDK_RUNTIME_ASSERT(ret.first->second == user_key);
        }
    }

    void bip44_pubkeys::remove_subaccount(uint32_t subaccount)
    {
        // Removing subaccounts is not supported
        (void)subaccount;
        GDK_RUNTIME_ASSERT(false);
    }

    xpub_hdkey bip44_pubkeys::get_subaccount(uint32_t subaccount)
    {
        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT(p != m_subaccounts.end());
        return p->second;
    }

} // namespace green
