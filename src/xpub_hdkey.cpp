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

    std::vector<uint32_t> xpub_hdkeys::get_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal) const
    {
        auto path = get_path_to_subaccount(subaccount);
        auto post = get_path_from_subaccount(subaccount, pointer, is_internal);
        path.insert(path.end(), post.begin(), post.end());
        return path;
    }

    green_pubkeys::green_pubkeys(const network_parameters& net_params, uint32_span_t gait_path)
        : xpub_hdkeys(net_params)
        , m_master_xpub(m_is_main_net, h2b(net_params.pub_key()), h2b(net_params.chain_code()))
    {
        GDK_RUNTIME_ASSERT(static_cast<size_t>(gait_path.size()) == m_gait_path.size());
        std::copy(std::begin(gait_path), std::end(gait_path), m_gait_path.begin());
        get_subaccount(0); // Initialize main account
    }

    std::vector<uint32_t> green_pubkeys::get_path_to_subaccount(uint32_t subaccount) const
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

    std::vector<uint32_t> green_pubkeys::get_path_from_subaccount(
        uint32_t /*subaccount*/, uint32_t pointer, bool /*is_internal*/) const
    {
        return { pointer };
    }

    xpub_hdkey green_pubkeys::get_subaccount(uint32_t subaccount)
    {
        // Note unlike user pubkeys, the Green key is not privately derived,
        // since the user must be able to derive it from the Green service xpub.
        const auto p = m_subaccounts.find(subaccount);
        if (p != m_subaccounts.end()) {
            return p->second;
        }
        const auto path = get_path_to_subaccount(subaccount);
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

    std::vector<uint32_t> green_user_pubkeys::get_path_to_subaccount(uint32_t subaccount) const
    {
        if (subaccount != 0u) {
            return { harden(3), harden(subaccount) };
        }
        return {};
    }

    std::vector<uint32_t> green_user_pubkeys::get_path_from_subaccount(
        uint32_t /*subaccount*/, uint32_t pointer, bool /*is_internal*/) const
    {
        return { 1, pointer };
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

    std::vector<uint32_t> bip44_pubkeys::get_path_to_subaccount(uint32_t subaccount) const
    {
        const std::array<uint32_t, 3> purpose_lookup{ 49, 84, 44 };
        const uint32_t purpose = purpose_lookup.at(subaccount % 16);
        const uint32_t coin_type = m_is_main_net ? (m_is_liquid ? 1776 : 0) : 1;
        const uint32_t account = subaccount / 16;
        return std::vector<uint32_t>{ harden(purpose), harden(coin_type), harden(account) };
    }

    std::vector<uint32_t> bip44_pubkeys::get_path_from_subaccount(
        uint32_t /*subaccount*/, uint32_t pointer, bool is_internal) const
    {
        return { is_internal ? 1u : 0u, pointer };
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
