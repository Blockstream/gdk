#ifndef GDK_REDEPOSIT_AUTH_HANDLERS_HPP
#define GDK_REDEPOSIT_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"
#include <optional>

namespace green {

    class create_redeposit_transaction_call : public auth_handler_impl {
    public:
        create_redeposit_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void on_next_handler_complete(auth_handler* next_handler) override;

        void initialize();
        std::string get_nth_asset_id(size_t n) const;
        void add_fee_utxo(nlohmann::json& to);

        nlohmann::json m_details;
        nlohmann::json::array_t m_fee_utxos;
        std::optional<uint32_t> m_subaccount;
        std::optional<uint32_t> m_fee_subaccount;
    };
} // namespace green
#endif // GDK_REDEPOSIT_AUTH_HANDLERS_HPP
