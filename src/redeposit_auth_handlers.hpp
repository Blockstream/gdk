#ifndef GDK_REDEPOSIT_AUTH_HANDLERS_HPP
#define GDK_REDEPOSIT_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"

namespace green {

    struct redeposit_data;

    class create_redeposit_transaction_call : public auth_handler_impl {
    public:
        create_redeposit_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void on_next_handler_complete(auth_handler* next_handler) override;

        std::unique_ptr<redeposit_data> m_details;
    };
} // namespace green
#endif // GDK_REDEPOSIT_AUTH_HANDLERS_HPP
