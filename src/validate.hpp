#ifndef GDK_VALIDATE_HPP
#define GDK_VALIDATE_HPP
#pragma once

#include "auth_handler.hpp"
#include "ga_wally.hpp"

namespace ga {
namespace sdk {
    class validate_call : public auth_handler_impl {
    public:
        validate_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        bool is_addressees() const;
        void addressees_impl();

        bool is_liquidex() const; // in swap_auth_handlers.cpp
        void liquidex_impl(); // in swap_auth_handlers.cpp

        nlohmann::json m_details;
    };
} // namespace sdk
} // namespace ga
#endif // GDK_VALIDATE_HPP
