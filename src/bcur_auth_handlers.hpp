#ifndef GDK_BCUR_AUTH_HANDLERS_HPP
#define GDK_BCUR_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"

namespace ur {
class UREncoder;
class URDecoder;
} // namespace ur

namespace ga {
namespace sdk {
    class bcur_encoder_call : public auth_handler_impl {
    public:
        explicit bcur_encoder_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        std::unique_ptr<ur::UREncoder> m_encoder;
    };

    class bcur_decoder_call : public auth_handler_impl {
    public:
        explicit bcur_decoder_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        std::unique_ptr<ur::URDecoder> m_decoder;
    };
} // namespace sdk
} // namespace ga
#endif
