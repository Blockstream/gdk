#include "bcur_auth_handlers.hpp"
#include "assertion.hpp"
#include "exception.hpp"

#include <string>
#ifdef USE_REAL_BCUR
#include "ga_wally.hpp"
#include <bc-ur/bc-ur.hpp>
#else
namespace ur {
class UREncoder {
};
class URDecoder {
};
} // namespace ur
#endif
namespace ga {
namespace sdk {

    bcur_encoder_call::bcur_encoder_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "bcur_encode", std::shared_ptr<signer>())
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type bcur_encoder_call::call_impl()
    {
#ifndef USE_REAL_BCUR
        throw user_error("not available");
        return state_type::error;
#else
        if (!m_encoder) {
            std::string ur_type = m_details.at("ur_type");
            auto cbor = h2b(m_details.at("data"));
            const auto max_fragment_len = m_details.at("max_fragment_len");
            auto ur = ur::UR(std::move(ur_type), std::move(cbor));
            m_encoder = std::make_unique<ur::UREncoder>(std::move(ur), max_fragment_len);
        }
        nlohmann::json::array_t parts;
        const size_t num_parts = m_encoder->seq_len() == 1 ? 1 : 3 * m_encoder->seq_len();
        parts.reserve(num_parts);
        auto& encoder = this->m_encoder;
        std::generate_n(std::back_inserter(parts), num_parts, [&]() { return encoder->next_part(); });
        m_result = { { "parts", std::move(parts) } };
        return state_type::done;
#endif
    }

    bcur_decoder_call::bcur_decoder_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "bcur_decode", std::shared_ptr<signer>())
        , m_details(std::move(details))
    {
    }

    auth_handler::state_type bcur_decoder_call::call_impl()
    {
#ifndef USE_REAL_BCUR
        throw user_error("not available");
        return state_type::error;
#else
        if (!m_decoder) {
            m_decoder = std::make_unique<ur::URDecoder>();
            m_decoder->receive_part(m_details.at("part"));
        } else {
            GDK_RUNTIME_ASSERT(m_action == "data");
            m_decoder->receive_part(m_code);
        }

        if (m_decoder->is_failure()) {
            throw user_error("Decoding failed");
        }

        if (m_decoder->is_complete() && m_decoder->is_success()) {
            const auto& ur = m_decoder->result_ur();
            m_result = { { "ur_type", ur.type() }, { "data", b2h(ur.cbor()) } };
            return state_type::done;
        }

        signal_data_request();
        m_auth_data = { { "received_indices", m_decoder->received_part_indexes() } };
        return m_state;
#endif
    }

} // namespace sdk
} // namespace ga
