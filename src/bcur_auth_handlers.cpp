#include "bcur_auth_handlers.hpp"

#include "assertion.hpp"
#include "exception.hpp"

#include <nlohmann/json.hpp>
#include <string>
#ifdef USE_REAL_BCUR
#include "ga_wally.hpp"
#include "json_utils.hpp"
#include "logging.hpp"

#include <bc-ur/bc-ur.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <gsl/span>
#include <urc/urc.h>
#else
namespace ur {
    class UREncoder {
    };
    class URDecoder {
    };
} // namespace ur
#endif

namespace green {

#ifdef USE_REAL_BCUR
    namespace {

        using urc_string_ptr = std::unique_ptr<char, decltype(&urc_string_free)>;
        using urc_buffer_ptr = std::unique_ptr<uint8_t, decltype(&urc_free)>;
        using urc_psbt_ptr = std::unique_ptr<crypto_psbt, decltype(&urc_crypto_psbt_free)>;
        using urc_string_array_ptr = std::unique_ptr<char*[], decltype(&urc_string_array_free)>;
        using urc_jade_bip8539_response_ptr
            = std::unique_ptr<jade_bip8539_response, decltype(&urc_jade_bip8539_response_free)>;

        static nlohmann::json deserialize_psbt(const std::vector<uint8_t>& cbor)
        {
            crypto_psbt psbt;
            urc_psbt_ptr holder(&psbt, urc_crypto_psbt_free);
            int result = urc_crypto_psbt_deserialize(cbor.data(), cbor.size(), &psbt);
            if (result != URC_OK) {
                throw user_error("ur-c: Parsing crypto_psbt failed with error code:" + std::to_string(result));
            }
            return { { "psbt", base64_from_bytes({ psbt.psbt, psbt.psbt_len }) } };
        }

        static nlohmann::json deserialize_output(const std::vector<uint8_t>& raw)
        {
            crypto_output output;
            int result = urc_crypto_output_deserialize(raw.data(), raw.size(), &output);
            GDK_RUNTIME_ASSERT_MSG(
                result == URC_OK, "ur-c: Parsing crypto-output failed with error code:" + std::to_string(result));
            char* formatted_output = nullptr;
            urc_string_ptr holder(formatted_output, urc_string_free);
            // Add missing "[0;1]/*" derivation elements to BIP44 paths
            const auto mode = urc_crypto_output_format_mode_BIP44_compatible;
            result = urc_crypto_output_format(&output, mode, &formatted_output);
            GDK_RUNTIME_ASSERT_MSG(
                result == URC_OK, "ur-c: crypto-output format failed with error code:" + std::to_string(result));
            return { { "descriptor", formatted_output } };
        }

        static nlohmann::json deserialize_account(const std::vector<uint8_t>& raw)
        {
            crypto_account account;
            int result = urc_crypto_account_deserialize(raw.data(), raw.size(), &account);
            if (result != URC_OK) {
                result = urc_jade_account_deserialize(raw.data(), raw.size(), &account);
                GDK_RUNTIME_ASSERT_MSG(
                    result == URC_OK, "ur-c: Parsing account failed with error code:" + std::to_string(result));
            }

            char** formatted_descriptors = nullptr;
            urc_string_array_ptr holder(formatted_descriptors, urc_string_array_free);
            result = urc_crypto_account_format(
                &account, urc_crypto_output_format_mode_BIP44_compatible, &formatted_descriptors);
            nlohmann::json::array_t descriptors;
            size_t i = 0;
            while (formatted_descriptors[i] != nullptr) {
                descriptors.push_back(formatted_descriptors[i++]);
            }
            auto fingerprint = (boost::format("%08x") % account.master_fingerprint).str();
            return { { "master_fingerprint", fingerprint }, { "descriptors", std::move(descriptors) } };
        }

        static nlohmann::json deserialize_jaderesponse(
            const std::vector<uint8_t>& raw, const std::optional<std::string>& private_key)
        {
            jade_bip8539_response response;
            urc_jade_bip8539_response_ptr holder(&response, urc_jade_bip8539_response_free);
            int result = urc_jade_bip8539_response_deserialize(raw.data(), raw.size(), &response);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            if (!private_key) {
                nlohmann::json retv = {
                    { "public_key", b2h({ response.pubkey, EC_PUBLIC_KEY_LEN }) },
                    { "encrypted", b2h({ response.encrypted_data, response.encrypted_len }) },
                };
                return retv;
            }
            std::vector<uint8_t> privkey = h2b(private_key.value());
            GDK_RUNTIME_ASSERT(privkey.size() == EC_PRIVATE_KEY_LEN);
            std::string salt_str = "bip85_bip39_entropy";
            gsl::span<uint8_t> salt(reinterpret_cast<uint8_t*>(salt_str.data()), salt_str.size());

            size_t buffer_required_len = 0;
            int wally_error = wally_aes_cbc_with_ecdh_key_get_maximum_length(privkey.data(), privkey.size(), nullptr, 0,
                response.encrypted_data, response.encrypted_len, response.pubkey, EC_PUBLIC_KEY_LEN, salt.data(),
                salt.size(), AES_FLAG_DECRYPT, &buffer_required_len);

            if (wally_error != WALLY_OK) {
                throw user_error(
                    "internal wally error on parse_jaderesponse, error_code: " + std::to_string(wally_error));
            }

            std::vector<uint8_t> jade_entropy;
            jade_entropy.resize(buffer_required_len);
            size_t buffer_written_len = 0;
            wally_error = wally_aes_cbc_with_ecdh_key(privkey.data(), privkey.size(), nullptr, 0,
                response.encrypted_data, response.encrypted_len, response.pubkey, EC_PUBLIC_KEY_LEN, salt.data(),
                salt.size(), AES_FLAG_DECRYPT, jade_entropy.data(), jade_entropy.size(), &buffer_written_len);
            GDK_RUNTIME_ASSERT_MSG(wally_error == WALLY_OK,
                "internal wally error on parse_jaderesponse, error_code: " + std::to_string(wally_error));
            jade_entropy.resize(buffer_written_len);
            auto mnemonic = bip39_mnemonic_from_bytes(jade_entropy);
            return {
                { "entropy", b2h(jade_entropy) },
                { "mnemonic", std::move(mnemonic) },
            };
        }

        nlohmann::json deserialize_jaderpc(const green::byte_span_t raw)
        {
            char* raw_json = nullptr;
            urc_string_ptr holder(raw_json, urc_string_free);
            int result = urc_jade_rpc_deserialize(raw.data(), raw.size(), &raw_json);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            return json_parse(raw_json);
        }

        struct json_jaderequest {
            uint32_t num_words;
            uint32_t index;
            std::string private_key;
        };
        bool from_json(const nlohmann::json& input, json_jaderequest& jrequest)
        {
            try {
                jrequest.num_words = j_uint32ref(input, "num_words");
                jrequest.index = j_uint32ref(input, "index");
                jrequest.private_key = j_strref(input, "private_key");
            } catch (const user_error&) {
                return false;
            }
            return true;
        }
        // NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(json_jaderequest, num_words, index, private_key);

        static ur::UR prepare_jaderequest_ur(const json_jaderequest& jrequest)
        {
            auto private_key = h2b(jrequest.private_key);
            auto public_key = ec_public_key_from_private_key({ private_key });

            jade_bip8539_request request;
            request.num_words = jrequest.num_words;
            request.index = jrequest.index;
            memcpy(request.pubkey, public_key.data(), public_key.size());

            uint8_t* buffer = nullptr;
            size_t buffer_len = 0;
            urc_buffer_ptr holder(buffer, urc_free);
            int result = urc_jade_bip8539_request_serialize(&request, &buffer, &buffer_len);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            ur::UR ur("jade-bip8539-request", { buffer, buffer + buffer_len });
            return ur;
        }

        static ur::UR prepare_psbt_ur(const std::string& base64_psbt)
        {
            std::vector<uint8_t> raw = base64_to_bytes(base64_psbt);
            const crypto_psbt psbt{ raw.data(), raw.size() };
            uint8_t* cbor = nullptr;
            size_t cbor_len = 0;
            urc_buffer_ptr holder(cbor, urc_free);
            int result = urc_crypto_psbt_serialize(&psbt, &cbor, &cbor_len);
            if (result != URC_OK) {
                throw user_error("ur-c: Serializing crypto_psbt failed with error code:" + std::to_string(result));
            }
            return { "crypto-psbt", { cbor, cbor + cbor_len } };
        }

        static ur::UR prepare_generic_ur(const nlohmann::json& input)
        {
            return { j_strref(input, "ur_type"), j_bytesref(input, "data") };
        }
    } // namespace
#endif

    bcur_encoder_call::bcur_encoder_call(session& session, nlohmann::json details)
        : auth_handler_impl(session, "bcur_encode", {})
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
            const auto max_fragment_len = j_uint32ref(m_details, "max_fragment_len");
            const auto& ur_type = j_strref(m_details, "ur_type");
            if (ur_type == "jade-bip8539-request") {
                json_jaderequest jrequest;
                bool ok = from_json(m_details, jrequest);
                GDK_RUNTIME_ASSERT_MSG(ok, "failed to parse jaderequest");
                ur::UR ur = prepare_jaderequest_ur(jrequest);
                m_encoder = std::make_unique<ur::UREncoder>(std::move(ur), max_fragment_len);
            } else if (ur_type == "crypto-psbt" || ur_type == "psbt") {
                ur::UR ur = prepare_psbt_ur(j_strref(m_details, "data"));
                m_encoder = std::make_unique<ur::UREncoder>(std::move(ur), max_fragment_len);
            } else {
                ur::UR ur = prepare_generic_ur(m_details);
                m_encoder = std::make_unique<ur::UREncoder>(std::move(ur), max_fragment_len);
            }
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
        : auth_handler_impl(session, "bcur_decode", {})
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
            bool is_ok = m_decoder->receive_part(j_strref(m_details, "part"));
            if (!is_ok) {
                throw user_error("Invalid part");
            }
        } else {
            GDK_RUNTIME_ASSERT(m_action == "data");
            m_decoder->receive_part(m_code);
        }

        if (m_decoder->is_failure()) {
            throw user_error("Decoding failed");
        }

        if (!m_decoder->is_complete() || !m_decoder->is_success()) {
            signal_data_request();
            const uint32_t progress = std::lround(m_decoder->estimated_percent_complete() * 100.0);
            m_auth_data
                = { { "received_indices", m_decoder->received_part_indexes() }, { "estimated_progress", progress } };
            return m_state;
        }

        bool return_raw_data = j_bool_or_false(m_details, "return_raw_data");
        const auto& ur = m_decoder->result_ur();
        auto ur_type = boost::algorithm::to_lower_copy(ur.type());

        if (ur_type == "crypto-psbt" || ur_type == "psbt") {
            m_result = deserialize_psbt(ur.cbor());
        } else if (ur_type == "crypto-output") {
            m_result = deserialize_output(ur.cbor());
        } else if (ur_type == "crypto-account") {
            m_result = deserialize_account(ur.cbor());
        } else if (ur_type == "jade-bip8539-reply") {
            m_result = deserialize_jaderesponse(ur.cbor(), j_str(m_details, "private_key"));
        } else if (ur_type == "jade-pin") {
            m_result["result"] = deserialize_jaderpc(ur.cbor());
        } else {
            return_raw_data = true; // bytes or an unknown type, return raw
        }
        if (return_raw_data) {
            m_result["data"] = b2h(ur.cbor());
        }
        m_result["ur_type"] = std::move(ur_type);
        return state_type::done;
#endif
    }

} // namespace green
