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
        // FIXME: this whole set of functions inside this anonymous namespace should be moved to ur-c library

        static std::string format_eckey(const crypto_eckey& key)
        {
            switch (key.type) {
            case crypto_eckey::eckey_type_private:
                return b2h(key.key.prvate);
            case crypto_eckey::eckey_type_public_compressed:
                return b2h(key.key.public_compressed);
            case crypto_eckey::eckey_type_public_uncompressed:
                return b2h(key.key.public_uncompressed);
            default:
                throw user_error("unhandled eckey type");
            }
        }

        static std::string format_hdkey(const crypto_hdkey& key, bool is_bip44 = false)
        {
            std::string keyorigin;
            keyorigin.resize(15);
            int len = static_cast<int>(keyorigin.size());
            while (len >= static_cast<int>(keyorigin.size())) {
                keyorigin.resize(keyorigin.size() * 2);
                len = format_keyorigin(&key, keyorigin.data(), keyorigin.size());
                if (len < 0) {
                    throw user_error("crypto_hdkey not available");
                }
            }
            keyorigin.resize(len);

            std::array<uint8_t, BIP32_SERIALIZED_LEN> bip32 = { 0 }; // Initialize to prevent clang-tidy warning
            if (!bip32_serialize(&key, bip32.data())) {
                throw user_error("hdkey2bip32 failure");
            }
            std::string derivationpath;
            derivationpath.resize(5);
            len = static_cast<int>(derivationpath.size());
            while (len >= static_cast<int>(derivationpath.size())) {
                derivationpath.resize(derivationpath.capacity() * 2);
                len = format_keyderivationpath(&key, derivationpath.data(), derivationpath.capacity());
                if (len < 0) {
                    throw user_error("crypto_hdkey not available");
                }
            }

            derivationpath.resize(len);
            if (is_bip44 && derivationpath.empty()) {
                /* HD Keys inside crypto-account do not include the
                 * derivation path, but are only allowed to be bip44
                 * compatible. Append the bip44 derivation so
                 * callers can use the resulting descriptor.
                 * TODO: The correct path is "/<0;1>/<star>", but wallets
                 * that do not understand multi-index descriptors require
                 * "/0/<star>" and must infer the change addresses themselves.
                 */
                derivationpath = "/0/*";
            }
            return keyorigin + base58check_from_bytes(bip32) + derivationpath;
        }

        static std::string format_output(const crypto_output& output, bool is_bip44 = false)
        {
            std::string descriptor;
            std::string descriptor_end;
            switch (output.type) {
            case crypto_output::output_type__:
                break;
            case crypto_output::output_type_sh:
                descriptor = "sh(";
                descriptor_end = ")";
                break;
            case crypto_output::output_type_wsh:
                descriptor += "wsh(";
                descriptor_end += ")";
                break;
            case crypto_output::output_type_sh_wsh:
                descriptor += "sh(wsh(";
                descriptor_end += "))";
                break;
            case crypto_output::output_type_rawscript:
                return "raw(" + b2h(output.output.raw) + ")";
            default:
                throw user_error("crypto_output not available");
            }
            switch (output.output.key.type) {
            case output_keyexp::keyexp_type_pk:
                descriptor += "pk(";
                descriptor_end += ")";
                break;
            case output_keyexp::keyexp_type_pkh:
                descriptor += "pkh(";
                descriptor_end += ")";
                break;
            case output_keyexp::keyexp_type_wpkh:
                descriptor += "wpkh(";
                descriptor_end += ")";
                break;
            case output_keyexp::keyexp_type_cosigner:
                /* NOTE: cosigner() is just made-up nonsense, no software will
                 *       decode it and no BIP has ever been proposed for it.
                 */
                descriptor += "cosigner(";
                descriptor_end += ")";
                break;
            case output_keyexp::keyexp_type_na:
                throw user_error("output_keyexp not available");
            }
            const auto& key = output.output.key;
            switch (key.keytype) {
            case output_keyexp::keyexp_keytype_eckey:
                /* EC Keys cannot appear in 'crypto-account's so no bip44
                 * path needs to be appended.
                 */
                return descriptor + format_eckey(key.key.eckey) + descriptor_end;
                break;
            case output_keyexp::keyexp_keytype_hdkey:
                return descriptor + format_hdkey(key.key.hdkey, is_bip44) + descriptor_end;
                break;
            case output_keyexp::keyexp_keytype_na:
                throw user_error("output_keyexp not available");
            }
            GDK_RUNTIME_ASSERT(false);
            __builtin_unreachable();
        }

        static nlohmann::json deserialize_psbt(const std::vector<uint8_t>& cbor)
        {
            crypto_psbt psbt;
            std::unique_ptr<crypto_psbt, decltype(&urc_crypto_psbt_free)> holder(&psbt, urc_crypto_psbt_free);
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
            return { { "descriptor", format_output(output) } };
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
            nlohmann::json::array_t descriptors;
            for (size_t i = 0; i < account.descriptors_count; i++) {
                constexpr bool is_bip44 = true;
                descriptors.push_back(format_output(account.descriptors[i], is_bip44));
            }
            auto fingerprint = (boost::format("%08x") % account.master_fingerprint).str();
            return { { "master_fingerprint", fingerprint }, { "descriptors", std::move(descriptors) } };
        }

        static nlohmann::json deserialize_jaderesponse(
            const std::vector<uint8_t>& raw, const std::optional<std::string>& private_key)
        {
            jade_bip8539_response response;
            int result = urc_jade_bip8539_response_deserialize(raw.data(), raw.size(), &response);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            if (!private_key) {
                nlohmann::json retv = {
                    { "public_key", b2h({ response.pubkey, EC_PUBLIC_KEY_LEN }) },
                    { "encrypted", b2h({ response.encrypted_data, response.encrypted_len }) },
                };
                urc_jade_bip8539_response_free(&response);
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
                urc_jade_bip8539_response_free(&response);
                throw user_error(
                    "internal wally error on parse_jaderesponse, error_code: " + std::to_string(wally_error));
            }

            std::vector<uint8_t> jade_entropy;
            jade_entropy.resize(buffer_required_len);
            size_t buffer_written_len = 0;
            wally_error = wally_aes_cbc_with_ecdh_key(privkey.data(), privkey.size(), nullptr, 0,
                response.encrypted_data, response.encrypted_len, response.pubkey, EC_PUBLIC_KEY_LEN, salt.data(),
                salt.size(), AES_FLAG_DECRYPT, jade_entropy.data(), jade_entropy.size(), &buffer_written_len);
            urc_jade_bip8539_response_free(&response);
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
            int result = urc_jade_rpc_deserialize(raw.data(), raw.size(), &raw_json);
            std::unique_ptr<char, decltype(&urc_string_free)> holder(raw_json, urc_string_free);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            std::string_view json_str(raw_json);
            auto retv = nlohmann::json::parse(json_str);
            return retv;
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
            int result = urc_jade_bip8539_request_serialize(&request, &buffer, &buffer_len);
            std::unique_ptr<uint8_t, decltype(&urc_free)> holder(buffer, urc_free);
            GDK_RUNTIME_ASSERT_MSG(result == URC_OK, "internal ur-c error, error_code: " + std::to_string(result));
            ur::UR ur("jade-bip8539-request", { buffer, buffer + buffer_len });
            return ur;
        }

        static ur::UR prepare_psbt_ur(const std::string& base64_psbt)
        {
            std::vector<uint8_t> raw = base64_to_bytes(base64_psbt);
            const crypto_psbt psbt{ raw.data(), raw.size() };
            uint8_t* cbor = nullptr;
            std::unique_ptr<uint8_t, decltype(&urc_free)> hojder(cbor, urc_free);
            size_t cbor_len = 0;
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
