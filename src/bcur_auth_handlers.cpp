#include "bcur_auth_handlers.hpp"

#include "assertion.hpp"
#include "exception.hpp"
#include "json_utils.hpp"
#include "wally_crypto.h"

#include <iterator>
#include <nlohmann/json.hpp>
#include <string>
#ifdef USE_REAL_BCUR
#include "ga_wally.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "wally_crypto.h"
#include <bc-ur/bc-ur.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <gsl/span>
extern "C" {
#include <urc/crypto_account.h>
#include <urc/crypto_eckey.h>
#include <urc/crypto_hdkey.h>
#include <urc/crypto_output.h>
#include <urc/crypto_psbt.h>
#include <urc/error.h>
#include <urc/jade_bip8539.h>
}
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
    namespace {
        // FIXME: this whole set of functions inside this anonymous namespace should be moved to ur-c library

        static std::string format(const crypto_eckey& key)
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

        static std::string format(const crypto_hdkey& key)
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
            return keyorigin + base58check_from_bytes(bip32) + derivationpath;
        }

        static std::string format(const crypto_output& output)
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
                descriptor += "cosigner(";
                descriptor_end += ")";
                break;
            case output_keyexp::keyexp_type_na:
                throw user_error("output_keyexp not available");
            }
            switch (output.output.key.keytype) {
            case output_keyexp::keyexp_keytype_eckey:
                return descriptor + format(output.output.key.key.eckey) + descriptor_end;
                break;
            case output_keyexp::keyexp_keytype_hdkey:
                return descriptor + format(output.output.key.key.hdkey) + descriptor_end;
                break;
            case output_keyexp::keyexp_keytype_na:
                throw user_error("output_keyexp not available");
            }
            GDK_RUNTIME_ASSERT(false);
            __builtin_unreachable();
        }

        static std::string parsepsbt(const std::vector<uint8_t>& raw)
        {
            crypto_psbt psbt;
            int result = URC_OK;
            size_t buffer_size = raw.size();
            std::vector<uint8_t> psbt_bytes;
            do {
                buffer_size *= 2;
                psbt_bytes.resize(buffer_size);
                psbt.buffer = psbt_bytes.data();
                psbt.buffer_size = psbt_bytes.size();
                result = urc_crypto_psbt_parse(raw.data(), raw.size(), &psbt);
            } while (result == URC_EBUFFERTOOSMALL);
            if (result != URC_OK) {
                throw user_error("ur-c: Parsing crypto_psbt failed with error code:" + std::to_string(result));
            }
            return base64_from_bytes({ psbt.buffer, psbt.psbt_len });
        }

        static std::string parseoutput(const std::vector<uint8_t>& raw)
        {
            crypto_output output;
            int result = urc_crypto_output_parse(raw.data(), raw.size(), &output);
            if (result != URC_OK) {
                throw user_error("ur-c: Parsing crypto-output failed with error code:" + std::to_string(result));
            }
            return format(output);
        }

        static crypto_account parseaccount(const std::vector<uint8_t>& raw)
        {
            crypto_account account;
            auto&& ca_parse_fn = urc_crypto_account_parse;
            auto&& ja_parse_fn = urc_jade_account_parse;
            int result = URC_OK;
            for (const auto& parse_fn : { ca_parse_fn, ja_parse_fn }) {
                result = parse_fn(raw.data(), raw.size(), &account);
                if (result == URC_OK) {
                    return account;
                }
            }
            throw user_error("ur-c: Parsing account failed with error code:" + std::to_string(result));
        }

        static nlohmann::json parse_jaderesponse(
            const std::vector<uint8_t>& raw, const std::optional<std::string>& private_key)
        {
            jade_bip8539_response response;
            std::vector<uint8_t> buffer;
            buffer.resize(512);
            int result = URC_OK;
            do {
                buffer.resize(buffer.size() * 2);
                result
                    = urc_jade_bip8539_response_parse(raw.data(), raw.size(), &response, buffer.data(), buffer.size());
            } while (result == URC_EBUFFERTOOSMALL);
            if (result != URC_OK) {
                throw user_error("internal ur-c error, error_code: " + std::to_string(result));
            }
            if (!private_key) {
                return {
                    { "public_key", b2h({ response.pubkey, EC_PUBLIC_KEY_LEN }) },
                    { "encrypted", b2h({ response.encripted_data, response.encrypted_len }) },
                };
            }
            std::vector<uint8_t> privkey = h2b(private_key.value());
            GDK_RUNTIME_ASSERT(privkey.size() == EC_PRIVATE_KEY_LEN);
            std::string salt_str = "bip85_bip39_entropy";
            gsl::span<uint8_t> salt(reinterpret_cast<uint8_t*>(salt_str.data()), salt_str.size());

            size_t buffer_required_len = 0;
            int wally_error = wally_aes_cbc_with_ecdh_key_get_maximum_length(privkey.data(), privkey.size(), nullptr, 0,
                response.encripted_data, response.encrypted_len, response.pubkey, EC_PUBLIC_KEY_LEN, salt.data(),
                salt.size(), AES_FLAG_DECRYPT, &buffer_required_len);
            if (wally_error != WALLY_OK) {
                throw user_error(
                    "internal wally error on parse_jaderesponse, error_code: " + std::to_string(wally_error));
            }

            std::vector<uint8_t> jade_entropy;
            jade_entropy.resize(buffer_required_len);
            size_t buffer_written_len = 0;
            wally_error = wally_aes_cbc_with_ecdh_key(privkey.data(), privkey.size(), nullptr, 0,
                response.encripted_data, response.encrypted_len, response.pubkey, EC_PUBLIC_KEY_LEN, salt.data(),
                salt.size(), AES_FLAG_DECRYPT, jade_entropy.data(), jade_entropy.size(), &buffer_written_len);
            if (wally_error != WALLY_OK) {
                throw user_error(
                    "internal wally error on parse_jaderesponse, error_code: " + std::to_string(wally_error));
            }
            jade_entropy.resize(buffer_written_len);
            auto mnemonic = bip39_mnemonic_from_bytes(jade_entropy);
            return {
                { "entropy", b2h(jade_entropy) },
                { "mnemonic", std::move(mnemonic) },
            };
        }

        struct json_jaderequest {
            std::string ur_type;
            uint32_t num_words;
            uint32_t index;
            std::string private_key;
        };
        bool from_json(const nlohmann::json& input, json_jaderequest& jrequest)
        {
            try {
                jrequest.ur_type = j_strref(input, "ur_type");
                jrequest.num_words = j_uint32ref(input, "num_words");
                jrequest.index = j_uint32ref(input, "index");
                jrequest.private_key = j_strref(input, "private_key");
            } catch (const user_error&) {
                return false;
            }
            return true;
        }
        // NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(json_jaderequest, ur_type, num_words, index, private_key);

        static ur::UR prepare_jaderequest_ur(const json_jaderequest& jrequest)
        {
            GDK_RUNTIME_ASSERT(boost::algorithm::to_lower_copy(jrequest.ur_type) == "jade-bip8539-request");
            auto private_key = h2b(jrequest.private_key);
            auto public_key = ec_public_key_from_private_key({ private_key });

            jade_bip8539_request request;
            request.num_words = jrequest.num_words;
            request.index = jrequest.index;
            memcpy(request.pubkey, public_key.data(), public_key.size());

            std::vector<uint8_t> out;
            out.resize(512);
            int result = URC_OK;
            size_t len = 0;
            do {
                out.resize(out.size() * 2);
                len = out.size();
                result = urc_jade_bip8539_request_format(&request, out.data(), &len);
            } while (result == URC_EBUFFERTOOSMALL);
            if (result != URC_OK) {
                throw user_error("internal ur-c error, error_code: " + std::to_string(result));
            }
            out.resize(len);
            return ur::UR(jrequest.ur_type, std::move(out));
        }

        static ur::UR prepare_generic_ur(const nlohmann::json& input)
        {
            const auto& ur_type = j_strref(input, "ur_type");
            auto cbor = h2b(j_strref(input, "data"));
            return { ur_type, std::move(cbor) };
        }
    } // namespace

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
            const auto max_fragment_len = j_uint32ref(m_details, "max_fragment_len");
            json_jaderequest jrequest;
            if (from_json(m_details, jrequest)) {
                ur::UR ur = prepare_jaderequest_ur(m_details);
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
            m_decoder->receive_part(j_strref(m_details, "part"));
        } else {
            GDK_RUNTIME_ASSERT(m_action == "data");
            m_decoder->receive_part(m_code);
        }

        if (m_decoder->is_failure()) {
            throw user_error("Decoding failed");
        }

        if (!m_decoder->is_complete() || !m_decoder->is_success()) {
            signal_data_request();
            m_auth_data = { { "received_indices", m_decoder->received_part_indexes() } };
            return m_state;
        }

        const auto& ur = m_decoder->result_ur();
        m_result = { { "ur_type", ur.type() } };

        const auto urtype = boost::algorithm::to_lower_copy(ur.type());
        if (urtype == "crypto-psbt") {
            m_result["psbt"] = parsepsbt(ur.cbor());
        } else if (urtype == "crypto-output") {
            m_result["descriptor"] = parseoutput(ur.cbor());
        } else if (urtype == "crypto-account") {
            crypto_account account = parseaccount(ur.cbor());
            m_result["master_fingerprint"] = (boost::format("%08x") % account.master_fingerprint).str();
            for (size_t idx = 0; idx < account.descriptors_count; idx++) {
                m_result["descriptors"].push_back(format(account.descriptors[idx]));
            }
        } else if (urtype == "jade-bip8539-reply") {
            auto response = parse_jaderesponse(ur.cbor(), j_str(m_details, "private_key"));
            m_result.update(response);
        } else {
            // bytes or an unknown type - return the raw CBOR
            m_result["data"] = b2h(ur.cbor());
        }
        return state_type::done;
#endif
    }

} // namespace sdk
} // namespace ga
