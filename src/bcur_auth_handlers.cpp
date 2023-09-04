#include "bcur_auth_handlers.hpp"
#include "assertion.hpp"
#include "exception.hpp"

#include <string>
#ifdef USE_REAL_BCUR
#include "ga_wally.hpp"
#include "logging.hpp"
#include <bc-ur/bc-ur.hpp>
#include <boost/algorithm/string.hpp>
#include <gsl/span>
extern "C" {
#include <urc/crypto_account.h>
#include <urc/crypto_eckey.h>
#include <urc/crypto_hdkey.h>
#include <urc/crypto_output.h>
#include <urc/crypto_psbt.h>
#include <urc/error.h>
}
#else
namespace ur {
class UREncoder {
};
class URDecoder {
};
} // namespace ur
#endif

namespace {
// FIXME: this whole set of functions inside this anonymous namespace should be moved to ur-c library

static std::string format(const crypto_eckey& key)
{
    switch (key.type) {
    case crypto_eckey::eckey_type_private:
        return ga::sdk::b2h(key.key.prvate);
    case crypto_eckey::eckey_type_public_compressed:
        return ga::sdk::b2h(key.key.public_compressed);
    case crypto_eckey::eckey_type_public_uncompressed:
        return ga::sdk::b2h(key.key.public_uncompressed);
    default:
        throw ga::sdk::user_error("unhandled eckey type");
    }
}

static std::string format(const crypto_hdkey& key)
{
    std::string keyorigin;
    keyorigin.resize(15);
    int len = static_cast<int>(keyorigin.size());
    while (len >= static_cast<int>(keyorigin.size())) {
        keyorigin.resize(keyorigin.capacity() * 2);
        len = format_keyorigin(&key, keyorigin.capacity(), keyorigin.data());
        if (len < 0) {
            throw ga::sdk::user_error("crypto_hdkey not available");
        }
    }
    keyorigin.resize(len);

    uint8_t bip32[BIP32_SERIALIZED_LEN];
    if (!bip32_serialize(&key, bip32)) {
        throw ga::sdk::user_error("hdkey2bip32 failure");
    }
    std::string derivationpath;
    derivationpath.resize(5);
    len = static_cast<int>(derivationpath.size());
    while (len >= static_cast<int>(derivationpath.size())) {
        derivationpath.resize(derivationpath.capacity() * 2);
        len = format_keyderivationpath(&key, derivationpath.capacity(), derivationpath.data());
        if (len < 0) {
            throw ga::sdk::user_error("crypto_hdkey not available");
        }
    }

    derivationpath.resize(len);
    return keyorigin + ga::sdk::base58check_from_bytes(bip32) + derivationpath;
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
        return "raw(" + ga::sdk::b2h(output.output.raw) + ")";
    default:
        throw ga::sdk::user_error("crypto_output not available");
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
        throw ga::sdk::user_error("output_keyexp not available");
    }
    switch (output.output.key.keytype) {
    case output_keyexp::keyexp_keytype_eckey:
        return descriptor + format(output.output.key.key.eckey) + descriptor_end;
        break;
    case output_keyexp::keyexp_keytype_hdkey:
        return descriptor + format(output.output.key.key.hdkey) + descriptor_end;
        break;
    case output_keyexp::keyexp_keytype_na:
        throw ga::sdk::user_error("output_keyexp not available");
    }
    GDK_RUNTIME_ASSERT(false);
    __builtin_unreachable();
}

static std::string parsepsbt(const std::vector<uint8_t>& raw)
{
    crypto_psbt psbt;
    urc_error result;
    size_t buffer_size = raw.size();
    std::vector<uint8_t> psbt_bytes;
    do {
        buffer_size *= 2;
        psbt_bytes.resize(buffer_size);
        psbt.buffer = psbt_bytes.data();
        psbt.buffer_size = psbt_bytes.size();
        result = parse_psbt(raw.size(), raw.data(), &psbt);
    } while (result.tag == urc_error_tag_wrongstringlength);
    // urc_error result;
    if (result.tag != urc_error_tag_noerror) {
        throw ga::sdk::user_error("ur-c: Parsing crypto_psbt failed with error tag:" + std::to_string(result.tag));
    }
    return ga::sdk::base64_from_bytes(gsl::span<uint8_t>(psbt.buffer, psbt.psbt_len));
}

static std::string parseoutput(const std::vector<uint8_t>& raw)
{
    crypto_output output;
    urc_error result = parse_output(raw.size(), raw.data(), &output);
    if (result.tag != urc_error_tag_noerror) {
        throw ga::sdk::user_error("ur-c: Parsing crypto-output failed with error tag:" + std::to_string(result.tag));
    }
    return format(output);
}

static crypto_account parseaccount(const std::vector<uint8_t>& raw)
{
    crypto_account account;
    urc_error result = parse_account(raw.size(), raw.data(), &account);
    if (result.tag == urc_error_tag_noerror) {
        return account;
    }
    if (result.tag == urc_error_tag_taprootnotsupported) {
        GDK_LOG_SEV(ga::sdk::log_level::warning)
            << "crypto_account contains a taproot descriptor, which is not supported";
        return account;
    }
    result = parse_jadeaccount(raw.size(), raw.data(), &account);
    if (result.tag == urc_error_tag_noerror) {
        return account;
    }
    if (result.tag == urc_error_tag_taprootnotsupported) {
        GDK_LOG_SEV(ga::sdk::log_level::warning)
            << "crypto_account contains a taproot descriptor, which is not supported";
        return account;
    }
    throw ga::sdk::user_error("ur-c: Parsing crypto-account failed with error tag:" + std::to_string(result.tag));
}
} // namespace
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
            m_result["master_fingerprint"] = account.master_fingerprint;
            for (size_t idx = 0; idx < account.descriptors_count; idx++) {
                m_result["descriptors"].push_back(format(account.descriptors[idx]));
            }
        } else {
            // bytes or an unknown type - return the raw CBOR
            m_result["data"] = b2h(ur.cbor());
        }
        return state_type::done;
#endif
    }

} // namespace sdk
} // namespace ga
