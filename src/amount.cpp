#include <cctype>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"

#include "amount.hpp"
#include "assertion.hpp"

namespace ga {
namespace sdk {
    // BTC amounts have 8 DP
    using btc_type = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<8>>;
    // Fiat amounts are decimal values with 2 DP
    using fiat_type = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<2>>;
    // Internal calculations are done with 15 DP before rounding
    using conversion_type = boost::multiprecision::number<boost::multiprecision::cpp_dec_float<15>>;

    namespace {
        static const conversion_type COIN_VALUE_100("100");
        static const conversion_type COIN_VALUE_DECIMAL("100000000");
        static const conversion_type COIN_VALUE_DECIMAL_MBTC("100000");
        static const conversion_type COIN_VALUE_DECIMAL_UBTC("100");
        static const std::vector<std::string> NON_SATOSHI_KEYS{ "btc", "mbtc", "ubtc", "bits", "fiat", "fiat_currency",
            "fiat_rate" };

        template <typename T> static std::string fmt(const T& fiat, size_t dp = 2)
        {
            return fiat_type(fiat).str(dp, std::ios_base::fixed | std::ios_base::showpoint);
        }
    } // namespace

    // convert to internal representation (from Bitcoin Core)
    amount::amount(const std::string& str_value)
        : m_value(btc_type(conversion_type(str_value) * COIN_VALUE_DECIMAL).convert_to<value_type>())
    {
    }

    amount::amount(const nlohmann::json& json_value)
        : amount(json_value.get<amount::value_type>())
    {
    }

    nlohmann::json amount::convert(
        const nlohmann::json& amount_json, const std::string& fiat_currency, const std::string& fiat_rate)
    {
        const auto satoshi_p = amount_json.find("satoshi");
        const auto btc_p = amount_json.find("btc");
        const auto mbtc_p = amount_json.find("mbtc");
        const auto ubtc_p = amount_json.find("ubtc");
        const auto bits_p = amount_json.find("bits");
        const auto fiat_p = amount_json.find("fiat");
        const auto end_p = amount_json.end();
        const int key_count = (satoshi_p != end_p) + (btc_p != end_p) + (mbtc_p != end_p) + (ubtc_p != end_p)
            + (bits_p != end_p) + (fiat_p != end_p);
        if (key_count != 1) {
            throw user_error(res::id_no_amount_specified);
        }
        GDK_RUNTIME_ASSERT(key_count == 1);

        const std::string fr_str = fiat_rate.empty() ? "0" : fiat_rate;
        const conversion_type fr(fr_str);
        uint64_t satoshi;

        // Compute satoshi from our input
        if (satoshi_p != end_p) {
            satoshi = *satoshi_p;
        } else if (btc_p != end_p) {
            const std::string btc_str = *btc_p;
            satoshi = amount(btc_str).value();
        } else if (mbtc_p != end_p) {
            const std::string mbtc_str = *mbtc_p;
            satoshi = (amount(mbtc_str) / 1000).value();
        } else if (ubtc_p != end_p || bits_p != end_p) {
            const std::string ubtc_str = *(ubtc_p == end_p ? bits_p : ubtc_p);
            satoshi = (amount(ubtc_str) / 1000000).value();
        } else {
            const std::string fiat_str = *fiat_p;
            const conversion_type btc_decimal = conversion_type(fiat_str) / fr;
            satoshi = (btc_type(btc_decimal) * COIN_VALUE_DECIMAL).convert_to<value_type>();
        }

        // Then compute the other denominations and fiat amount
        const conversion_type satoshi_conv = conversion_type(satoshi);
        const std::string btc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL), 8);
        const std::string mbtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_MBTC), 5);
        const std::string ubtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_UBTC), 2);

        const conversion_type fiat_decimal = fr * conversion_type(satoshi) / COIN_VALUE_DECIMAL;

        // TODO: If the server returned the ISO country code, the caller could do locale aware formatting
        return { { "satoshi", satoshi }, { "btc", btc }, { "mbtc", mbtc }, { "ubtc", ubtc }, { "bits", ubtc },
            { "fiat", fmt(fiat_type(fiat_decimal)) }, { "fiat_currency", fiat_currency }, { "fiat_rate", fr_str } };
    }

    void amount::strip_non_satoshi_keys(nlohmann::json& amount_json)
    {
        for (const auto& key : NON_SATOSHI_KEYS) {
            amount_json.erase(key);
        }
    }

    nlohmann::json amount::convert_fiat_cents(
        value_type cents, const std::string& fiat_currency, const std::string& fiat_rate)
    {
        const conversion_type fiat_decimal = conversion_type(cents) / COIN_VALUE_100;
        return convert({ { "fiat", fmt(fiat_type(fiat_decimal)) } }, fiat_currency, fiat_rate);
    }

    amount::value_type amount::get_fiat_cents(const std::string& fiat_str)
    {
        const conversion_type fiat_decimal = conversion_type(fiat_str) * COIN_VALUE_100;
        return floor(fiat_type(fiat_decimal)).convert_to<value_type>();
    }

    std::string amount::format_amount(const std::string& value_str, size_t dp)
    {
        return fmt(conversion_type(value_str), dp);
    }

} // namespace sdk
} // namespace ga
