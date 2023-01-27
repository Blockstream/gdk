#include <cctype>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "wally_wrapper.h"

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
        static constexpr int64_t SATOSHI_MAX = static_cast<int64_t>(WALLY_BTC_MAX) * WALLY_SATOSHI_PER_BTC;
        static const conversion_type COIN_VALUE_100("100");
        static const conversion_type COIN_VALUE_DECIMAL("100000000");
        static const conversion_type COIN_VALUE_DECIMAL_MBTC("100000");
        static const conversion_type COIN_VALUE_DECIMAL_UBTC("100");
        static const std::vector<std::string> NON_SATOSHI_KEYS{ "btc", "mbtc", "ubtc", "bits", "sats", "fiat",
            "fiat_currency", "fiat_rate", "is_current" };

        template <typename T> static std::string fmt(const T& fiat, size_t dp = 2)
        {
            return fiat_type(fiat).str(dp, std::ios_base::fixed | std::ios_base::showpoint);
        }
    } // namespace

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
        const auto sats_p = amount_json.find("sats");
        const auto fiat_p = amount_json.find("fiat");
        const bool have_asset_info = amount_json.contains("asset_info");
        const auto asset_json = amount_json.value("asset_info", nlohmann::json::object());
        const auto precision = asset_json.value("precision", 0);
        const auto asset_id = asset_json.value("asset_id", "");
        const auto asset_p = amount_json.find(asset_id);
        const auto end_p = amount_json.end();
        const int key_count = (satoshi_p != end_p) + (btc_p != end_p) + (mbtc_p != end_p) + (ubtc_p != end_p)
            + (bits_p != end_p) + (sats_p != end_p) + (fiat_p != end_p) + (asset_p != end_p);

        if (key_count != 1) {
            throw user_error(res::id_no_amount_specified);
        }

        // If either the fiat rate or currency is not available, use any provided values
        // from the amount json instead and indicate that the conversion is out of date
        const std::string old_fiat_rate = amount_json.value("fiat_rate", std::string());
        const std::string& fiat_rate_used(fiat_rate.empty() ? old_fiat_rate : fiat_rate);

        const std::string old_fiat_ccy = amount_json.value("fiat_currency", std::string());
        const std::string& fiat_ccy_used(fiat_currency.empty() ? old_fiat_ccy : fiat_currency);

        const bool is_current = !fiat_rate.empty() && !fiat_currency.empty();

        const conversion_type COIN_VALUE_WITH_PRECISION(std::pow(10, precision));
        signed_value_type satoshi;

        // Compute satoshi from our input
        if (satoshi_p != end_p) {
            satoshi = *satoshi_p;
        } else if (btc_p != end_p) {
            const std::string btc_str = *btc_p;
            satoshi = (conversion_type(btc_str) * COIN_VALUE_DECIMAL).convert_to<signed_value_type>();
        } else if (mbtc_p != end_p) {
            const std::string mbtc_str = *mbtc_p;
            satoshi = (conversion_type(mbtc_str) * COIN_VALUE_DECIMAL_MBTC).convert_to<signed_value_type>();
        } else if (ubtc_p != end_p || bits_p != end_p) {
            const std::string ubtc_str = *(ubtc_p == end_p ? bits_p : ubtc_p);
            satoshi = (conversion_type(ubtc_str) * COIN_VALUE_DECIMAL_UBTC).convert_to<signed_value_type>();
        } else if (sats_p != end_p) {
            const std::string sats_str = *sats_p;
            satoshi = (conversion_type(sats_str)).convert_to<signed_value_type>();
        } else if (asset_p != end_p) {
            const std::string asset_str = *asset_p;
            satoshi = (conversion_type(asset_str) * COIN_VALUE_WITH_PRECISION).convert_to<signed_value_type>();
        } else {
            if (fiat_rate_used.empty()) {
                throw user_error(res::id_your_favourite_exchange_rate_is);
            }
            const std::string fiat_str = *fiat_p;
            const conversion_type btc_decimal = conversion_type(fiat_str) / conversion_type(fiat_rate_used);
            satoshi = (btc_type(btc_decimal) * COIN_VALUE_DECIMAL).convert_to<signed_value_type>();
        }

        // Check upper limit for btc type (ie. non-asset) inputs
        // Note: an asset_info block indicating btc denomination would have failed key_count check above
        if (asset_p == end_p && (satoshi > SATOSHI_MAX || satoshi < -SATOSHI_MAX)) {
            throw user_error(res::id_invalid_amount);
        }

        // Then compute the other denominations and fiat amount
        const conversion_type satoshi_conv = conversion_type(satoshi);
        const std::string btc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL), 8);
        const std::string mbtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_MBTC), 5);
        const std::string ubtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_UBTC), 2);
        const std::string sats = std::to_string(satoshi);

        nlohmann::json result = { { "satoshi", satoshi }, { "btc", btc }, { "mbtc", mbtc }, { "ubtc", ubtc },
            { "bits", ubtc }, { "sats", sats }, { "fiat", nullptr }, { "fiat_currency", fiat_ccy_used },
            { "fiat_rate", nullptr }, { "is_current", is_current } };

        if (!fiat_rate_used.empty()) {
            result["fiat_rate"] = fiat_rate_used;
            result["fiat"]
                = fmt(fiat_type(conversion_type(fiat_rate_used) * conversion_type(satoshi) / COIN_VALUE_DECIMAL));
        }

        if (have_asset_info) {
            if (precision == 0) {
                result[asset_id] = sats;
            } else {
                result[asset_id] = fmt(btc_type(satoshi_conv / COIN_VALUE_WITH_PRECISION), precision);
            }
        }
        return result;
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

    amount::signed_value_type amount::signed_value() const
    {
        constexpr auto highbit = (((uint64_t)1) << ((uint64_t)63));
        GDK_RUNTIME_ASSERT_MSG(!(m_value & highbit), "value out of range");
        return static_cast<signed_value_type>(m_value);
    }

} // namespace sdk
} // namespace ga
