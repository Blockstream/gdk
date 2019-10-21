#include <cctype>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "include/wally_wrapper.h"

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
            "fiat_currency", "fiat_rate" };

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
        const auto asset_info_p = amount_json.find("asset_info");
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
        GDK_RUNTIME_ASSERT(key_count == 1);

        const conversion_type COIN_VALUE_WITH_PRECISION(std::pow(10, precision));

        const std::string fr_str = fiat_rate.empty() ? "0" : fiat_rate;
        const conversion_type fr(fr_str);
        int64_t satoshi;

        // Compute satoshi from our input
        if (satoshi_p != end_p) {
            satoshi = *satoshi_p;
        } else if (btc_p != end_p) {
            const std::string btc_str = *btc_p;
            satoshi = (conversion_type(btc_str) * COIN_VALUE_DECIMAL).convert_to<value_type>();
        } else if (mbtc_p != end_p) {
            const std::string mbtc_str = *mbtc_p;
            satoshi = (conversion_type(mbtc_str) * COIN_VALUE_DECIMAL_MBTC).convert_to<value_type>();
        } else if (ubtc_p != end_p || bits_p != end_p) {
            const std::string ubtc_str = *(ubtc_p == end_p ? bits_p : ubtc_p);
            satoshi = (conversion_type(ubtc_str) * COIN_VALUE_DECIMAL_UBTC).convert_to<value_type>();
        } else if (sats_p != end_p) {
            const std::string sats_str = *sats_p;
            satoshi = (conversion_type(sats_str)).convert_to<value_type>();
        } else if (asset_p != end_p) {
            const std::string asset_str = *asset_p;
            satoshi = (conversion_type(asset_str) * COIN_VALUE_WITH_PRECISION).convert_to<value_type>();
        } else {
            const std::string fiat_str = *fiat_p;
            const conversion_type btc_decimal = conversion_type(fiat_str) / fr;
            satoshi = (btc_type(btc_decimal) * COIN_VALUE_DECIMAL).convert_to<value_type>();
        }
        GDK_RUNTIME_ASSERT_MSG(satoshi >= 0, "amount cannot be negative");

        // Check upper limit for btc type (ie. non-asset) inputs
        // Note: an asset_info block indicating btc denomination would have failed key_count check above
        if (asset_p == end_p) {
            GDK_RUNTIME_ASSERT_MSG(satoshi <= SATOSHI_MAX, "amount cannot exceed maximum number of bitcoins");
        }

        // Then compute the other denominations and fiat amount
        const conversion_type satoshi_conv = conversion_type(satoshi);
        const std::string btc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL), 8);
        const std::string mbtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_MBTC), 5);
        const std::string ubtc = fmt(btc_type(satoshi_conv / COIN_VALUE_DECIMAL_UBTC), 2);
        const std::string sats = std::to_string(satoshi);

        const conversion_type fiat_decimal = fr * conversion_type(satoshi) / COIN_VALUE_DECIMAL;

        // TODO: If the server returned the ISO country code, the caller could do locale aware formatting
        nlohmann::json result = { { "satoshi", satoshi }, { "btc", btc }, { "mbtc", mbtc }, { "ubtc", ubtc },
            { "bits", ubtc }, { "sats", sats }, { "fiat", fmt(fiat_type(fiat_decimal)) },
            { "fiat_currency", fiat_currency }, { "fiat_rate", fr_str } };
        if (asset_info_p != end_p) {
            result.emplace(
                asset_id, precision == 0 ? sats : fmt(btc_type(satoshi_conv / COIN_VALUE_WITH_PRECISION), precision));
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

} // namespace sdk
} // namespace ga
