#ifndef GDK_AMOUNT_HPP
#define GDK_AMOUNT_HPP
#pragma once

#include <ostream>
#include <string>

#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {

    class amount final {
    public:
        // Internally, BTC amounts are held as satoshi
        using signed_value_type = int64_t;
        using value_type = uint64_t;

        static constexpr value_type coin_value = 100000000;
        static constexpr value_type cent = 1000000;

        explicit amount(value_type v = 0)
            : m_value(v)
        {
        }

        amount(const amount&) = default;
        amount& operator=(const amount&) = default;
        amount(amount&&) = default;
        amount& operator=(amount&&) = default;
        amount(const nlohmann::json& json_value);
        ~amount() = default;

        // General purpose conversion to/from fiat
        static nlohmann::json convert(
            const nlohmann::json& amount_json, const std::string& fiat_currency, const std::string& fiat_rate);

        // Remove all conversion keys except satoshi
        static void strip_non_satoshi_keys(nlohmann::json& amount_json);

        // Convert fiat cents to fiat + BTC amounts
        static nlohmann::json convert_fiat_cents(value_type cents, const std::string& fiat_currency);

        // Get fiat cents from a fiat string
        static value_type get_fiat_cents(const std::string& fiat_str);

        // Format a number string to include 'dp' decimal places
        static std::string format_amount(const std::string& value_str, size_t dp);

        // Get the maximum number of satoshi for a BTC/L-BTC amount
        static value_type get_max_satoshi();

        amount& operator=(value_type v)
        {
            m_value = v;
            return *this;
        }

        amount& operator+=(value_type v)
        {
            m_value += v;
            return *this;
        }

        amount& operator-=(value_type v)
        {
            m_value -= v;
            return *this;
        }

        amount& operator*=(value_type v)
        {
            m_value *= v;
            return *this;
        }

        amount& operator/=(value_type v)
        {
            m_value /= v;
            return *this;
        }

        amount& operator+=(const amount& x)
        {
            m_value += x.m_value;
            return *this;
        }

        amount& operator-=(const amount& y)
        {
            m_value -= y.m_value;
            return *this;
        }

        value_type value() const { return m_value; }
        signed_value_type signed_value() const;

    private:
        value_type m_value;
    };

    inline amount operator+(const amount& x, const amount& y)
    {
        amount r = x;
        r += y;
        return r;
    }

    inline amount operator+(const amount& x, amount::value_type y)
    {
        amount r = x;
        r += y;
        return r;
    }

    inline amount operator+(amount::value_type x, const amount& y)
    {
        amount r = y;
        r += x;
        return r;
    }

    inline amount operator-(const amount& x, const amount& y)
    {
        amount r = x;
        r -= y;
        return r;
    }

    inline amount operator-(const amount& x, amount::value_type y)
    {
        amount r = x;
        r -= y;
        return r;
    }

    inline amount operator-(amount::value_type x, const amount& y)
    {
        amount r{ x };
        r -= y;
        return r;
    }

    inline amount operator*(const amount& x, amount::value_type y)
    {
        amount r = x;
        r *= y;
        return r;
    }

    inline amount operator*(amount::value_type x, const amount& y)
    {
        amount r = y;
        r *= x;
        return r;
    }

    inline amount operator/(const amount& x, amount::value_type y)
    {
        amount r = x;
        r /= y;
        return r;
    }

    inline amount operator/(amount::value_type x, const amount& y)
    {
        amount r = y;
        r /= x;
        return r;
    }

    inline amount operator+(const amount& x) { return x; }

    inline amount operator-(const amount& x) { return amount{ -x.value() }; }

    inline bool operator==(const amount& x, const amount& y) { return x.value() == y.value(); }

    inline bool operator==(const amount& x, const amount::value_type& y) { return x.value() == y; }

    inline bool operator==(amount::value_type x, const amount& y) { return x == y.value(); }

    inline bool operator!=(const amount& x, const amount& y) { return x.value() != y.value(); }

    inline bool operator!=(const amount& x, const amount::value_type& y) { return x.value() != y; }

    inline bool operator!=(amount::value_type x, const amount& y) { return x != y.value(); }

    inline bool operator>(const amount& x, const amount& y) { return x.value() > y.value(); }

    inline bool operator>(const amount& x, const amount::value_type& y) { return x.value() > y; }

    inline bool operator>(amount::value_type x, const amount& y) { return x > y.value(); }

    inline bool operator>=(const amount& x, const amount& y) { return x.value() >= y.value(); }

    inline bool operator>=(const amount& x, const amount::value_type& y) { return x.value() >= y; }

    inline bool operator>=(amount::value_type x, const amount& y) { return x >= y.value(); }

    inline bool operator<(const amount& x, const amount& y) { return x.value() < y.value(); }

    inline bool operator<(const amount& x, const amount::value_type& y) { return x.value() < y; }

    inline bool operator<(amount::value_type x, const amount& y) { return x < y.value(); }

    inline bool operator<=(const amount& x, const amount& y) { return x.value() <= y.value(); }

    inline bool operator<=(const amount& x, const amount::value_type& y) { return x.value() <= y; }

    inline bool operator<=(amount::value_type x, const amount& y) { return x <= y.value(); }

    inline std::ostream& operator<<(std::ostream& os, const amount& x)
    {
        os << x.value();
        return os;
    }

    inline std::string to_string(const amount& x) { return std::to_string(x.value()); }
} // namespace sdk
} // namespace ga

#endif
