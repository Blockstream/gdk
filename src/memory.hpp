#ifndef GDK_MEMORY_HPP
#define GDK_MEMORY_HPP
#pragma once

#include <array>
#include <memory>
#include <new>
#include <vector>

#include <gsl/span>

#include "assertion.hpp"

namespace ga {
namespace sdk {
    template <typename T, typename U, typename V> inline void init_container(T& dst, const U& arg1, const V& arg2)
    {
        GDK_RUNTIME_ASSERT(arg1.data() && arg2.data());
        GDK_RUNTIME_ASSERT(
            dst.size() == gsl::narrow<typename T::size_type>(arg1.size() + arg2.size())); // No partial fills supported
        std::copy(arg1.begin(), arg1.end(), dst.data());
        std::copy(arg2.begin(), arg2.end(), dst.data() + arg1.size());
    }

    // Make a byte span out of string input
    inline auto ustring_span(const std::string& str)
    {
        return gsl::make_span(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

    // Make an empty byte span
    template <typename T = unsigned char> inline auto empty_span() { return gsl::make_span<const T>(nullptr, 0); }
} // namespace sdk
} // namespace ga

#endif
