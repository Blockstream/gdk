#ifndef GDK_MEMORY_HPP
#define GDK_MEMORY_HPP
#pragma once

#include <array>
#include <memory>
#include <new>
#include <vector>

#include "assertion.hpp"
#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"

namespace ga {
namespace sdk {
    template <std::size_t N> inline std::array<unsigned char, N> make_byte_array(byte_span_t bytes)
    {
        GDK_RUNTIME_ASSERT(bytes.size() == N);
        std::array<unsigned char, N> ret;
        std::copy(bytes.begin(), bytes.end(), ret.data());
        return ret;
    }

    template <typename T, std::size_t N> inline std::vector<T> make_vector(const std::array<T, N>& src)
    {
        return { src.begin(), src.end() };
    }
    template <typename T, std::size_t N> inline std::vector<T> make_vector(const std::array<const T, N>& src)
    {
        return { src.begin(), src.end() };
    }

    template <typename T> void swap_with_default(T& obj) { T().swap(obj); }

    template <typename T> void bzero_and_free(std::vector<T>& data)
    {
        wally_bzero(data.data(), data.size());
        swap_with_default(data);
    }

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
} // namespace sdk
} // namespace ga

#endif
