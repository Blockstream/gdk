#ifndef GDK_MEMORY_HPP
#define GDK_MEMORY_HPP
#pragma once

#include <array>
#include <memory>
#include <new>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <type_traits>
#include <vector>

#include "assertion.hpp"
#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"

namespace green {

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

    template <typename T> void wipe_and_truncate(std::vector<T>& data)
    {
        wally_bzero(data.data(), data.size());
        swap_with_default(data);
    }

    // Only the containers current buffer is wiped.
    // Buffers abandoned by re-allocation, e.g. when a string grows, cannot be reached.
    template <typename T> inline void wipe(T& data) noexcept
    {
        // e.g. a vector<string> must not be wiped as a whole: only its elements
        static_assert(std::is_trivially_copyable_v<std::remove_reference_t<decltype(*data.data())>>);
        if (!data.empty()) {
            wally_bzero(data.data(), data.size() * sizeof(*data.data()));
        }
    }

    // Recurses into arrays and objects. Scalars are stored inline and not wiped.
    void wipe(nlohmann::json& data) noexcept;

    template <typename T, typename U> inline void wipe(std::pair<T, U>& data) noexcept
    {
        wipe(data.first);
        wipe(data.second);
    }

    template <typename T> inline void wipe(std::optional<T>& data) noexcept
    {
        if (data.has_value()) {
            wipe(*data);
        }
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
    inline auto ustring_span(const std::string_view& str)
    {
        return gsl::make_span(reinterpret_cast<const unsigned char*>(str.data()), str.size());
    }

} // namespace green

// Never use on a local that is returned: under NRVO the local is the return
// value, and so would be wiped before the caller can read it.
#define GDK_WIPE_ON_EXIT(name) const auto name##_wiper = gsl::finally([&to_wipe = (name)] { green::wipe(to_wipe); })

// Declare 'name' from the given expression, and wipe it as GDK_WIPE_ON_EXIT
#define GDK_AUTO_WIPE(name, ...)                                                                                       \
    auto name = __VA_ARGS__;                                                                                           \
    GDK_WIPE_ON_EXIT(name)

#endif
