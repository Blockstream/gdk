#ifndef GDK_UTILS_HPP
#define GDK_UTILS_HPP
#pragma once

#include <cstddef>
#include <map>
#include <string>

#include "containers.hpp"
#include "ga_wally.hpp"
#include "include/gdk.h"
#include "logging.hpp"
#include "threading.hpp"

namespace ga {
namespace sdk {
    void get_random_bytes(std::size_t num_bytes, void* output_bytes, std::size_t siz);

    template <std::size_t N> std::array<unsigned char, N> get_random_bytes()
    {
        std::array<unsigned char, N> buff{ { 0 } };
        get_random_bytes(N, buff.data(), buff.size());
        return buff;
    }

    // Return a uint32_t in the range 0 to (upper_bound - 1) without bias
    uint32_t get_uniform_uint32_t(uint32_t upper_bound);

    int32_t spv_verify_tx(const nlohmann::json& details);

    // STL compatible RNG returning uniform uint32_t's
    struct uniform_uint32_rng {
        uniform_uint32_rng() // NOLINT: ignored for valgrind use
            : m_index(m_entropy.size() - 1u)
        {
        }

        using result_type = uint32_t;
        constexpr static result_type min() { return std::numeric_limits<result_type>::min(); }
        constexpr static result_type max() { return std::numeric_limits<result_type>::max(); }
        result_type operator()();

    private:
        std::array<result_type, 8> m_entropy; // NOLINT: ignored for valgrind use
        size_t m_index;
    };

    template <typename InputIt, typename OutputIt, typename BinaryOperation>
    void adjacent_transform(InputIt first, InputIt last, OutputIt d_first, BinaryOperation binary_op)
    {
        auto next = first;
        while (next != last) {
            auto prev = next++;
            *d_first++ = binary_op(*prev, *next++);
        }
    }

    template <typename F> void no_std_exception_escape(F&& fn) noexcept GDK_NO_THREAD_SAFETY_ANALYSIS
    {
        try {
            fn();
        } catch (const std::exception& e) {
            try {
                const auto what = e.what();
                GDK_LOG_SEV(log_level::debug) << "ignoring exception:" << what;
            } catch (const std::exception&) {
            }
        }
    }

    nlohmann::json parse_bitcoin_uri(const std::string& uri, const std::string& expected_scheme);

    nlohmann::json parse_url(const std::string& url);
    nlohmann::json select_url(const std::vector<nlohmann::json>& urls, bool use_tor);

    // Mnemonic handling
    std::string encrypt_mnemonic(const std::string& plaintext_mnemonic, const std::string& password);
    std::string decrypt_mnemonic(const std::string& encrypted_mnemonic, const std::string& password);

    // Encryption
    std::string aes_cbc_decrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& ciphertext);
    std::string aes_cbc_encrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& plaintext);

} // namespace sdk
} // namespace ga

#endif
