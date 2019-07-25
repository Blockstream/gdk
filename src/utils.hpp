#ifndef GDK_UTILS_HPP
#define GDK_UTILS_HPP
#pragma once

#include <cstddef>
#include <map>
#include <mutex>
#include <string>

#include "containers.hpp"
#include "ga_wally.hpp"
#include "include/gdk.h"

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

    nlohmann::json parse_bitcoin_uri(const std::string& uri);
    // TODO: URI parsing
    std::pair<std::string, std::string> split_url(const std::string& domain_name, std::string& target, bool& secure);

    // Mnemonic handling
    std::string encrypt_mnemonic(const std::string& plaintext_mnemonic, const std::string& password);
    std::string decrypt_mnemonic(const std::string& encrypted_mnemonic, const std::string& password);

    // Encryption
    nlohmann::json encrypt_data(const nlohmann::json& input, const std::vector<unsigned char>& default_password);
    nlohmann::json decrypt_data(const nlohmann::json& input, const std::vector<unsigned char>& default_password);
    std::string aes_cbc_decrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& ciphertext);
    std::string aes_cbc_encrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& plaintext);

    // Scoped unlocker
    struct unique_unlock {
        explicit unique_unlock(std::unique_lock<std::mutex>& locker)
            : m_locker(locker)
            , m_owns_lock(true)
        {
            unlock();
        }

        unique_unlock(const unique_unlock&) = delete;
        unique_unlock(unique_unlock&&) = delete;
        unique_unlock& operator=(const unique_unlock&) = delete;
        unique_unlock& operator=(unique_unlock&&) = delete;

        void lock()
        {
            GDK_RUNTIME_ASSERT(!m_locker.owns_lock());
            GDK_RUNTIME_ASSERT(!m_owns_lock);
            m_locker.lock();
            m_owns_lock = true;
        }

        void unlock()
        {
            GDK_RUNTIME_ASSERT(m_locker.owns_lock());
            GDK_RUNTIME_ASSERT(m_owns_lock);
            m_locker.unlock();
            m_owns_lock = false;
        }

        ~unique_unlock()
        {
            if (!m_owns_lock) {
                lock();
            }
        }

    private:
        std::unique_lock<std::mutex>& m_locker;
        bool m_owns_lock;
    };
} // namespace sdk
} // namespace ga

#endif
