#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>

#ifdef __x86_64
#include <x86intrin.h>
#endif

#include <openssl/rand.h>

#include "boost_wrapper.hpp"

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_strings.hpp"
#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"
#include "memory.hpp"
#include "utils.hpp"

#if defined _WIN32 || defined WIN32 || defined __CYGWIN__
#include "bcrypt.h"
#endif

namespace ga {
namespace sdk {

    // from bitcoin core
    namespace {
        inline int64_t GetPerformanceCounter()
        {
            // Read the hardware time stamp counter when available.
            // See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
            return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
            uint64_t r = 0;
            __asm__ volatile("rdtsc" : "=A"(r)); // Constrain the r variable to the eax:edx pair.
            return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
            uint64_t r1 = 0, r2 = 0;
            __asm__ volatile("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
            return (r2 << 32) | r1;
#else
            // Fall back to using C++11 clock (usually microsecond or nanosecond precision)
            return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
        }

        void GetOSRand(unsigned char* buf)
        {
#if !defined _WIN32 && !defined WIN32 && !defined __CYGWIN__
            int random_device = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            GDK_RUNTIME_ASSERT(random_device != -1);
            const auto random_device_ptr = std::unique_ptr<int, std::function<void(int*)>>(
                &random_device, [](const int* device) { ::close(*device); });

            GDK_RUNTIME_ASSERT(static_cast<size_t>(read(random_device, buf, 32)) == 32);
#else
            GDK_RUNTIME_ASSERT(BCryptGenRandom(NULL, buf, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0x0);
#endif
        }

        bool Random_SanityCheck()
        {
            constexpr int NUM_OS_RANDOM_BYTES = 32;

            uint64_t start = GetPerformanceCounter();

            /* This does not measure the quality of randomness, but it does test that
             * OSRandom() overwrites all 32 bytes of the output given a maximum
             * number of tries.
             */
            static const ssize_t MAX_TRIES = 1024;
            uint8_t data[NUM_OS_RANDOM_BYTES];
            bool overwritten[NUM_OS_RANDOM_BYTES] = {}; /* Tracks which bytes have been overwritten at least once */
            int num_overwritten;
            int tries = 0;
            /* Loop until all bytes have been overwritten at least once, or max number tries reached */
            do {
                memset(data, 0, NUM_OS_RANDOM_BYTES);
                GetOSRand(data);
                for (int x = 0; x < NUM_OS_RANDOM_BYTES; ++x) {
                    overwritten[x] |= (data[x] != 0);
                }

                num_overwritten = 0;
                for (int x = 0; x < NUM_OS_RANDOM_BYTES; ++x) { // NOLINT: original from Core.
                    if (overwritten[x]) {
                        num_overwritten += 1;
                    }
                }

                tries += 1;
            } while (num_overwritten < NUM_OS_RANDOM_BYTES && tries < MAX_TRIES);
            if (num_overwritten != NUM_OS_RANDOM_BYTES) {
                return false; /* If this failed, bailed out after too many tries */
            }

            // Check that GetPerformanceCounter increases at least during a GetOSRand() call + 1ms sleep.
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            uint64_t stop = GetPerformanceCounter();
            if (stop == start) {
                return false;
            }

            // We called GetPerformanceCounter. Use it as entropy.
            RAND_add((const unsigned char*)&start, sizeof(start), 1);
            RAND_add((const unsigned char*)&stop, sizeof(stop), 1);

            return true;
        }
    } // namespace

    // use the same strategy as bitcoin core
    void get_random_bytes(std::size_t num_bytes, void* output_bytes, std::size_t siz)
    {
        static std::mutex curr_state_mutex;
        static std::array<unsigned char, 32> curr_state = { { 0 } };
        static uint64_t nonce = 0;

        // We only allow fetching up to 32 bytes of random data as bits beyond
        // this expose the final bytes of the sha512 we use to update curr_state.
        GDK_RUNTIME_ASSERT(num_bytes <= 32 && num_bytes <= siz);

        int64_t tsc = GetPerformanceCounter();

        RAND_add(&tsc, sizeof tsc, 1.5);
        wally_bzero(&tsc, sizeof tsc);

        // 32 bytes from openssl, 32 from os random source, 32 from state, 8 from nonce
        std::array<unsigned char, 32 + 32 + 32 + 8> buf;
        GDK_RUNTIME_ASSERT(RAND_bytes(buf.data(), 32) == 1);

        GetOSRand(buf.data() + 32);

        std::array<unsigned char, SHA512_LEN> hashed;
        {
            std::unique_lock<std::mutex> l{ curr_state_mutex };

            GDK_RUNTIME_ASSERT(nonce || Random_SanityCheck());

            std::copy(curr_state.begin(), curr_state.end(), buf.data() + 64);
            std::copy(reinterpret_cast<unsigned char*>(&nonce), reinterpret_cast<unsigned char*>(&nonce) + 8,
                buf.data() + 96);
            ++nonce;

            hashed = sha512(buf);
            std::copy(hashed.begin() + 32, hashed.end(), curr_state.data());
        }

        std::copy(hashed.begin(), hashed.begin() + siz, static_cast<unsigned char*>(output_bytes));

        wally_bzero(hashed.data(), hashed.size());
    }

    int32_t spv_verify_tx(const nlohmann::json& details)
    {
        auto rustinput = gdkrust_json(details).get();
        return GDKRUST_spv_verify_tx(rustinput);
    }

    uint32_t get_uniform_uint32_t(uint32_t upper_bound)
    {
        // Algorithm from the PCG family of random generators
        uniform_uint32_rng rng;
        const uint32_t lower_threshold = -upper_bound % upper_bound;
        while (true) {
            uint32_t v = rng();
            if (v >= lower_threshold) {
                return v % upper_bound;
            }
        }
    }

    uniform_uint32_rng::result_type uniform_uint32_rng::operator()()
    {
        if (++m_index == m_entropy.size()) {
            m_index = 0;
            const size_t num_bytes = m_entropy.size() * sizeof(result_type);
            get_random_bytes(num_bytes, m_entropy.data(), num_bytes);
        }
        return m_entropy[m_index];
    }

    std::string decrypt_mnemonic(const std::string& encrypted_mnemonic, const std::string& password)
    {
        const auto entropy = bip39_mnemonic_to_bytes(encrypted_mnemonic);
        GDK_RUNTIME_ASSERT_MSG(entropy.size() == 36, "Invalid encrypted mnemonic");
        const auto ciphertext = gsl::make_span(entropy).first(32);
        const auto salt = gsl::make_span(entropy).last(4);

        std::vector<unsigned char> derived(64);
        scrypt(ustring_span(password), salt, 16384, 8, 8, derived);

        const auto key = gsl::make_span(derived).last(32);
        std::vector<unsigned char> plaintext(32);
        aes(key, ciphertext, AES_FLAG_DECRYPT, plaintext);
        for (int i = 0; i < 32; ++i) {
            plaintext[i] ^= derived[i];
        }

        const auto sha_buffer = sha256d(plaintext);
        const auto salt_ = gsl::make_span(sha_buffer).first(4);
        GDK_RUNTIME_ASSERT_MSG(!memcmp(salt_.data(), salt.data(), salt.size()), "Invalid checksum");

        return bip39_mnemonic_from_bytes(plaintext);
    }

    std::string encrypt_mnemonic(const std::string& plaintext_mnemonic, const std::string& password)
    {
        const auto plaintext = bip39_mnemonic_to_bytes(plaintext_mnemonic);
        const auto sha_buffer = sha256d(plaintext);
        const auto salt = gsl::make_span(sha_buffer).first(4);

        std::vector<unsigned char> derived(64);
        scrypt(ustring_span(password), salt, 16384, 8, 8, derived);
        const auto derivedhalf1 = gsl::make_span(derived).first(32);
        const auto derivedhalf2 = gsl::make_span(derived).last(32);

        std::array<unsigned char, 32> decrypted;
        for (int i = 0; i < 32; ++i) {
            decrypted[i] = plaintext[i] ^ derivedhalf1[i];
        }

        std::vector<unsigned char> ciphertext;
        ciphertext.reserve(36);
        ciphertext.resize(32);
        aes(derivedhalf2, decrypted, AES_FLAG_ENCRYPT, ciphertext);
        ciphertext.insert(ciphertext.end(), salt.begin(), salt.end());

        return bip39_mnemonic_from_bytes(ciphertext);
    }

    // Parse a bitcoin uri as described in bip21/72 and return the components
    // If the uri passed is not a bitcoin uri return a null json object.
    nlohmann::json parse_bitcoin_uri(const std::string& uri, const std::string& expected_scheme)
    {
        // Split a string into a head and tail around the first (leftmost) occurrence
        // of delimiter and return the tuple (head, tail). If delimiter does not occur
        // in input return the tuple (input, '')
        auto&& split = [](const std::string& input, char delimiter) {
            const auto pos = input.find(delimiter);
            const auto endpos = pos == std::string::npos ? input.size() : pos + 1;
            return std::make_tuple(input.substr(0, pos), input.substr(endpos));
        };

        // TODO: Take either the label or message and set the tx memo field with it if not set
        // FIXME: URL unescape the arguments before returning
        //
        std::string uri_copy = uri;
        boost::trim(uri_copy);
        nlohmann::json parsed;
        std::string scheme, tail;
        std::tie(scheme, tail) = split(uri_copy, ':');

        boost::algorithm::to_lower(scheme);
        if (scheme == expected_scheme) {
            parsed["scheme"] = scheme;

            std::string address;
            std::tie(address, tail) = split(tail, '?');
            if (!address.empty()) {
                parsed["address"] = address;
            }
            nlohmann::json params;
            while (!tail.empty()) {
                std::string param, key, value;
                std::tie(param, tail) = split(tail, '&');
                std::tie(key, value) = split(param, '=');
                if (boost::algorithm::starts_with(key, "req-")) {
                    throw user_error(res::id_unknown_bip21_parameter);
                }
                params.emplace(key, value);
            }
            parsed["bip21-params"] = params;

            // always treat the asset_id as lowercase
            if (parsed["bip21-params"].contains("assetid")) {
                parsed["bip21-params"]["assetid"]
                    = boost::algorithm::to_lower_copy(parsed["bip21-params"]["assetid"].get<std::string>());
            }
        }

        return parsed;
    }

    // Lookup key in json and if present decode it as hex and return the bytes, if not present
    // return the result of calling f()
    // This is useful in a couple of places where a bytes value can be optionally overridden in json
    template <class F> inline auto json_default_hex(const nlohmann::json& json, const std::string& key, F&& f)
    {
        const auto p = json.find(key);
        return p == json.end() ? f() : h2b(p->get<std::string>());
    }

    std::string aes_cbc_decrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& ciphertext)
    {
        const auto ciphertext_bytes = h2b(ciphertext);
        const auto iv = gsl::make_span(ciphertext_bytes).first(AES_BLOCK_LEN);
        const auto encrypted = gsl::make_span(ciphertext_bytes).subspan(AES_BLOCK_LEN);
        std::vector<unsigned char> plaintext(encrypted.size());
        aes_cbc(key, iv, encrypted, AES_FLAG_DECRYPT, plaintext);
        GDK_RUNTIME_ASSERT(plaintext.size() <= static_cast<size_t>(encrypted.size()));
        return std::string(plaintext.begin(), plaintext.end());
    }

    std::string aes_cbc_encrypt(
        const std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>& key, const std::string& plaintext)
    {
        const auto iv = get_random_bytes<AES_BLOCK_LEN>();
        const size_t plaintext_padded_size = (plaintext.size() / AES_BLOCK_LEN + 1) * AES_BLOCK_LEN;
        std::vector<unsigned char> encrypted(AES_BLOCK_LEN + plaintext_padded_size);
        aes_cbc(key, iv, ustring_span(plaintext), AES_FLAG_ENCRYPT, encrypted);
        GDK_RUNTIME_ASSERT(encrypted.size() == plaintext_padded_size);
        encrypted.insert(std::begin(encrypted), iv.begin(), iv.end());
        return b2h(encrypted);
    }

    // Given a set of urls select the most appropriate
    // Preference is in order:
    //  - onion
    //  - https
    //  - http
    //
    // onion urls are ignored if use_tor is false
    nlohmann::json select_url(const std::vector<nlohmann::json>& urls, bool use_tor)
    {
        GDK_RUNTIME_ASSERT(!urls.empty());

        std::vector<nlohmann::json> onion_urls, https_urls, insecure_urls;
        for (const auto& url_json : urls) {
            const auto url = parse_url(url_json);
            if (url["is_onion"]) {
                if (use_tor) {
                    onion_urls.push_back(url);
                }
            } else if (url["is_secure"]) {
                https_urls.push_back(url);
            } else {
                insecure_urls.push_back(url);
            }
        }

        if (!onion_urls.empty()) {
            return onion_urls[0];
        } else if (!https_urls.empty()) {
            return https_urls[0];
        } else {
            return insecure_urls[0];
        }
    }

    nlohmann::json parse_url(const std::string& url)
    {
        nlohmann::json retval;

        namespace algo = boost::algorithm;
        auto endpoint = url;
        const bool use_tls = algo::starts_with(endpoint, "wss://") || algo::starts_with(endpoint, "https://");
        if (use_tls) {
            algo::erase_all(endpoint, "wss://");
            algo::erase_all(endpoint, "https://");
            retval["is_secure"] = true;
        } else {
            algo::erase_all(endpoint, "ws://");
            algo::erase_all(endpoint, "http://");
            retval["is_secure"] = false;
        }
        std::vector<std::string> endpoint_parts;
        algo::split(endpoint_parts, endpoint, algo::is_any_of("/"));
        GDK_RUNTIME_ASSERT(!endpoint_parts.empty());
        if (endpoint_parts.size() > 1) {
            retval["target"] = "/"
                + algo::join(std::vector<std::string>(std::begin(endpoint_parts) + 1, std::end(endpoint_parts)), "/");
        }
        std::vector<std::string> host_parts;
        algo::split(host_parts, endpoint_parts[0], algo::is_any_of(":"));
        GDK_RUNTIME_ASSERT(!host_parts.empty());
        retval["port"] = host_parts.size() > 1 ? host_parts[1] : use_tls ? "443" : "80";
        retval["is_onion"] = algo::ends_with(host_parts[0], ".onion");
        retval["host"] = host_parts[0];

        return retval;
    }
} // namespace sdk
} // namespace ga

namespace {
template <std::size_t N> int generate_mnemonic(char** output)
{
    try {
        GDK_RUNTIME_ASSERT(output);
        auto entropy = ga::sdk::get_random_bytes<N>();
        GDK_VERIFY(::bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), output));
        wally_bzero(entropy.data(), entropy.size());
        return GA_OK;
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}
} // namespace

extern "C" int GA_get_random_bytes(size_t num_bytes, unsigned char* output_bytes, size_t len)
{
    try {
        ga::sdk::get_random_bytes(num_bytes, output_bytes, len);
        return GA_OK;
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

extern "C" int GA_generate_mnemonic(char** output) { return generate_mnemonic<32>(output); }

extern "C" int GA_generate_mnemonic_12(char** output) { return generate_mnemonic<16>(output); }

extern "C" int GA_validate_mnemonic(const char* mnemonic, uint32_t* valid)
{
    *valid = GA_FALSE;
    try {
        GDK_VERIFY(bip39_mnemonic_validate(nullptr, mnemonic));
        *valid = GA_TRUE;
    } catch (const std::exception& e) {
    }
    return GA_OK;
}

void GA_destroy_string(char* str) { free(str); }
