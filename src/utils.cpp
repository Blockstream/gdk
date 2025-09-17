#if defined _WIN32 || defined WIN32 || defined __CYGWIN__
// workaround https://sourceforge.net/p/mingw-w64/bugs/903/
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>

#include "bcrypt.h"
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <nlohmann/json.hpp>

#ifdef __x86_64
#include <x86intrin.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "assertion.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_wally.hpp"
#include "gdk_rust.h"
#include "gsl_wrapper.hpp"
#include "json_utils.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "signer.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"
#include <zlib.h>

namespace green {

    // from bitcoin core
    namespace {
        // Dummy network to use for computing xpub_hash_id
        static const std::string XPUB_HASH_NETWORK("GREEN_XPUB_HASH_NETWORK");

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
            return gsl::narrow<int64_t>((r2 << 32) | r1);
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

        static std::pair<std::string, std::string> get_rust_exception_details(const nlohmann::json& details)
        {
            std::pair<std::string, std::string> ret;
            if (!details.is_null()) {
                try {
                    ret.first = details.value("error", std::string());
                    ret.second = details.value("message", std::string());
                } catch (const std::exception&) {
                    // Ignore
                }
            }
            return ret;
        }

        static void check_rust_return_code(const int32_t return_code, const nlohmann::json& json)
        {
            if (return_code != GA_OK) {
                switch (return_code) {
                case GA_RECONNECT:
                case GA_SESSION_LOST:
                    throw reconnect_error();

                case GA_TIMEOUT:
                    throw timeout_error();

                case GA_NOT_AUTHORIZED:
                    throw login_error(get_rust_exception_details(json).second);

                case GA_ERROR:
                default:
                    throw user_error(get_rust_exception_details(json).second);
                }
            }
        }

        static nlohmann::json rust_call_impl(const std::string& method, const nlohmann::json& input, void* session)
        {
            char* output = nullptr;
            int ret;
            if (session) {
                ret = GDKRUST_call_session(session, method.c_str(), input.dump().c_str(), &output);
            } else {
                ret = GDKRUST_call(method.c_str(), input.dump().c_str(), &output);
            }
            nlohmann::json cppjson = nlohmann::json();
            if (output) {
                // output was set by calling `std::ffi::CString::into_raw`;
                // parse it, then destroy it with GDKRUST_destroy_string.
                std::unique_ptr<char, decltype(&GDKRUST_destroy_string)> holder(output, GDKRUST_destroy_string);
                cppjson = json_parse(output);
            }
            check_rust_return_code(ret, cppjson);
            return cppjson;
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
        GDK_RUNTIME_ASSERT(output_bytes);
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

    nlohmann::json rust_call(const std::string& method, const nlohmann::json& details, void* session)
    {
        return rust_call_impl(method, details, session);
    }

    void init_rust(const nlohmann::json& details) { rust_call("init", details); }

    static void write_length32(uint32_t len, std::vector<unsigned char>::iterator it)
    {
        *it++ = (unsigned char)(len >> 0);
        *it++ = (unsigned char)(len >> 8);
        *it++ = (unsigned char)(len >> 16);
        *it = (unsigned char)(len >> 24);
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
        if (password.empty()) {
            return encrypted_mnemonic; // Unencrypted
        }
        const auto entropy = bip39_mnemonic_to_bytes(encrypted_mnemonic);
        GDK_RUNTIME_ASSERT_MSG(entropy.size() == 36, "Invalid encrypted mnemonic");
        const auto ciphertext = gsl::make_span(entropy).first(32);
        const auto salt = gsl::make_span(entropy).last(4);

        const std::vector<unsigned char> derived = scrypt(ustring_span(password), salt);

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
        if (password.empty()) {
            return plaintext_mnemonic;
        }
        const auto plaintext = bip39_mnemonic_to_bytes(plaintext_mnemonic);
        const auto sha_buffer = sha256d(plaintext);
        const auto salt = gsl::make_span(sha_buffer).first(4);

        const std::vector<unsigned char> derived = scrypt(ustring_span(password), salt);
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

    std::vector<unsigned char> compute_watch_only_entropy(const std::string& username, const std::string& password)
    {
        const std::string u_p = username + password;
        std::vector<unsigned char> entropy;
        entropy.resize(sizeof(uint32_t) + u_p.size());
        write_length32(username.size(), entropy.begin());
        std::copy(u_p.begin(), u_p.end(), entropy.begin() + sizeof(uint32_t));
        return scrypt(entropy, signer::WATCH_ONLY_SALT);
    }

    static pbkdf2_hmac256_t get_watch_only_aes_key(byte_span_t entropy)
    {
        return pbkdf2_hmac_sha512_256(entropy, signer::WO_SEED_K);
    }

    std::string encrypt_watch_only_data(byte_span_t entropy, byte_span_t data)
    {
        return aes_cbc_encrypt_to_hex(get_watch_only_aes_key(entropy), data);
    }

    std::vector<unsigned char> decrypt_watch_only_data(byte_span_t entropy, const std::string& data_hex)
    {
        return aes_cbc_decrypt_from_hex(get_watch_only_aes_key(entropy), data_hex);
    }

    pub_key_t get_watch_only_cache_encryption_key(byte_span_t entropy, const std::string& extra_entropy)
    {
        GDK_RUNTIME_ASSERT(!extra_entropy.empty());
        pub_key_t encryption_key;
        const auto key_bytes = pbkdf2_hmac_sha512(entropy, ustring_span(extra_entropy));
        std::copy(key_bytes.begin(), key_bytes.begin() + sizeof(pub_key_t), encryption_key.begin());
        // Note that the pubkey data we return does not have to be valid
        return encryption_key;
    }

    nlohmann::json parse_bitcoin_uri(const network_parameters& net_params, const std::string& uri)
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
        auto [scheme, tail] = split(boost::trim_copy(uri), ':');

        if (boost::to_lower_copy(scheme) == net_params.bip21_prefix()) {
            std::string address;
            std::tie(address, tail) = split(tail, '?');
            if (address.empty()) {
                throw user_error(res::id_invalid_address);
            }
            nlohmann::json params;
            while (!tail.empty()) {
                std::string param;
                std::tie(param, tail) = split(tail, '&');
                auto [key, value] = split(param, '=');
                if (boost::algorithm::starts_with(key, "req-")) {
                    throw user_error(res::id_unknown_bip21_parameter);
                }
                params.emplace(key, value);
            }

            const bool is_liquid = net_params.is_liquid();
            if (auto p = params.find("assetid"); p != params.end()) {
                // Lowercase and validate the asset id
                *p = boost::to_lower_copy(p->is_null() ? std::string() : p->get<std::string>());
                (void)j_assetref(is_liquid, params, "assetid"); // Validate it
            } else if (is_liquid && params.contains("amount")) {
                // Asset id is mandatory if an amount is present
                throw user_error(res::id_invalid_payment_request_assetid);
            }

            // Valid. Convert the URI to its address and return the
            // asset id and amount in "bip21-params".
            return { { "address", std::move(address) }, { "bip21-params", std::move(params) } };
        }

        return {};
    }

    // Lookup key in json and if present decode it as hex and return the bytes, if not present
    // return the result of calling f()
    // This is useful in a couple of places where a bytes value can be optionally overridden in json
    template <class F> inline auto json_default_hex(const nlohmann::json& json, const std::string& key, F&& f)
    {
        const auto p = json.find(key);
        return p == json.end() ? f() : h2b(p->get<std::string>());
    }

    std::vector<unsigned char> aes_cbc_decrypt(const pbkdf2_hmac256_t& key, byte_span_t ciphertext)
    {
        const auto iv = ciphertext.first(AES_BLOCK_LEN);
        const auto encrypted = ciphertext.subspan(AES_BLOCK_LEN);
        std::vector<unsigned char> plaintext(encrypted.size());
        aes_cbc(key, iv, encrypted, AES_FLAG_DECRYPT, plaintext);
        GDK_RUNTIME_ASSERT(plaintext.size() <= static_cast<size_t>(encrypted.size()));
        return plaintext;
    }

    std::vector<unsigned char> aes_cbc_decrypt_from_hex(const pbkdf2_hmac256_t& key, const std::string& ciphertext_hex)
    {
        const auto ciphertext = h2b(ciphertext_hex);
        return aes_cbc_decrypt(key, ciphertext);
    }

    std::vector<unsigned char> aes_cbc_encrypt(const pbkdf2_hmac256_t& key, byte_span_t plaintext)
    {
        const auto iv = get_random_bytes<AES_BLOCK_LEN>();
        const size_t plaintext_padded_size = (plaintext.size() / AES_BLOCK_LEN + 1) * AES_BLOCK_LEN;
        std::vector<unsigned char> encrypted(AES_BLOCK_LEN + plaintext_padded_size);
        aes_cbc(key, iv, plaintext, AES_FLAG_ENCRYPT, encrypted);
        GDK_RUNTIME_ASSERT(encrypted.size() == plaintext_padded_size);
        encrypted.insert(std::begin(encrypted), iv.begin(), iv.end());
        return encrypted;
    }

    std::string aes_cbc_encrypt_to_hex(const pbkdf2_hmac256_t& key, byte_span_t plaintext)
    {
        return b2h(aes_cbc_encrypt(key, plaintext));
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
        std::vector<nlohmann::json> https_urls, insecure_urls;
        for (const auto& url_json : urls) {
            auto url = parse_url(url_json);
            if (j_boolref(url, "is_onion")) {
                if (use_tor) {
                    return url;
                }
            } else if (j_boolref(url, "is_secure")) {
                https_urls.emplace_back(std::move(url));
            } else {
                insecure_urls.emplace_back(std::move(url));
            }
        }

        if (!https_urls.empty()) {
            return std::move(https_urls.front());
        } else if (insecure_urls.empty()) {
            throw user_error("No URL provided");
        }
        return std::move(insecure_urls.front());
    }

    static const std::string SOCKS5("socks5://");
    std::string socksify(const std::string& proxy)
    {
        std::string trimmed = boost::algorithm::trim_copy(proxy);
        if (!trimmed.empty() && !boost::algorithm::starts_with(trimmed, SOCKS5)) {
            return SOCKS5 + trimmed;
        }
        return trimmed;
    }

    std::string unsocksify(const std::string& proxy)
    {
        std::string trimmed = boost::algorithm::trim_copy(proxy);
        if (boost::algorithm::starts_with(trimmed, SOCKS5)) {
            trimmed.erase(0, SOCKS5.size());
        }
        return trimmed;
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
        std::string target;
        if (endpoint_parts.size() > 1) {
            target = "/"
                + algo::join(std::vector<std::string>(std::begin(endpoint_parts) + 1, std::end(endpoint_parts)), "/");
        }
        retval["target"] = target;
        std::vector<std::string> host_parts;
        algo::split(host_parts, endpoint_parts[0], algo::is_any_of(":"));
        GDK_RUNTIME_ASSERT(!host_parts.empty());
        retval["port"] = host_parts.size() > 1 ? host_parts[1] : use_tls ? "443" : "80";
        retval["is_onion"] = algo::ends_with(host_parts[0], ".onion");
        retval["host"] = host_parts[0];

        return retval;
    }

    std::string format_recovery_key_message(const std::string& xpub, uint32_t subaccount, uint32_t version)
    {
        GDK_RUNTIME_ASSERT(version == 0);
        return std::string("greenaddress.it      2of3 v") + std::to_string(version) + ' ' + xpub + ' '
            + std::to_string(subaccount);
    }

    std::vector<unsigned char> compress(byte_span_t prefix, byte_span_t bytes)
    {
        const size_t prefix_len = prefix.size();
        const size_t bytes_len = bytes.size();
        uLongf compressed_len = compressBound(bytes_len);

        std::vector<unsigned char> result;
        // Initialise result with supplied prefix bytes and decompressed length
        result.resize(prefix_len + sizeof(uint32_t) + compressed_len);
        std::copy(prefix.begin(), prefix.end(), result.begin());
        const auto offset_len = gsl::narrow<std::vector<unsigned char>::difference_type>(prefix_len);
        write_length32(bytes_len, result.begin() + offset_len);
        // Add the compressed data
        int z_result = compress2(result.data() + prefix_len + sizeof(uint32_t), &compressed_len, bytes.data(),
            bytes_len, Z_BEST_COMPRESSION);
        if (z_result != Z_OK) {
            GDK_RUNTIME_ASSERT(false);
        }
        // Shrink result to the actual compressed size and return it
        result.resize(prefix_len + sizeof(uint32_t) + compressed_len);
        return result;
    }

    std::vector<unsigned char> decompress(byte_span_t bytes)
    {
        constexpr size_t minimum_compressed_size = 11;
        const size_t bytes_len = bytes.size();
        GDK_RUNTIME_ASSERT(bytes_len >= sizeof(uint32_t) + minimum_compressed_size);
        uLong compressed_len = bytes_len - sizeof(uint32_t);
        uLongf decompressed_len
            = (uint32_t)bytes[0] << 0 | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[3] << 24;

        std::vector<unsigned char> result;
        result.resize(decompressed_len);
        int z_result = uncompress2(result.data(), &decompressed_len, bytes.data() + sizeof(uint32_t), &compressed_len);
        if (z_result != Z_OK || compressed_len + sizeof(uint32_t) != bytes_len) {
            GDK_RUNTIME_ASSERT(false);
        }
        return result;
    }

#define OPENSSL_VERIFY(x) GDK_RUNTIME_ASSERT((x) == 1)

    namespace {
        constexpr int AES_GCM_TAG_SIZE = 16;
        constexpr int AES_GCM_IV_SIZE = 12;
    } // namespace
    using EVP_CIPHER_CTX_ptr = const std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

    size_t aes_gcm_encrypt_get_length(byte_span_t plaintext)
    {
        GDK_RUNTIME_ASSERT(!plaintext.empty());
        return AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE + plaintext.size();
    }

    size_t aes_gcm_encrypt(byte_span_t key, byte_span_t plaintext, gsl::span<unsigned char> cyphertext)
    {
        GDK_RUNTIME_ASSERT(key.size() == SHA256_LEN);
        GDK_RUNTIME_ASSERT(static_cast<size_t>(cyphertext.size()) == aes_gcm_encrypt_get_length(plaintext));

        std::array<unsigned char, AES_GCM_IV_SIZE> iv;
        get_random_bytes(iv.size(), iv.data(), iv.size());
        std::copy(iv.begin(), iv.end(), cyphertext.begin());
        unsigned char* out = cyphertext.data() + iv.size();

        EVP_CIPHER_CTX_ptr ctx{ EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
        OPENSSL_VERIFY(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), iv.data()));
        int n;
        OPENSSL_VERIFY(EVP_EncryptUpdate(ctx.get(), out, &n, plaintext.data(), plaintext.size()));
        out += n;
        OPENSSL_VERIFY(EVP_EncryptFinal_ex(ctx.get(), out, &n));
        out += n;
        OPENSSL_VERIFY(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, out));
        out += AES_GCM_TAG_SIZE;
        return out - cyphertext.data(); // Return the number of bytes written
    }

    size_t aes_gcm_decrypt_get_length(byte_span_t cyphertext)
    {
        const size_t len = cyphertext.size();
        GDK_RUNTIME_ASSERT(len > AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE);
        return len - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    }

    size_t aes_gcm_decrypt(byte_span_t key, byte_span_t cyphertext, gsl::span<unsigned char> plaintext)
    {
        GDK_RUNTIME_ASSERT(key.size() == SHA256_LEN);
        const size_t plaintext_size = aes_gcm_decrypt_get_length(cyphertext);
        GDK_RUNTIME_ASSERT(static_cast<size_t>(plaintext.size()) == plaintext_size);

        const byte_span_t iv(cyphertext.data(), AES_GCM_IV_SIZE);
        auto tag = const_cast<unsigned char*>(cyphertext.data()) + iv.size() + plaintext_size;
        const unsigned char* in = cyphertext.data() + iv.size();
        unsigned char* out = plaintext.data();

        EVP_CIPHER_CTX_ptr ctx{ EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

        OPENSSL_VERIFY(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, key.data(), iv.data()));
        OPENSSL_VERIFY(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag));
        int n, n_final;
        OPENSSL_VERIFY(EVP_DecryptUpdate(ctx.get(), out, &n, in, plaintext_size));
        OPENSSL_VERIFY(EVP_DecryptFinal_ex(ctx.get(), out, &n_final));
        return n + n_final;
    }

    static EVP_PKEY* pubkey_from_pem(std::string_view pem)
    {
        using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
        BIO_ptr input(BIO_new_mem_buf(pem.data(), gsl::narrow<int>(pem.size())), BIO_free);
        return PEM_read_bio_PUBKEY(input.get(), nullptr, nullptr, nullptr);
    }

    void rsa_verify_challenge(std::string_view pem, byte_span_t challenge, byte_span_t sig)
    {
        using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        EVP_PKEY_ptr pubkey(pubkey_from_pem(pem), EVP_PKEY_free);
        if (!pubkey) {
            throw user_error("Invalid public key PEM");
        }
        using EVP_MD_CTX_ptr = const std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
        EVP_MD_CTX_ptr ctx{ EVP_MD_CTX_new(), EVP_MD_CTX_free };
        if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pubkey.get()) != 1) {
            throw user_error("Failed to initialize verify context");
        }
        if (EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), challenge.data(), challenge.size()) != 1) {
            throw user_error("Verification failed");
        }
    }

    std::string get_wallet_hash_id(const std::string& chain_code_hex, const std::string& public_key_hex,
        bool is_mainnet, const std::string& network)
    {
        const xpub_hdkey main_hdkey(is_mainnet, h2b(public_key_hex), h2b(chain_code_hex));
        return main_hdkey.to_hashed_identifier(network);
    }

    nlohmann::json get_wallet_hash_ids(
        const network_parameters& net_params, const std::string& chain_code_hex, const std::string& public_key_hex)
    {
        auto wallet_hash_id
            = get_wallet_hash_id(chain_code_hex, public_key_hex, net_params.is_main_net(), net_params.network());
        auto xpub_hash_id = get_wallet_hash_id(chain_code_hex, public_key_hex, false, XPUB_HASH_NETWORK);
        return { { "wallet_hash_id", std::move(wallet_hash_id) }, { "xpub_hash_id", std::move(xpub_hash_id) } };
    }

    nlohmann::json get_wallet_hash_ids(const nlohmann::json& net_params, const nlohmann::json& params)
    {
        auto defaults = network_parameters::get(net_params.value("name", std::string()));
        const network_parameters np{ net_params, defaults };
        std::string chain_code_hex, public_key_hex;

        try {
            std::string bip32_xpub;
            if (params.contains("mnemonic")) {
                // Create a software signer to derive the master xpub
                signer tmp_signer{ np, nlohmann::json(), params };
                GDK_RUNTIME_ASSERT(tmp_signer.has_master_bip32_xpub());
                bip32_xpub = tmp_signer.get_master_bip32_xpub();
            } else {
                bip32_xpub = params.value("master_xpub", std::string());
            }
            if (!bip32_xpub.empty()) {
                const auto master_key = xpub_hdkey(bip32_xpub);
                chain_code_hex = b2h(master_key.get_chain_code());
                public_key_hex = b2h(master_key.get_public_key());
            }
        } catch (const std::exception&) {
            // Fall through...
        }
        if (chain_code_hex.empty() || public_key_hex.empty()) {
            throw user_error("Invalid credentials");
        }
        return get_wallet_hash_ids(np, chain_code_hex, public_key_hex);
    }

    bool nsee_log_info(std::string message, const char* context)
    {
        try {
            // Remove any useless boost prefix and trailing newline
            if (boost::algorithm::starts_with(message, "Throw location unknown")) {
                message.erase(0, 62);
            }
            if (!message.empty() && message.back() == '\n') {
                message.pop_back();
            }
        } catch (const std::exception&) {
        }
        GDK_LOG(info) << context << (*context ? " " : "") << "ignoring exception:" << message;
        return true;
    }

    std::string get_diagnostic_information(const boost::exception& e) { return boost::diagnostic_information(e); }

    // For use in gdb as
    // printf "%s", gdb_dump_json(<json_variable>).c_str()
    std::string gdb_dump_json(const nlohmann::json& json) { return json.dump(4); }

    bool is_valid_utf8(const std::string& str)
    {
        if (str.empty()) {
            return true; // Trivially valid
        }
        try {
            // using nlohmann::json::dump() as shortcut for utf-8 validity check
            (void)nlohmann::json(str).dump();
            return true;
        } catch (const std::exception&) {
        }
        return false;
    }

} // namespace green

namespace {
    template <std::size_t N> int generate_mnemonic(char** output)
    {
        try {
            GDK_RUNTIME_ASSERT(output);
            auto entropy = green::get_random_bytes<N>();
            GDK_VERIFY(::bip39_mnemonic_from_bytes(nullptr, entropy.data(), entropy.size(), output));
            if (::bip39_mnemonic_validate(nullptr, *output) != GA_OK) {
                wally_free_string(*output);
                *output = nullptr;
                // This should only be possible with bad hardware/cosmic rays
                GDK_RUNTIME_ASSERT_MSG(false, "Mnemonic creation failed!");
            }
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
        green::get_random_bytes(num_bytes, output_bytes, len);
        return GA_OK;
    } catch (const std::exception& e) {
        return GA_ERROR;
    }
}

extern "C" int GA_generate_mnemonic(char** output) { return generate_mnemonic<32>(output); }

extern "C" int GA_generate_mnemonic_12(char** output) { return generate_mnemonic<16>(output); }

extern "C" int GA_validate_mnemonic(const char* mnemonic, uint32_t* valid)
{
    if (!mnemonic || !valid) {
        return GA_ERROR; /* Invalid parameters */
    }
    *valid = GA_FALSE;
    try {
        GDK_VERIFY(bip39_mnemonic_validate(nullptr, mnemonic));
        *valid = GA_TRUE;
    } catch (const std::exception& e) {
    }
    return GA_OK;
}

void GA_destroy_string(char* str) { free(str); }
