#include "src/utils.hpp"

using namespace green::sdk;

// Verify AES GCM encryption/decryption

int main()
{
    unsigned char buff[32 * 32];

    for (size_t i = 0; i < 32; ++i) {
        get_random_bytes(32, buff + i * 32, 32);
    }
    const auto key = sha256(gsl::make_span(buff, sizeof(buff)));
    const auto bad_key = sha256(key);

    // Verify all lengths up to 1024 encrypt and decrypt OK
    // Perform each test in new buffers so valgrind can find any overruns
    for (size_t i = 1; i <= 1024; ++i) {
        // Encrypt
        unsigned char* plaintext = reinterpret_cast<unsigned char*>(malloc(i));
        const auto plaintext_span = gsl::make_span(plaintext, i);
        memcpy(plaintext, buff, i);
        const size_t encrypted_length = aes_gcm_encrypt_get_length(plaintext_span);
        unsigned char* cyphertext = reinterpret_cast<unsigned char*>(malloc(encrypted_length));
        auto cyphertext_span = gsl::make_span(cyphertext, encrypted_length);
        size_t written = aes_gcm_encrypt(key, plaintext_span, cyphertext_span);
        GDK_RUNTIME_ASSERT(written == encrypted_length);

        // Decrypt
        const size_t decrypted_length = aes_gcm_decrypt_get_length(cyphertext_span);
        unsigned char* decrypted = reinterpret_cast<unsigned char*>(malloc(decrypted_length));
        auto decrypted_span = gsl::make_span(decrypted, decrypted_length);
        written = aes_gcm_decrypt(key, cyphertext_span, decrypted_span);
        GDK_RUNTIME_ASSERT(written == i);
        GDK_RUNTIME_ASSERT(memcmp(decrypted, buff, i) == 0);

        // Bad Key
        bool failed = false;
        try {
            aes_gcm_decrypt(bad_key, cyphertext_span, decrypted_span);
        } catch (const std::exception&) {
            failed = true;
        }
        GDK_RUNTIME_ASSERT(failed);

        free(plaintext);
        free(cyphertext);
        free(decrypted);
    }

    return 0;
}
