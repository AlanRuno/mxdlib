#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include <sodium.h>
#include <string.h>

// First 64 words from BIP39 wordlist (truncated for testing)
static const char *BIP39_WORDS[] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among"
};

int mxd_generate_passphrase(char *output, size_t max_length) {
    if (!output || max_length < 120) { // Minimum length for 12 words
        return -1;
    }

    uint8_t entropy[16];
    randombytes_buf(entropy, sizeof(entropy));

    // Generate 12 random words
    size_t offset = 0;
    const size_t num_words = sizeof(BIP39_WORDS) / sizeof(BIP39_WORDS[0]);
    
    for (int i = 0; i < 12 && i < sizeof(entropy); i++) {
        uint8_t rand_byte = entropy[i];
        uint8_t index = rand_byte % num_words;
        const char *word = BIP39_WORDS[index];
        size_t word_len = strlen(word);
        
        // Check if we have space for word + space + null terminator
        if (offset + word_len + 2 > max_length) {
            output[0] = '\0';
            return -1;
        }
        
        if (i > 0) {
            output[offset++] = ' ';
        }
        
        memcpy(output + offset, word, word_len);
        offset += word_len;
    }
    output[offset] = '\0';
    
    return 0;
}

int mxd_derive_property_key(const char *passphrase, const char *pin,
                           uint8_t property_key[64]) {
    if (!passphrase || !pin || !property_key) {
        return -1;
    }

    // Double SHA-512 on passphrase
    if (mxd_sha512((const uint8_t*)passphrase, strlen(passphrase), property_key) != 0) {
        return -1;
    }
    if (mxd_sha512(property_key, 64, property_key) != 0) {
        return -1;
    }

    return 0;
}

int mxd_generate_keypair(const uint8_t property_key[64],
                        uint8_t public_key[256],
                        uint8_t private_key[128]) {
    if (!property_key || !public_key || !private_key) {
        return -1;
    }

    // First derive the private key using Argon2
    static const uint8_t DERIVATION_SALT[16] = "MXDKeyDerivation";
    if (mxd_argon2((const char*)property_key, DERIVATION_SALT, private_key, 128) != 0) {
        return -1;
    }

    // Generate Dilithium keypair
    return mxd_dilithium_keygen(public_key, private_key);
}

// Helper function for Base58Check encoding
static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int base58_encode(const uint8_t *data, size_t data_len, char *output, size_t max_length) {
    if (!data || !output || data_len == 0 || max_length == 0) {
        return -1;
    }

    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) {
        zeros++;
    }

    // Allocate enough space for the worst case
    size_t size = (data_len - zeros) * 138 / 100 + 1;
    uint8_t *digits = calloc(size, sizeof(uint8_t));
    if (!digits) return -1;

    size_t digits_len = 0;
    
    // Convert to base-58 digits
    for (size_t i = zeros; i < data_len; i++) {
        uint32_t carry = data[i];
        for (size_t j = 0; j < digits_len; j++) {
            carry += (uint32_t)digits[j] << 8;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            if (digits_len >= size) {
                free(digits);
                return -1;
            }
            digits[digits_len++] = carry % 58;
            carry /= 58;
        }
    }

    // Check output buffer size
    if (zeros + digits_len + 1 > max_length) {
        free(digits);
        return -1;
    }

    // Write leading '1's for zeros
    size_t out_pos = 0;
    for (size_t i = 0; i < zeros; i++) {
        output[out_pos++] = '1';
    }

    // Convert digits to characters
    for (size_t i = 0; i < digits_len; i++) {
        output[out_pos + digits_len - 1 - i] = BASE58_ALPHABET[digits[i]];
    }
    output[out_pos + digits_len] = '\0';

    free(digits);
    return 0;
}

int mxd_generate_address(const uint8_t public_key[256],
                        char *address, size_t max_length) {
    if (!public_key || !address || max_length < 42) {
        return -1;
    }

    uint8_t sha_output[64];
    uint8_t ripemd_output[20];
    uint8_t address_bytes[25]; // Version(1) + RIPEMD160(20) + Checksum(4)

    // Double SHA-512 on public key
    if (mxd_sha512(public_key, 256, sha_output) != 0 ||
        mxd_sha512(sha_output, 64, sha_output) != 0) {
        return -1;
    }

    // RIPEMD-160 on the double SHA-512 output
    if (mxd_ripemd160(sha_output, 64, ripemd_output) != 0) {
        return -1;
    }

    // Version byte
    address_bytes[0] = 0x32; // MXD version byte

    // RIPEMD-160 hash
    memcpy(address_bytes + 1, ripemd_output, 20);

    // Calculate checksum (double SHA-512 of version + hash)
    if (mxd_sha512(address_bytes, 21, sha_output) != 0 ||
        mxd_sha512(sha_output, 64, sha_output) != 0) {
        return -1;
    }

    // Add 4-byte checksum
    memcpy(address_bytes + 21, sha_output, 4);

    // Encode in Base58Check
    return base58_encode(address_bytes, 25, address, max_length);
}

static int base58_decode(const char *input, uint8_t *output, size_t *output_len) {
    size_t input_len = strlen(input);
    if (input_len == 0) return -1;

    // Initialize output array
    memset(output, 0, *output_len);
    size_t out_pos = 0;

    // Process each input character
    for (size_t i = 0; i < input_len; i++) {
        unsigned char c = input[i];
        const char *pos = strchr(BASE58_ALPHABET, c);
        if (!pos) return -1; // Invalid character

        int val = pos - BASE58_ALPHABET;
        for (size_t j = 0; j < out_pos; j++) {
            int carry = output[j] * 58 + val;
            output[j] = carry & 0xff;
            val = carry >> 8;
        }
        if (val > 0) {
            if (out_pos >= *output_len) return -1;
            output[out_pos++] = val;
        }
    }

    // Count leading zeros in input
    size_t zeros = 0;
    while (zeros < input_len && input[zeros] == '1') {
        zeros++;
    }

    // Add leading zeros to output
    if (zeros + out_pos > *output_len) return -1;
    memmove(output + zeros, output, out_pos);
    memset(output, 0, zeros);
    *output_len = zeros + out_pos;

    return 0;
}

int mxd_validate_address(const char *address) {
    if (!address) return -1;

    size_t address_len = strlen(address);
    if (address_len < 25 || address_len > 42) return -1;

    // Decode Base58 address
    uint8_t decoded[25];
    size_t decoded_len = sizeof(decoded);
    if (base58_decode(address, decoded, &decoded_len) != 0 || decoded_len != 25) {
        return -1;
    }

    // Check version byte
    if (decoded[0] != 0x32) { // MXD version byte
        return -1;
    }

    // Verify checksum
    uint8_t sha_output[64];
    if (mxd_sha512(decoded, 21, sha_output) != 0 ||
        mxd_sha512(sha_output, 64, sha_output) != 0) {
        return -1;
    }

    // Compare checksum
    return memcmp(decoded + 21, sha_output, 4) == 0 ? 0 : -1;
}
