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
    for (size_t i = 0; i < data_len && data[i] == 0; i++) {
        zeros++;
    }

    // Handle special case for all zeros
    if (zeros == data_len) {
        if (zeros + 1 > max_length) {
            return -1;
        }
        memset(output, '1', zeros);
        output[zeros] = '\0';
        return 0;
    }

    // Initialize result array with zeros
    uint8_t b58[512] = {0};
    size_t b58_len = 0;

    // Convert from base256 to base58
    for (size_t i = zeros; i < data_len; i++) {
        uint32_t carry = data[i];
        size_t j;

        // Apply base conversion for each byte
        for (j = 0; j < b58_len; j++) {
            carry += (uint32_t)b58[j] * 256;
            b58[j] = carry % 58;
            carry /= 58;
        }

        // Add new digits
        while (carry > 0 && b58_len < sizeof(b58)) {
            b58[b58_len++] = carry % 58;
            carry /= 58;
        }
    }

    // If no non-zero bytes found, b58_len will be 0
    if (b58_len == 0) {
        b58_len = 1;  // Ensure we have at least one digit for non-zero inputs
    }

    // Check output buffer size
    if (zeros + b58_len + 1 > max_length) {
        return -1;
    }

    // Write leading '1's for zeros
    memset(output, '1', zeros);

    // Convert digits to Base58 alphabet in reverse order
    for (size_t i = 0; i < b58_len; i++) {
        output[zeros + i] = BASE58_ALPHABET[b58[b58_len - 1 - i]];
    }
    output[zeros + b58_len] = '\0';

    return 0;
}

int mxd_generate_address(const uint8_t public_key[256],
                        char *address, size_t max_length) {
    if (!public_key || !address || max_length < 42) {
        return -1;
    }

    uint8_t sha_output[64] = {0};
    uint8_t ripemd_output[20] = {0};
    uint8_t address_bytes[25] = {0}; // Version(1) + RIPEMD160(20) + Checksum(4)

    // First SHA-512 on public key
    if (mxd_sha512(public_key, 256, sha_output) != 0) {
        return -1;
    }

    // Second SHA-512
    if (mxd_sha512(sha_output, 64, sha_output) != 0) {
        return -1;
    }

    // RIPEMD-160 on the double SHA-512 output
    if (mxd_ripemd160(sha_output, 64, ripemd_output) != 0) {
        return -1;
    }

    // Version byte (0x32 = 50 in decimal, unique to MXD)
    address_bytes[0] = 0x32;

    // RIPEMD-160 hash
    memcpy(address_bytes + 1, ripemd_output, 20);

    // Calculate checksum (double SHA-512 of version + hash)
    uint8_t checksum[64];
    if (mxd_sha512(address_bytes, 21, checksum) != 0) {
        return -1;
    }
    if (mxd_sha512(checksum, 64, checksum) != 0) {
        return -1;
    }

    // Add 4-byte checksum
    memcpy(address_bytes + 21, checksum, 4);

    // Encode in Base58Check
    return base58_encode(address_bytes, 25, address, max_length);
}

static int base58_decode(const char *input, uint8_t *output, size_t *output_len) {
    if (!input || !output || !output_len || *output_len == 0) {
        return -1;
    }

    size_t input_len = strlen(input);
    if (input_len == 0) {
        return -1;
    }

    // Count leading '1's
    size_t zeros = 0;
    for (size_t i = 0; i < input_len && input[i] == '1'; i++) {
        zeros++;
    }

    // Handle special case for all zeros
    if (zeros == input_len) {
        if (zeros > *output_len) {
            return -1;
        }
        memset(output, 0, zeros);
        *output_len = zeros;
        return 0;
    }

    // Convert from base58 to base256
    uint8_t digits[512] = {0};
    size_t digitslen = 1;

    // Process each input character
    for (size_t i = zeros; i < input_len; i++) {
        // Lookup value in alphabet
        const char *pos = strchr(BASE58_ALPHABET, input[i]);
        if (!pos) {
            return -1;
        }
        uint32_t carry = pos - BASE58_ALPHABET;

        // Multiply existing digits by 58 and add new digit
        for (size_t j = 0; j < digitslen; j++) {
            carry += (uint32_t)digits[j] * 58;
            digits[j] = carry & 0xFF;
            carry >>= 8;
        }

        // Add new digits
        while (carry > 0) {
            digits[digitslen++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    // Check output buffer size
    if (zeros + digitslen > *output_len) {
        return -1;
    }

    // Write leading zeros
    memset(output, 0, zeros);

    // Copy digits in reverse order
    for (size_t i = 0; i < digitslen; i++) {
        output[zeros + i] = digits[digitslen - 1 - i];
    }

    *output_len = zeros + digitslen;
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
