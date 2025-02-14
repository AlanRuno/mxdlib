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
    // Implementation of Base58Check encoding
    // This is a simplified version - in production we would need a more robust implementation
    uint8_t count = 0;
    size_t i, j;
    uint32_t carry;
    uint8_t *digits = calloc(data_len * 2, sizeof(uint8_t));
    
    if (!digits) return -1;
    
    for (i = 0; i < data_len; ++i) {
        carry = data[i];
        for (j = 0; j < count; ++j) {
            carry += digits[j] * 256;
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits[count++] = carry % 58;
            carry /= 58;
        }
    }
    
    if (count >= max_length) {
        free(digits);
        return -1;
    }
    
    // Convert to actual Base58 characters
    for (i = 0; i < count; ++i) {
        output[i] = BASE58_ALPHABET[digits[count - 1 - i]];
    }
    output[count] = '\0';
    
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
    uint8_t address_bytes[22];

    // Double SHA-512 on public key
    if (mxd_sha512(public_key, 256, sha_output) != 0 ||
        mxd_sha512(sha_output, 64, sha_output) != 0) {
        return -1;
    }

    // RIPEMD-160 on the double SHA-512 output
    if (mxd_ripemd160(sha_output, 64, ripemd_output) != 0) {
        return -1;
    }

    // Prepare address bytes with "mx" prefix
    address_bytes[0] = 'm';
    address_bytes[1] = 'x';
    memcpy(address_bytes + 2, ripemd_output, 20);

    // Encode in Base58Check
    return base58_encode(address_bytes, 22, address, max_length);
}

int mxd_validate_address(const char *address) {
    if (!address || strlen(address) > 42) {
        return -1;
    }

    // Check prefix
    if (address[0] != '1' || // Base58 encoding of 'mx' prefix
        strlen(address) < 25) { // Minimum length for valid address
        return -1;
    }

    // TODO: Implement full Base58Check decoding and validation
    return 0;
}
