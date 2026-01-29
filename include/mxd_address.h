#ifndef MXD_ADDRESS_H
#define MXD_ADDRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Generate a random 12-word mnemonic passphrase (ISO 11889 compliant)
int mxd_generate_passphrase(char *output, size_t max_length);

// Convert a passphrase and optional PIN into a property key
// NOTE: PIN is NOT used in property key derivation (passphrase only)
// PIN should be used in later key derivation steps (e.g., Argon2)
int mxd_derive_property_key(const char *passphrase, const char *pin,
                            uint8_t property_key[64]);

// Generate keypair with PIN support and algorithm selection (RECOMMENDED)
// Implements: property_key → deterministic salt → Argon2(property_key + PIN + salt) → keypair
// - algo_id: MXD_SIGALG_ED25519 or MXD_SIGALG_DILITHIUM5
// - pin: 4-6 digit PIN (can be empty string "" for no PIN)
// - Same property_key + PIN always produces same keypair (portable wallets)
int mxd_generate_keypair_with_pin(uint8_t algo_id, const uint8_t property_key[64],
                                   const char *pin, uint8_t *public_key, uint8_t *private_key);

// DEPRECATED: Generate public/private key pair from property key (Ed25519 only, no PIN)
// Use mxd_generate_keypair_with_pin() for PIN support and algorithm selection
// This function is deprecated and should only be used in legacy code or tests
__attribute__((deprecated("Use mxd_generate_keypair_with_pin() for PIN support")))
int mxd_generate_keypair(const uint8_t property_key[64],
                         uint8_t public_key[32], uint8_t private_key[64]);

// V2 algo-aware address generation (RECOMMENDED)
int mxd_address_to_string_v2(uint8_t algo_id, const uint8_t *public_key, size_t pubkey_len, 
                              char *address, size_t max_length);

// DEPRECATED: Generate MXD address from public key (legacy - wraps v2 with Ed25519 default)
// Use mxd_address_to_string_v2() for algorithm-aware address generation
__attribute__((deprecated("Use mxd_address_to_string_v2() for algorithm-aware address generation")))
int mxd_generate_address(const uint8_t public_key[256], char *address,
                         size_t max_length);

// Validate an MXD address format and checksum
int mxd_validate_address(const char *address);

// Parse an MXD address to extract algo_id and address20
// Returns 0 on success, -1 on error
// Version bytes: 0x32 for Ed25519, 0x33 for Dilithium5
int mxd_parse_address(const char *address, uint8_t *out_algo_id, uint8_t out_addr20[20]);

#ifdef __cplusplus
}
#endif

#endif // MXD_ADDRESS_H
