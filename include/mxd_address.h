#ifndef MXD_ADDRESS_H
#define MXD_ADDRESS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Generate a random 12-word mnemonic passphrase (ISO 11889 compliant)
int mxd_generate_passphrase(char *output, size_t max_length);

// Convert a passphrase and PIN into a property key
int mxd_derive_property_key(const char *passphrase, const char *pin,
                            uint8_t property_key[64]);

// Generate public/private key pair from property key
int mxd_generate_keypair(const uint8_t property_key[64],
                         uint8_t public_key[256], uint8_t private_key[128]);

// V2 algo-aware address generation
int mxd_address_to_string_v2(uint8_t algo_id, const uint8_t *public_key, size_t pubkey_len, 
                              char *address, size_t max_length);

// Generate MXD address from public key (legacy - wraps v2 with Ed25519 default)
int mxd_generate_address(const uint8_t public_key[256], char *address,
                         size_t max_length);

// Validate an MXD address format and checksum
int mxd_validate_address(const char *address);

#ifdef __cplusplus
}
#endif

#endif // MXD_ADDRESS_H
