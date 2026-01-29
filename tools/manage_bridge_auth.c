/**
 * @file manage_bridge_auth.c
 * @brief CLI tool to manage bridge contract authorizations
 *
 * Usage:
 *   manage_bridge_auth --add <contract_hash> [--db-path <path>]
 *   manage_bridge_auth --revoke <contract_hash> [--db-path <path>]
 *   manage_bridge_auth --list [--db-path <path>]
 *   manage_bridge_auth --check <contract_hash> [--db-path <path>]
 */

#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define DEFAULT_DB_PATH "./mxd_blockchain.db"

static void print_usage(const char *prog_name) {
    printf("Usage: %s <command> <contract_hash> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  --add <hash>      Authorize a bridge contract\n");
    printf("  --revoke <hash>   Revoke a bridge contract authorization\n");
    printf("  --list            List all authorized bridge contracts\n");
    printf("  --check <hash>    Check if a contract is authorized\n\n");
    printf("Options:\n");
    printf("  --db-path <path>  Path to blockchain database (default: %s)\n", DEFAULT_DB_PATH);
    printf("  --help            Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s --add abc123...def456\n", prog_name);
    printf("  %s --revoke abc123...def456\n", prog_name);
    printf("  %s --list\n", prog_name);
    printf("  %s --check abc123...def456\n", prog_name);
}

// Convert hex string to bytes
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t bytes_len) {
    if (!hex || !bytes) return -1;

    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    return 0;
}

// Convert bytes to hex string
static void bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[bytes_len * 2] = '\0';
}

// Authorize a bridge contract
static int authorize_contract(rocksdb_t *db, const uint8_t contract_hash[64]) {
    // Create key: "bridge_auth:" + contract_hash
    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, contract_hash, 64);

    // Value: "1" for authorized
    const char *value = "1";

    rocksdb_writeoptions_t *writeopts = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(db, writeopts, (const char *)key, 76, value, 1, &err);

    rocksdb_writeoptions_destroy(writeopts);

    if (err) {
        fprintf(stderr, "Error authorizing contract: %s\n", err);
        free(err);
        return -1;
    }

    char hex_hash[129];
    bytes_to_hex(contract_hash, 64, hex_hash);
    printf("Successfully authorized bridge contract: %s\n", hex_hash);

    return 0;
}

// Revoke a bridge contract authorization
static int revoke_contract(rocksdb_t *db, const uint8_t contract_hash[64]) {
    // Create key: "bridge_auth:" + contract_hash
    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, contract_hash, 64);

    // Value: "0" for revoked
    const char *value = "0";

    rocksdb_writeoptions_t *writeopts = rocksdb_writeoptions_create();
    char *err = NULL;

    rocksdb_put(db, writeopts, (const char *)key, 76, value, 1, &err);

    rocksdb_writeoptions_destroy(writeopts);

    if (err) {
        fprintf(stderr, "Error revoking contract: %s\n", err);
        free(err);
        return -1;
    }

    char hex_hash[129];
    bytes_to_hex(contract_hash, 64, hex_hash);
    printf("Successfully revoked bridge contract: %s\n", hex_hash);

    return 0;
}

// Check if a contract is authorized
static int check_contract(rocksdb_t *db, const uint8_t contract_hash[64]) {
    // Create key: "bridge_auth:" + contract_hash
    uint8_t key[76];
    memcpy(key, "bridge_auth:", 12);
    memcpy(key + 12, contract_hash, 64);

    rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
    char *err = NULL;
    size_t val_len;

    char *value = rocksdb_get(db, readopts, (const char *)key, 76, &val_len, &err);

    rocksdb_readoptions_destroy(readopts);

    if (err) {
        fprintf(stderr, "Error checking contract: %s\n", err);
        free(err);
        return -1;
    }

    char hex_hash[129];
    bytes_to_hex(contract_hash, 64, hex_hash);

    if (value) {
        int authorized = (val_len > 0 && value[0] == '1');
        printf("Contract %s: %s\n", hex_hash, authorized ? "AUTHORIZED" : "REVOKED");
        free(value);
        return authorized ? 0 : 1;
    } else {
        printf("Contract %s: NOT FOUND (not authorized)\n", hex_hash);
        return 1;
    }
}

// List all authorized contracts
static int list_contracts(rocksdb_t *db) {
    rocksdb_readoptions_t *readopts = rocksdb_readoptions_create();
    rocksdb_iterator_t *iter = rocksdb_create_iterator(db, readopts);

    const char *prefix = "bridge_auth:";
    rocksdb_iter_seek(iter, prefix, strlen(prefix));

    int count = 0;
    printf("Authorized Bridge Contracts:\n");
    printf("========================================\n");

    while (rocksdb_iter_valid(iter)) {
        size_t key_len, val_len;
        const char *key = rocksdb_iter_key(iter, &key_len);
        const char *val = rocksdb_iter_value(iter, &val_len);

        // Check if key starts with prefix
        if (key_len < strlen(prefix) || memcmp(key, prefix, strlen(prefix)) != 0) {
            break;
        }

        // Extract contract hash (skip "bridge_auth:" prefix)
        if (key_len == 76) {
            uint8_t contract_hash[64];
            memcpy(contract_hash, key + 12, 64);

            char hex_hash[129];
            bytes_to_hex(contract_hash, 64, hex_hash);

            int authorized = (val_len > 0 && val[0] == '1');
            printf("%d. %s [%s]\n", ++count, hex_hash, authorized ? "ACTIVE" : "REVOKED");
        }

        rocksdb_iter_next(iter);
    }

    if (count == 0) {
        printf("(No authorized bridge contracts found)\n");
    }

    rocksdb_iter_destroy(iter);
    rocksdb_readoptions_destroy(readopts);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *db_path = DEFAULT_DB_PATH;
    const char *contract_hash_hex = NULL;
    enum {
        CMD_NONE,
        CMD_ADD,
        CMD_REVOKE,
        CMD_CHECK,
        CMD_LIST
    } command = CMD_NONE;

    // Parse command line arguments
    static struct option long_options[] = {
        {"add", required_argument, 0, 'a'},
        {"revoke", required_argument, 0, 'r'},
        {"check", required_argument, 0, 'c'},
        {"list", no_argument, 0, 'l'},
        {"db-path", required_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "a:r:c:ld:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                command = CMD_ADD;
                contract_hash_hex = optarg;
                break;
            case 'r':
                command = CMD_REVOKE;
                contract_hash_hex = optarg;
                break;
            case 'c':
                command = CMD_CHECK;
                contract_hash_hex = optarg;
                break;
            case 'l':
                command = CMD_LIST;
                break;
            case 'd':
                db_path = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (command == CMD_NONE) {
        fprintf(stderr, "Error: No command specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // Initialize logging
    mxd_set_log_level(MXD_LOG_LEVEL_INFO);

    // Open database
    rocksdb_options_t *options = rocksdb_options_create();
    rocksdb_options_set_create_if_missing(options, 1);

    char *err = NULL;
    rocksdb_t *db = rocksdb_open(options, db_path, &err);

    if (err) {
        fprintf(stderr, "Error opening database: %s\n", err);
        free(err);
        rocksdb_options_destroy(options);
        return 1;
    }

    // Set global database reference
    mxd_set_rocksdb_db(db);

    int result = 0;

    // Execute command
    switch (command) {
        case CMD_ADD: {
            if (!contract_hash_hex || strlen(contract_hash_hex) != 128) {
                fprintf(stderr, "Error: Invalid contract hash (must be 128 hex characters)\n");
                result = 1;
                break;
            }

            uint8_t contract_hash[64];
            if (hex_to_bytes(contract_hash_hex, contract_hash, 64) != 0) {
                fprintf(stderr, "Error: Failed to parse contract hash\n");
                result = 1;
                break;
            }

            result = authorize_contract(db, contract_hash);
            break;
        }

        case CMD_REVOKE: {
            if (!contract_hash_hex || strlen(contract_hash_hex) != 128) {
                fprintf(stderr, "Error: Invalid contract hash (must be 128 hex characters)\n");
                result = 1;
                break;
            }

            uint8_t contract_hash[64];
            if (hex_to_bytes(contract_hash_hex, contract_hash, 64) != 0) {
                fprintf(stderr, "Error: Failed to parse contract hash\n");
                result = 1;
                break;
            }

            result = revoke_contract(db, contract_hash);
            break;
        }

        case CMD_CHECK: {
            if (!contract_hash_hex || strlen(contract_hash_hex) != 128) {
                fprintf(stderr, "Error: Invalid contract hash (must be 128 hex characters)\n");
                result = 1;
                break;
            }

            uint8_t contract_hash[64];
            if (hex_to_bytes(contract_hash_hex, contract_hash, 64) != 0) {
                fprintf(stderr, "Error: Failed to parse contract hash\n");
                result = 1;
                break;
            }

            result = check_contract(db, contract_hash);
            break;
        }

        case CMD_LIST:
            result = list_contracts(db);
            break;

        default:
            break;
    }

    // Cleanup
    rocksdb_close(db);
    rocksdb_options_destroy(options);

    return result;
}
