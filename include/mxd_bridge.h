#ifndef MXD_BRIDGE_H
#define MXD_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#define MXD_BRIDGE_MIN_CONFIRMATIONS 12
#define MXD_BRIDGE_DAILY_LIMIT 100000.0
#define MXD_BRIDGE_MAX_SINGLE_TRANSFER 10000.0
#define MXD_BRIDGE_BSC_RPC_URL "https://bsc-dataseed.binance.org/"

typedef struct {
    uint8_t bnb_tx_hash[64];
    char bnb_sender[43];
    uint8_t mxd_recipient[256];
    double amount;
    uint64_t bnb_block_number;
    uint64_t timestamp;
    uint8_t status;
    uint8_t transfer_id[32];
} mxd_bridge_transfer_t;

typedef struct {
    double daily_total;
    uint64_t reset_timestamp;
} mxd_bridge_limits_t;

typedef struct {
    char tx_hash[67];
    uint64_t block_number;
    uint64_t confirmations;
    char from_address[43];
    char to_address[43];
    char input_data[2048];
    uint8_t status;
} mxd_bsc_transaction_t;

int mxd_init_bridge(void);
void mxd_cleanup_bridge(void);

int mxd_process_bridge_transfer(const mxd_bridge_transfer_t *transfer);
int mxd_validate_bnb_transaction(const char *tx_hash, mxd_bsc_transaction_t *tx_info);
int mxd_check_daily_limits(double amount);
int mxd_mint_bridged_mxd(const uint8_t recipient_key[256], double amount);

int mxd_parse_bridge_event(const char *log_data, mxd_bridge_transfer_t *transfer);
int mxd_get_block_confirmations(uint64_t block_number, uint64_t *confirmations);
int mxd_extract_mxd_recipient(const char *input_data, uint8_t recipient_key[256]);

int mxd_store_processed_transfer(const uint8_t transfer_id[32]);
int mxd_is_transfer_processed(const uint8_t transfer_id[32]);

#endif // MXD_BRIDGE_H
