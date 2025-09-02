#include "test_utils.h"
#include "mxd_bridge.h"
#include "mxd_transaction.h"
#include "mxd_utxo.h"
#include <assert.h>
#include <string.h>
#include <time.h>

void test_bridge_initialization() {
    TEST_START("Bridge Initialization");
    
    assert(mxd_init_bridge() == 0);
    
    mxd_cleanup_bridge();
    TEST_END("Bridge Initialization");
}

void test_daily_limits() {
    TEST_START("Daily Limits");
    
    assert(mxd_init_bridge() == 0);
    
    assert(mxd_check_daily_limits(5000.0) == 0);
    assert(mxd_check_daily_limits(10000.0) == 0);
    assert(mxd_check_daily_limits(100001.0) == -1);
    
    mxd_cleanup_bridge();
    TEST_END("Daily Limits");
}

void test_single_transfer_limits() {
    TEST_START("Single Transfer Limits");
    
    assert(mxd_init_bridge() == 0);
    
    assert(mxd_check_daily_limits(5000.0) == 0);
    assert(mxd_check_daily_limits(10000.0) == 0);
    
    assert(mxd_check_daily_limits(10001.0) == -1);
    assert(mxd_check_daily_limits(20000.0) == -1);
    
    mxd_cleanup_bridge();
    TEST_END("Single Transfer Limits");
}

void test_mxd_recipient_extraction() {
    TEST_START("MXD Recipient Extraction");
    
    const char *test_data = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    uint8_t recipient_key[256];
    
    assert(mxd_extract_mxd_recipient(test_data, recipient_key) == 0);
    
    assert(recipient_key[0] == 0x12);
    assert(recipient_key[1] == 0x34);
    assert(recipient_key[2] == 0x56);
    assert(recipient_key[3] == 0x78);
    
    TEST_END("MXD Recipient Extraction");
}

void test_transfer_processing_tracking() {
    TEST_START("Transfer Processing Tracking");
    
    assert(mxd_init_bridge() == 0);
    assert(mxd_init_utxo_db("test_bridge_tracking.db") == 0);
    
    uint8_t transfer_id[32];
    memset(transfer_id, 0xAB, 32);
    
    assert(mxd_is_transfer_processed(transfer_id) == 0);
    
    assert(mxd_store_processed_transfer(transfer_id) == 0);
    
    assert(mxd_is_transfer_processed(transfer_id) == 1);
    
    mxd_cleanup_bridge();
    TEST_END("Transfer Processing Tracking");
}

void test_bridge_event_parsing() {
    TEST_START("Bridge Event Parsing");
    
    assert(mxd_init_bridge() == 0);
    
    const char *mock_log = "{"
        "\"sender\":\"0x1234567890123456789012345678901234567890\","
        "\"mxdRecipient\":\"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab\","
        "\"amount\":\"1000000000000000000\","
        "\"transferId\":\"0x1111111111111111111111111111111111111111111111111111111111111111\","
        "\"timestamp\":1693123456"
        "}";
    
    mxd_bridge_transfer_t transfer;
    assert(mxd_parse_bridge_event(mock_log, &transfer) == 0);
    
    assert(strcmp(transfer.bnb_sender, "0x1234567890123456789012345678901234567890") == 0);
    assert(transfer.amount == 1.0);
    assert(transfer.timestamp == 1693123456);
    assert(transfer.transfer_id[0] == 0x11);
    
    mxd_cleanup_bridge();
    TEST_END("Bridge Event Parsing");
}

void test_coinbase_minting_integration() {
    TEST_START("Coinbase Minting Integration");
    
    assert(mxd_init_bridge() == 0);
    assert(mxd_init_utxo_db("test_bridge_utxo.db") == 0);
    assert(mxd_init_transaction_validation() == 0);
    
    uint8_t recipient_key[256];
    memset(recipient_key, 0x42, 256);
    
    double mint_amount = 1000.0;
    assert(mxd_mint_bridged_mxd(recipient_key, mint_amount) == 0);
    
    mxd_cleanup_bridge();
    TEST_END("Coinbase Minting Integration");
}

void test_mock_bnb_validation() {
    TEST_START("Mock BNB Validation");
    
    assert(mxd_init_bridge() == 0);
    
    mxd_bsc_transaction_t tx_info;
    const char *mock_tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12";
    
    int result = mxd_validate_bnb_transaction(mock_tx_hash, &tx_info);
    
    mxd_cleanup_bridge();
    TEST_END("Mock BNB Validation");
}

int main() {
    printf("Running MXD Bridge Tests\n");
    printf("========================\n");
    
    test_bridge_initialization();
    test_daily_limits();
    test_single_transfer_limits();
    test_mxd_recipient_extraction();
    test_transfer_processing_tracking();
    test_bridge_event_parsing();
    test_coinbase_minting_integration();
    test_mock_bnb_validation();
    
    printf("\nAll bridge tests completed successfully!\n");
    return 0;
}
