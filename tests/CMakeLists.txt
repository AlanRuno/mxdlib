# Add test executables
add_executable(mxd_crypto_tests
    test_crypto.c
)

add_executable(mxd_address_tests
    test_address.c
)

add_executable(mxd_blockchain_tests
    test_blockchain.c
)

add_executable(mxd_rsc_tests
    test_rsc.c
)

add_executable(mxd_transaction_tests
    test_transaction.c
)

add_executable(mxd_utxo_tests
    test_utxo.c
)

add_executable(mxd_mempool_tests
    test_mempool.c
)

target_link_libraries(mxd_crypto_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_address_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_blockchain_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_rsc_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_transaction_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_utxo_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_mempool_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_executable(mxd_p2p_tests
    test_p2p.c
)

target_link_libraries(mxd_p2p_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_executable(mxd_smart_contracts_tests
    test_smart_contracts.c
)

target_link_libraries(mxd_smart_contracts_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    ${WASM3_LIBRARY}
    ${UVWASI_LIBRARY}
    ${UV_LIBRARY}
)

add_test(NAME crypto_tests COMMAND mxd_crypto_tests)
add_test(NAME address_tests COMMAND mxd_address_tests)
add_test(NAME blockchain_tests COMMAND mxd_blockchain_tests)
add_test(NAME rsc_tests COMMAND mxd_rsc_tests)
add_test(NAME transaction_tests COMMAND mxd_transaction_tests)
add_test(NAME utxo_tests COMMAND mxd_utxo_tests)
add_test(NAME mempool_tests COMMAND mxd_mempool_tests)
add_test(NAME p2p_tests COMMAND mxd_p2p_tests)
add_test(NAME smart_contracts_tests COMMAND mxd_smart_contracts_tests)
