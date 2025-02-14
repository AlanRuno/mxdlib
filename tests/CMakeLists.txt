# Add test executables
add_executable(mxd_crypto_tests
    test_crypto.c
)

add_executable(mxd_address_tests
    test_address.c
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

add_test(NAME crypto_tests COMMAND mxd_crypto_tests)
add_test(NAME address_tests COMMAND mxd_address_tests)
