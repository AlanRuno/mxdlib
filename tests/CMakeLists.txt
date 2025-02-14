# Add test executables
add_executable(mxd_crypto_tests
    test_crypto.c
)

target_link_libraries(mxd_crypto_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME crypto_tests COMMAND mxd_crypto_tests)
