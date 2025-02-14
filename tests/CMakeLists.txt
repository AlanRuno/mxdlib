# Add test executable
add_executable(mxd_tests
    test_main.c
)

target_link_libraries(mxd_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME mxd_tests COMMAND mxd_tests)
