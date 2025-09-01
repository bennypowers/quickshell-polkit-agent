cmake_minimum_required(VERSION 3.16)

# Find Qt6 Test module
find_package(Qt6 REQUIRED COMPONENTS Test Core Network Qml)

# Enable MOC processing for tests
set(CMAKE_AUTOMOC ON)

# Include parent source directory
include_directories(${CMAKE_SOURCE_DIR}/src)

# Enable testing (must come before add_test calls)
enable_testing()

# Test for MessageValidator
add_executable(test-message-validator
    test-message-validator.cpp
    ../src/message-validator.cpp
)
target_link_libraries(test-message-validator Qt6::Test Qt6::Core)
add_test(NAME MessageValidator COMMAND test-message-validator)

# Test for SecurityManager
add_executable(test-security
    test-security.cpp
    ../src/security.cpp
    ../src/logging.cpp
)
target_link_libraries(test-security Qt6::Test Qt6::Core)
add_test(NAME SecurityManager COMMAND test-security)

# Simple integration test (no polkit dependencies)
add_executable(test-simple-integration
    test-simple-integration.cpp
    ../src/message-validator.cpp
    ../src/security.cpp
    ../src/logging.cpp
)
target_link_libraries(test-simple-integration Qt6::Test Qt6::Core Qt6::Network)
add_test(NAME SimpleIntegration COMMAND test-simple-integration)

# Comprehensive E2E validation test for PolkitAgent LocalSocket implementation
add_executable(test-localsocket-validation
    test-localsocket-validation.cpp
    ../src/security.cpp
    ../src/logging.cpp
)
target_link_libraries(test-localsocket-validation Qt6::Test Qt6::Core Qt6::Network)
add_test(NAME LocalSocketValidation COMMAND test-localsocket-validation)

# Add custom target to run all tests
add_custom_target(run-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test-message-validator test-security test-simple-integration test-localsocket-validation
    COMMENT "Running all tests"
)