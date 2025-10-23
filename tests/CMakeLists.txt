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

# Authentication state machine integration tests
find_package(PolkitQt6-1 REQUIRED)
add_executable(test-authentication-state-integration
    test-authentication-state-integration.cpp
    ../src/polkit-wrapper.cpp
    ../src/logging.cpp
)

# Enable test-only methods
target_compile_definitions(test-authentication-state-integration PRIVATE BUILD_TESTING=1)

target_link_libraries(test-authentication-state-integration
    Qt6::Test
    Qt6::Core
    Qt6::Network
    PolkitQt6-1::Core
    PolkitQt6-1::Agent
)

# Add the test first
add_test(NAME AuthenticationStateIntegration COMMAND test-authentication-state-integration)

# Configure test with pam_wrapper if available
find_library(PAM_WRAPPER_LIBRARY NAMES pam_wrapper)
if(PAM_WRAPPER_LIBRARY)
    message(STATUS "Found pam_wrapper: ${PAM_WRAPPER_LIBRARY}")

    # Set up environment for PAM mocking
    set(PAM_WRAPPER_SERVICE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/pam")

    set_tests_properties(AuthenticationStateIntegration PROPERTIES
        ENVIRONMENT "PAM_WRAPPER=1;PAM_WRAPPER_SERVICE_DIR=${PAM_WRAPPER_SERVICE_DIR};LD_PRELOAD=${PAM_WRAPPER_LIBRARY}"
    )

    message(STATUS "PAM wrapper enabled for AuthenticationStateIntegration test")
    message(STATUS "  Service dir: ${PAM_WRAPPER_SERVICE_DIR}")
else()
    message(WARNING "pam_wrapper not found - some tests will be skipped")
    message(WARNING "  Install with: sudo dnf install pam_wrapper (Fedora)")
    message(WARNING "            or: sudo apt install libpam-wrapper (Debian/Ubuntu)")
endif()

# Add Python security tests
find_program(PYTHON3_EXECUTABLE python3)
if(PYTHON3_EXECUTABLE)
    # Add security test runner
    add_test(NAME SecurityTests 
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/run_security_tests.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    # Add individual security tests
    add_test(NAME FuzzIPCSocket
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/fuzz_ipc_socket.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    add_test(NAME PermissionSecurity
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/test_permissions.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    add_test(NAME ReplayAttacks
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/test_replay_attacks.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    add_test(NAME RateLimiting
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/test_rate_limiting.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    add_test(NAME AuditLogging
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/test_audit_logging.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    add_test(NAME UIConfusion
        COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/security/test_ui_confusion.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    
    message(STATUS "Python3 found: Security tests enabled")
else()
    message(WARNING "Python3 not found: Security tests disabled")
endif()

# Add custom target to run all tests
add_custom_target(run-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test-message-validator test-security test-simple-integration test-localsocket-validation test-authentication-state-integration
    COMMENT "Running all tests"
)

# Add custom target to run only security tests
add_custom_target(run-security-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure --tests-regex "Security|Fuzz|Permission|Replay|RateLimit|Audit|UIConfusion"
    COMMENT "Running security tests only"
)