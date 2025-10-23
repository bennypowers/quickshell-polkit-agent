cmake_minimum_required(VERSION 3.16)

# Build mock PAM module for FIDO testing
# This module simulates FIDO authentication for testing without hardware

find_package(PkgConfig)
pkg_check_modules(PAM pam)

if(PAM_FOUND)
    # Build pam_fido_mock.so
    add_library(pam_fido_mock MODULE pam_fido_mock.c)

    target_include_directories(pam_fido_mock PRIVATE ${PAM_INCLUDE_DIRS})
    target_link_libraries(pam_fido_mock ${PAM_LIBRARIES})

    # PAM modules should not have lib prefix
    set_target_properties(pam_fido_mock PROPERTIES
        PREFIX ""
        OUTPUT_NAME "pam_fido_mock"
    )

    message(STATUS "PAM mock module will be built: pam_fido_mock.so")
else()
    message(WARNING "PAM development files not found - pam_fido_mock.so will not be built")
endif()
