cmake_minimum_required(VERSION 3.16)
project(quickshell-polkit-agent VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Network)

# Find polkit-qt6
find_package(PkgConfig REQUIRED)
pkg_check_modules(POLKIT_QT6 REQUIRED polkit-qt6-core-1)
pkg_check_modules(POLKIT_QT6_AGENT REQUIRED polkit-qt6-agent-1)

# Enable MOC processing
set(CMAKE_AUTOMOC ON)

# Create the executable
add_executable(quickshell-polkit-agent
    src/main.cpp
    src/polkit-wrapper.cpp
    src/polkit-wrapper.h
    src/ipc-server.cpp
    src/ipc-server.h
)

target_link_libraries(quickshell-polkit-agent
    Qt6::Core
    Qt6::Network
    ${POLKIT_QT6_LIBRARIES}
    ${POLKIT_QT6_AGENT_LIBRARIES}
)

target_include_directories(quickshell-polkit-agent PRIVATE
    ${POLKIT_QT6_INCLUDE_DIRS}
    ${POLKIT_QT6_AGENT_INCLUDE_DIRS}
)

target_compile_definitions(quickshell-polkit-agent PRIVATE
    ${POLKIT_QT6_CFLAGS_OTHER}
    ${POLKIT_QT6_AGENT_CFLAGS_OTHER}
)

# Install binary to libexec (internal service location)
install(TARGETS quickshell-polkit-agent DESTINATION libexec)

# Install systemd user service unit
install(FILES packaging/systemd/quickshell-polkit-agent.service
        DESTINATION lib/systemd/user)