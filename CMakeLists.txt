cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS
            "src/nltp_core.c"
            "src/nltp_net.c"
            "src/nltp_sha256.c"
        INCLUDE_DIRS
            "src"
        PRIV_REQUIRES
            esp_timer
            esp_wifi
    )
else()
    project(nltp VERSION 1.6.0 LANGUAGES C)

    set(CMAKE_C_STANDARD 99)
    set(CMAKE_C_STANDARD_REQUIRED ON)
    set(CMAKE_C_EXTENSIONS OFF)

    add_library(nltp STATIC
        src/nltp_core.c
        src/nltp_net.c
        src/nltp_sha256.c
    )
    target_include_directories(nltp PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    )

    option(NLTP_BUILD_TESTS "Build NLTP cryptographic KAT and protocol test suite" ON)
    if(NLTP_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_kat_vectors.c")
        enable_testing()
        add_executable(test_kat_vectors tests/test_kat_vectors.c)
        target_link_libraries(test_kat_vectors PRIVATE nltp)
        add_test(NAME test_kat_vectors COMMAND test_kat_vectors)
    endif()
endif()
