cmake_minimum_required(VERSION 3.22)
project(analyzer_worker VERSION 1.0 LANGUAGES CXX)

add_compile_options(-Wall -Wextra -O2 -pthread)
add_link_options(-pthread)

add_executable(analyzer
    main.cpp
    packet_parser.cpp
)

find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
    target_link_libraries(analyzer PRIVATE nlohmann_json::nlohmann_json)
else()
    message(STATUS "nlohmann/json not found via CMake; expecting header at "
                   "${CMAKE_SOURCE_DIR}/external/nlohmann/json.hpp")
    target_include_directories(analyzer PRIVATE ${CMAKE_SOURCE_DIR}/external)
endif()

find_library(HIREDIS_LIB hiredis REQUIRED)
find_path(HIREDIS_INCLUDE hiredis/hiredis.h)
target_include_directories(analyzer PRIVATE ${HIREDIS_INCLUDE})
target_link_libraries(analyzer PRIVATE ${HIREDIS_LIB})
find_package(CURL REQUIRED)
target_link_libraries(analyzer PRIVATE CURL::libcurl)
install(TARGETS analyzer DESTINATION bin)