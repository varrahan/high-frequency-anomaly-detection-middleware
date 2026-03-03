add_executable(run_tests 
    test_parser.cpp
    ../packet_parser.cpp
)

if(nlohmann_json_FOUND)
    target_link_libraries(run_tests PRIVATE nlohmann_json::nlohmann_json)
else()
    target_include_directories(run_tests PRIVATE ${CMAKE_SOURCE_DIR}/external)
endif()

find_package(GTest REQUIRED)
target_include_directories(run_tests PRIVATE ${GTEST_INCLUDE_DIRS})
target_link_libraries(run_tests PRIVATE GTest::gtest_main GTest::gtest pthread)
target_include_directories(run_tests PRIVATE ${HIREDIS_INCLUDE})
target_link_libraries(run_tests PRIVATE ${HIREDIS_LIB} CURL::libcurl)

include(GoogleTest)
gtest_discover_tests(run_tests)