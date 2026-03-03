# Add inside external_workers/analyzer/CMakeLists.txt
enable_testing()
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(run_tests tests/test_parser.cpp packet_parser.cpp)
target_link_libraries(run_tests ${GTEST_LIBRARIES} pthread nlohmann_json::nlohmann_json)

add_test(NAME AnalyzerTests COMMAND run_tests)