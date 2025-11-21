include(GoogleTest)

add_executable(SocketWireTests
  test_BitStream.cpp
  # test_Crypto.cpp
  test_NetSocket.cpp
  test_Performance.cpp
  test_PosixUDPSocket.cpp
  test_SocketPoller.cpp
  test_ReliableConnection.cpp
  test_ReliableConnection_Integration.cpp
  test_ReliableConnection_Performance.cpp
)

target_link_libraries(SocketWireTests
  PRIVATE
    SocketWire
    GTest::gtest_main
    GTest::gmock
)

gtest_discover_tests(SocketWireTests)

# temp target
add_custom_target(dump_test_results
  COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/test_results_to_txt.py --build-dir ${CMAKE_BINARY_DIR} --output ${CMAKE_BINARY_DIR}/test-results.txt
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  COMMENT "Run CTest and write a human-readable test-results.txt to the build directory"
)
