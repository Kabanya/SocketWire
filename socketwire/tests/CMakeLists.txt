cmake_minimum_required(VERSION 3.28)

include(GoogleTest)

add_executable(SocketWireTests
  test_BitStream.cpp
  test_NetSocket.cpp
  test_Performance.cpp
)

target_link_libraries(SocketWireTests
  PRIVATE
    SocketWire
    GTest::gtest_main
    GTest::gmock
)

gtest_discover_tests(SocketWireTests)
