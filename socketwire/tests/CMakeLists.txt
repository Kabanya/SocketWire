include(GoogleTest)

add_executable(SocketWireTests
  test_BitStream.cpp
  test_Crypto.cpp
  test_NetSocket.cpp
  test_Performance.cpp
  test_PosixUDPSocket.cpp
  test_SocketPoller.cpp
  test_ThreadPool.cpp
  test_ReliableProtocol.cpp
  test_ReliableConnection.cpp
  test_ReliableConnection_Integration.cpp
  test_ReliableConnection_NetworkProfiles.cpp
  test_ReliableConnection_Performance.cpp
)

target_link_libraries(SocketWireTests
  PRIVATE
    SocketWire
    GTest::gtest_main
    GTest::gmock
)

target_compile_definitions(SocketWireTests PRIVATE SOCKETWIRE_TESTING=1)

gtest_discover_tests(SocketWireTests)

add_executable(SocketWireParityTests
  test_SocketWireParity.cpp
)

target_link_libraries(SocketWireParityTests
  PRIVATE
    SocketWire
)

set(SOCKETWIRE_PARITY_TEST_CASES
  Duplicate.ConnectDisconnect
  Duplicate.ReliableDelivery
  Duplicate.UnreliableDelivery
  Duplicate.ChannelSeparation
  Duplicate.FragmentedReliablePacket
  Duplicate.MultipleClients
  Duplicate.BroadcastReliable
  Duplicate.TransportStats
  Adverse.ReliableDeliveryAfterDroppedDatagrams
  Performance.ReliableBurstCompletesWithinBudget)

foreach(test_case IN LISTS SOCKETWIRE_PARITY_TEST_CASES)
  add_test(NAME "SocketWireParity.${test_case}"
    COMMAND SocketWireParityTests --case "${test_case}")
endforeach()
