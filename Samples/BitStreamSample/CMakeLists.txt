cmake_minimum_required(VERSION 3.28)

add_executable(bitstream_test BitStreamTest.cpp)

target_link_libraries(bitstream_test PRIVATE BitStreamLib)