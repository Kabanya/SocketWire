cmake_minimum_required(VERSION 3.28)

add_library(BitStreamLib STATIC
  BitStream.cpp
  BitStream.h
)

target_include_directories(BitStreamLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})