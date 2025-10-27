cmake_minimum_required(VERSION 3.28)

# Simple logging without headaches
CPMAddPackage(
  NAME spdlog
  GITHUB_REPOSITORY gabime/spdlog
  VERSION 1.15.3
  OPTIONS
    SPDLOG_USE_STD_FORMAT ON  # std::format from C++20
)

# Google Test for unit testing
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  VERSION 1.17.0
  OPTIONS
    "INSTALL_GTEST OFF"
    "gtest_force_shared_crt ON"
)

