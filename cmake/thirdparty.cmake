cmake_minimum_required(VERSION 3.28)

# Simple logging without headaches
CPMAddPackage(
  NAME spdlog
  GITHUB_REPOSITORY gabime/spdlog
  VERSION 1.15.3
  OPTIONS
    SPDLOG_USE_STD_FORMAT ON  # std::format from C++20
)

# A profiler for both CPU and GPU
CPMAddPackage(
  GITHUB_REPOSITORY wolfpld/tracy
  GIT_TAG v0.12.2
  OPTIONS
    "TRACY_ON_DEMAND ON"
    "TRACY_NO_VULKAN ON"
)
