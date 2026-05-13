BUILD_DIR ?= build
BUILD_TYPE ?= Debug
CMAKE ?= cmake
CTEST ?= ctest

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: build
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure

test-all: build
	$(BUILD_DIR)/socketwire/tests/SocketWireTests --gtest_also_run_disabled_tests

clean:
	$(CMAKE) -E rm -rf $(BUILD_DIR)
