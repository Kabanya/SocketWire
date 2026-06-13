BUILD_DIR ?= build
BUILD_TYPE ?= Debug
CMAKE ?= cmake
CTEST ?= ctest
NETEM_SCRIPT ?= socketwire/tests/socketwire_netem.sh
NETEM_PROFILE ?= bad_wifi
NETEM_PORT ?= 15001
NETEM_PROFILE_TARGETS := netem-perfect-lan netem-normal-online netem-bad-wifi netem-high-ping netem-loss-10 netem-low-bandwidth netem-very-bad
NETEM_TEST_PROFILE_TARGETS := netem-test-perfect-lan netem-test-normal-online netem-test-bad-wifi netem-test-high-ping netem-test-loss-10 netem-test-low-bandwidth netem-test-very-bad
NETEM_COMPARE_PROFILE_TARGETS := netem-compare-perfect-lan netem-compare-normal-online netem-compare-bad-wifi netem-compare-high-ping netem-compare-loss-10 netem-compare-low-bandwidth netem-compare-very-bad
NETEM_TESTS := \
	IntegrationTest.ClientServerConnect:15001 \
	IntegrationTest.ClientServerReliableMessage:15002 \
	IntegrationTest.ClientServerMultipleMessages:15003 \
	IntegrationTest.ClientServerUnreliableMessages:15004 \
	IntegrationTest.MultipleClients:15005 \
	IntegrationTest.ClientDisconnect:15006
TEST_RESULTS_DIR ?= $(BUILD_DIR)/test-results
TEST_JUNIT ?= $(TEST_RESULTS_DIR)/junit.xml
TEST_LOG ?= $(TEST_RESULTS_DIR)/ctest.log
NETWORK_PROFILE_RESULTS ?= $(TEST_RESULTS_DIR)/network-profiles.txt
NETWORK_PROFILE_FILTER ?= ReliableConnectionNetworkProfiles.ReliableMessagesPreserveInvariantsAcrossPrProfiles:ReliableConnectionNetworkProfiles.VeryBadIsVisibleComparedToPerfectLan
PERFORMANCE_RESULTS ?= $(TEST_RESULTS_DIR)/performance.txt
PERFORMANCE_LOG ?= $(TEST_RESULTS_DIR)/performance.log
PERFORMANCE_FILTER ?= PerformanceTest.*:ReliableConnectionPerformanceTest.*
TEST_JUNIT_ABS := $(abspath $(TEST_JUNIT))
TEST_LOG_ABS := $(abspath $(TEST_LOG))
NETWORK_PROFILE_RESULTS_ABS := $(abspath $(NETWORK_PROFILE_RESULTS))
PERFORMANCE_RESULTS_ABS := $(abspath $(PERFORMANCE_RESULTS))
PERFORMANCE_LOG_ABS := $(abspath $(PERFORMANCE_LOG))

.PHONY: help configure build test test-report performance-report network-profile-demo network-profile-report netem-start netem-status netem-stop netem-help netem-test-baseline netem-test netem-compare $(NETEM_PROFILE_TARGETS) $(NETEM_TEST_PROFILE_TARGETS) $(NETEM_COMPARE_PROFILE_TARGETS) clean

help:
	@printf '%s\n' \
		'SocketWire make targets:' \
		'' \
		'  make configure                 Configure CMake build directory' \
		'  make build                     Configure and build the project' \
		'  make test                      Build and run all CTest tests' \
		'  make test-report               Run tests and write junit/log files' \
		'  make performance-report        Run perf tests and write metrics' \
		'  make network-profile-demo      Show visible perfect_lan vs very_bad metrics' \
		'  make network-profile-report    Write network profile results to txt' \
		'  make clean                     Remove the build directory' \
		'' \
		'Netem controls:' \
		'  make netem-help                Show available network profiles' \
		'  make netem-status              Show active pf/dnctl rules' \
		'  make netem-stop                Disable active SocketWire netem rules' \
		'  make netem-start NETEM_PROFILE=bad_wifi NETEM_PORT=15001' \
		'' \
		'Netem profile shortcuts:' \
		'  make netem-bad-wifi NETEM_PORT=15001' \
		'  make netem-very-bad NETEM_PORT=15001' \
		'  make netem-high-ping NETEM_PORT=15001' \
		'' \
		'Integration tests with matching ports:' \
		'  sudo -v && make netem-test-very-bad' \
		'  sudo -v && make netem-compare-very-bad' \
		'  make netem-test-baseline'

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(BUILD_TYPE)

build: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: build
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure

test-report: build
	$(CMAKE) -E make_directory $(TEST_RESULTS_DIR)
	$(CTEST) --test-dir $(BUILD_DIR) --output-on-failure --output-junit $(TEST_JUNIT_ABS) -O $(TEST_LOG_ABS)

performance-report: build
	$(CMAKE) -E make_directory $(TEST_RESULTS_DIR)
	@echo "Writing performance results to $(PERFORMANCE_RESULTS_ABS)"
	@: > "$(PERFORMANCE_RESULTS_ABS)"
	@bash -o pipefail -c 'SOCKETWIRE_PERF_RESULTS="$(PERFORMANCE_RESULTS_ABS)" ./$(BUILD_DIR)/socketwire/tests/SocketWireTests --gtest_filter="$(PERFORMANCE_FILTER)" | tee "$(PERFORMANCE_LOG_ABS)"'

network-profile-demo: build
	./$(BUILD_DIR)/socketwire/tests/SocketWireTests --gtest_filter=ReliableConnectionNetworkProfiles.VeryBadIsVisibleComparedToPerfectLan

network-profile-report: build
	$(CMAKE) -E make_directory $(TEST_RESULTS_DIR)
	@echo "Writing network profile results to $(NETWORK_PROFILE_RESULTS_ABS)"
	@bash -o pipefail -c './$(BUILD_DIR)/socketwire/tests/SocketWireTests --gtest_filter="$(NETWORK_PROFILE_FILTER)" | tee "$(NETWORK_PROFILE_RESULTS_ABS)"'

netem-start:
	./$(NETEM_SCRIPT) start $(NETEM_PROFILE) $(NETEM_PORT)

netem-status:
	./$(NETEM_SCRIPT) status

netem-stop:
	./$(NETEM_SCRIPT) stop

netem-help:
	./$(NETEM_SCRIPT) help

$(NETEM_PROFILE_TARGETS):
	./$(NETEM_SCRIPT) start $(subst -,_,$(patsubst netem-%,%,$@)) $(NETEM_PORT)

netem-test-baseline: build
	@set -e; \
	echo "==> Running integration tests without netem"; \
	for test_case in $(NETEM_TESTS); do \
		test_name=$${test_case%%:*}; \
		test_port=$${test_case##*:}; \
		echo "==> $$test_name without netem (UDP $$test_port)"; \
		$(CTEST) --test-dir $(BUILD_DIR) -R "^$$test_name$$" --output-on-failure; \
	done

netem-test: build
	@set -e; \
	trap './$(NETEM_SCRIPT) stop >/dev/null 2>&1 || true' EXIT; \
	for test_case in $(NETEM_TESTS); do \
		test_name=$${test_case%%:*}; \
		test_port=$${test_case##*:}; \
		echo "==> $$test_name via $(NETEM_PROFILE) on UDP $$test_port"; \
		./$(NETEM_SCRIPT) start $(NETEM_PROFILE) $$test_port; \
		$(CTEST) --test-dir $(BUILD_DIR) -R "^$$test_name$$" --output-on-failure; \
	done

$(NETEM_TEST_PROFILE_TARGETS):
	$(MAKE) netem-test NETEM_PROFILE=$(subst -,_,$(patsubst netem-test-%,%,$@))

netem-compare: build
	@set -e; \
	./$(NETEM_SCRIPT) stop >/dev/null 2>&1 || true; \
	echo "==> Running integration tests without netem"; \
	for test_case in $(NETEM_TESTS); do \
		test_name=$${test_case%%:*}; \
		test_port=$${test_case##*:}; \
		echo "==> $$test_name without netem (UDP $$test_port)"; \
		$(CTEST) --test-dir $(BUILD_DIR) -R "^$$test_name$$" --output-on-failure; \
	done; \
	echo "==> Running integration tests with $(NETEM_PROFILE)"; \
	trap './$(NETEM_SCRIPT) stop >/dev/null 2>&1 || true' EXIT; \
	for test_case in $(NETEM_TESTS); do \
		test_name=$${test_case%%:*}; \
		test_port=$${test_case##*:}; \
		echo "==> $$test_name via $(NETEM_PROFILE) on UDP $$test_port"; \
		./$(NETEM_SCRIPT) start $(NETEM_PROFILE) $$test_port; \
		$(CTEST) --test-dir $(BUILD_DIR) -R "^$$test_name$$" --output-on-failure; \
	done

$(NETEM_COMPARE_PROFILE_TARGETS):
	$(MAKE) netem-compare NETEM_PROFILE=$(subst -,_,$(patsubst netem-compare-%,%,$@))

clean:
	$(CMAKE) -E rm -rf $(BUILD_DIR)
