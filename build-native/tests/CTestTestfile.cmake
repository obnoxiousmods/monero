# CMake generated Testfile for 
# Source directory: /home/o/feather-safe7/feather/monero/tests
# Build directory: /home/o/feather-safe7/feather/monero/build-native/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(hash-target "/home/o/feather-safe7/feather/monero/build-native/tests/hash-target-tests")
set_tests_properties(hash-target PROPERTIES  _BACKTRACE_TRIPLES "/home/o/feather-safe7/feather/monero/tests/CMakeLists.txt;116;add_test;/home/o/feather-safe7/feather/monero/tests/CMakeLists.txt;0;")
add_test(wallet-crypto-bench "/home/o/feather-safe7/feather/monero/build-native/tests/monero-wallet-crypto-bench")
set_tests_properties(wallet-crypto-bench PROPERTIES  _BACKTRACE_TRIPLES "/home/o/feather-safe7/feather/monero/tests/CMakeLists.txt;152;add_test;/home/o/feather-safe7/feather/monero/tests/CMakeLists.txt;0;")
subdirs("core_tests")
subdirs("fuzz")
subdirs("crypto")
subdirs("functional_tests")
subdirs("performance_tests")
subdirs("unit_tests")
subdirs("difficulty")
subdirs("block_weight")
subdirs("hash")
subdirs("net_load_tests")
