# CMake generated Testfile for 
# Source directory: /home/o/feather-safe7/feather/monero/tests/block_weight
# Build directory: /home/o/feather-safe7/feather/monero/build-native/tests/block_weight
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(block_weight "/usr/sbin/python" "/home/o/feather-safe7/feather/monero/tests/block_weight/compare.py" "/usr/sbin/python" "/home/o/feather-safe7/feather/monero/tests/block_weight/block_weight.py" "/home/o/feather-safe7/feather/monero/build-native/tests/block_weight/block_weight")
set_tests_properties(block_weight PROPERTIES  _BACKTRACE_TRIPLES "/home/o/feather-safe7/feather/monero/tests/block_weight/CMakeLists.txt;43;add_test;/home/o/feather-safe7/feather/monero/tests/block_weight/CMakeLists.txt;0;")
