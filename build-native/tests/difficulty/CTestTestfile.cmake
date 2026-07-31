# CMake generated Testfile for 
# Source directory: /home/o/feather-safe7/feather/monero/tests/difficulty
# Build directory: /home/o/feather-safe7/feather/monero/build-native/tests/difficulty
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(difficulty "/home/o/feather-safe7/feather/monero/build-native/tests/difficulty/difficulty-tests" "/home/o/feather-safe7/feather/monero/tests/difficulty/data.txt")
set_tests_properties(difficulty PROPERTIES  _BACKTRACE_TRIPLES "/home/o/feather-safe7/feather/monero/tests/difficulty/CMakeLists.txt;45;add_test;/home/o/feather-safe7/feather/monero/tests/difficulty/CMakeLists.txt;0;")
add_test(wide_difficulty "/usr/sbin/python" "/home/o/feather-safe7/feather/monero/tests/difficulty/wide_difficulty.py" "/usr/sbin/python" "/home/o/feather-safe7/feather/monero/tests/difficulty/gen_wide_data.py" "/home/o/feather-safe7/feather/monero/build-native/tests/difficulty/difficulty-tests" "/home/o/feather-safe7/feather/monero/build-native/tests/difficulty/wide_data.txt")
set_tests_properties(wide_difficulty PROPERTIES  _BACKTRACE_TRIPLES "/home/o/feather-safe7/feather/monero/tests/difficulty/CMakeLists.txt;48;add_test;/home/o/feather-safe7/feather/monero/tests/difficulty/CMakeLists.txt;0;")
