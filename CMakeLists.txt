cmake_minimum_required(VERSION 3.16)
project(gpt2_restart_2024)

find_package(SEAL 4.1.1 EXACT REQUIRED)
find_package(Eigen3 REQUIRED)
find_package(emp-tool REQUIRED)
find_package(emp-ot REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -mavx2 -msse4.1 -maes -msse2 -march=native -fopenmp")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/hxy_lib)

# General test
add_executable(test test.cpp hxy_lib/Common.cpp)
target_link_libraries(test ${EMP-TOOL_LIBRARIES} SEAL::seal)

# Common function
add_executable(Common_test test/Common_test.cpp hxy_lib/Common.cpp)
target_link_libraries(Common_test ${EMP-TOOL_LIBRARIES} SEAL::seal)

# BOLE
add_executable(BOLE_test test/BOLE_test.cpp hxy_lib/Common.cpp hxy_lib/FHE_Common.cpp hxy_lib/BOLE_protocol.cpp)
target_link_libraries(BOLE_test ${EMP-TOOL_LIBRARIES} SEAL::seal)

# MUX
add_executable(MUX_test test/MUX_test.cpp hxy_lib/Common.cpp hxy_lib/MUX_protocol.cpp)
target_link_libraries(MUX_test ${EMP-TOOL_LIBRARIES} SEAL::seal)

# AND
add_executable(AND_test test/AND_test.cpp hxy_lib/Common.cpp hxy_lib/AND_protocol.cpp)
target_link_libraries(AND_test ${EMP-TOOL_LIBRARIES} SEAL::seal)

# SPLUT
add_executable(SPLUT_test test/SPLUT_test.cpp hxy_lib/Common.cpp hxy_lib/AND_protocol.cpp hxy_lib/SPLUT.cpp)
target_link_libraries(SPLUT_test ${EMP-TOOL_LIBRARIES} SEAL::seal)