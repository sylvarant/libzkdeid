#------------------------------------------------------------------------------
# A library for zero-knowledge de-identified data proofs
# by AJHL
# Adapted from Ethereum-cpp ZK-SNARK experiments
#------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.7.2)
project(libzkdeid VERSION "0.1")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# C++ options
if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  # Common compilation flags and warning configuration
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Wfatal-errors -Wwrite-strings -Wfloat-equal -Wpointer-arith") 

  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -mtune=native")

  set(CMAKE_CXX_FLAGS_DEBUG "-g")

endif()

# build paths
set(DEPENDS_DIR "usr/local/")
set(DEP_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake" CACHE PATH "The path to the cmake directory")
list(APPEND CMAKE_MODULE_PATH ${DEP_CMAKE_DIR})

# use external for mcl
include(ExternalProject)
include(mcl)


#----------------------
# The library
#----------------------

file(GLOB SOURCES "*.cpp")
file(GLOB HEADERS "*.hpp")

add_library(libzkdeid ${SOURCES} ${HEADERS})

target_link_libraries(
 libzkdeid

 PRIVATE 
 mcl::loc
 gmp 
 gmpxx
 crypto
)

target_include_directories(libzkdeid

 PUBLIC
 "${CMAKE_BINARY_DIR}/deps/include/"
)

install(FILES ${HEADERS} DESTINATION include/philips)

# Testing
add_subdirectory(test)

# Benchmarking
add_subdirectory(bench)


