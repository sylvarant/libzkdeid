#------------------------------------------------------------------------------
# Bench marking
# by AJHL
#------------------------------------------------------------------------------
include_directories(.)

if (BENCH)

 add_custom_target(bench)

 # >>>> The solution benchmark <<<<
 add_executable(deid_bench
  EXCLUDE_FROM_ALL
  deid.cpp
 )

 target_link_libraries(deid_bench
  PRIVATE
  libzkdeid 
  mcl::loc
 )

 target_include_directories(deid_bench
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
  "${HEADERS}"
 )

 add_dependencies(bench deid_bench)

endif()

