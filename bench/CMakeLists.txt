#------------------------------------------------------------------------------
# Bench marking
# by AJHL
#------------------------------------------------------------------------------
include_directories(.)

if (BENCH)

 add_custom_target(bench)

 # >>>> The cls benchmark <<<<
 add_executable(cls_bench
  EXCLUDE_FROM_ALL
  cls.cpp
 )

 target_link_libraries(cls_bench
  PRIVATE
  libzkdeid 
  mcl::loc
 )

 target_include_directories(cls_bench
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
  "${HEADERS}"
 )

 add_dependencies(bench cls_bench)

endif()

