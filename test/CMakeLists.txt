#------------------------------------------------------------------------------
# TESTING
# by AJHL
#------------------------------------------------------------------------------
include_directories(.)

if(TESTING OR CMAKE_BUILD_TYPE MATCHES Debug)

 include(CTest)
 include(FindGTest)

 add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

 # pthreads misery 3.1+ 
 set(THREADS_PREFER_PTHREAD_FLAG ON)
 find_package(Threads REQUIRED)

 # >>>> The deid tests <<<<
 add_executable(deid_test
  EXCLUDE_FROM_ALL
  init_test.cpp
  deid.cpp
 )

 target_link_libraries(deid_test
  PRIVATE
  libzkdeid 
  mcl::loc
  gtest
  Threads::Threads
 )

 target_include_directories(deid_test
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
 )

 gtest_add_tests(
    deid_test
    ""
    deid.cpp
 )

 add_dependencies(check deid_test)

 # >>>> The bb tests <<<<
 add_executable(bb_test
  EXCLUDE_FROM_ALL
  init_test.cpp
  bb.cpp
 )

 target_link_libraries(bb_test
  PRIVATE
  libzkdeid 
  mcl::loc
  gtest
  Threads::Threads
 )

 target_include_directories(bb_test
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
 )

 gtest_add_tests(
    bb_test
    ""
    bb.cpp
 )

 add_dependencies(check bb_test)

 # >>>> crypto tests <<<<
 add_executable(crypto_test
  EXCLUDE_FROM_ALL
  init_test.cpp
  crypto.cpp
 )

 target_link_libraries(crypto_test
  PRIVATE
  libzkdeid 
  mcl::loc
  gtest
  Threads::Threads
 )

 target_include_directories(crypto_test
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
 )

 gtest_add_tests(
    crypto_test
    ""
    crypto.cpp
 )

 add_dependencies(check crypto_test)

  # >>>> web tests <<<<
 add_executable(web_test
  EXCLUDE_FROM_ALL
  init_test.cpp
  web.cpp
 )

 target_link_libraries(web_test
  PRIVATE
  libzkdeid 
  mcl::loc
  gtest
  Threads::Threads
 )

 target_include_directories(web_test
  PUBLIC
  "${CMAKE_BINARY_DIR}/deps/include"
  "${CMAKE_SOURCE_DIR}"
 )

 gtest_add_tests(
    web_test
    ""
    web.cpp
 )

 add_dependencies(check web_test)

endif()

