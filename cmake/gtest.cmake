# by AJHL
# https://github.com/google/googletest/archive/release-1.8.0.tar.gz 
set(prefix "${CMAKE_BINARY_DIR}/deps")
set(libgt_library "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(libgt_include_dir "${prefix}/include/gtest")

# fix to v1.8
#        -DBUILD_SHARED_LIBS=ON
ExternalProject_Add(gtest
    PREFIX "${prefix}"
    DOWNLOAD_NAME release-1.8.0.tar.gz
    DOWNLOAD_NO_PROGRESS TRUE
    URL https://github.com/google/googletest/archive/release-1.8.0.tar.gz 
    URL_HASH SHA256=58a6f4277ca2bc8565222b3bbd58a177609e9c488e8a72649359ba51450db7d8
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DBUILD_GTEST=ON
        -DBUILD_GMOCK=OFF
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release
    LOG_BUILD 1
    INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install
)    

# set gtest::loc ref point
add_library(gtest::loc STATIC IMPORTED)
file(MAKE_DIRECTORY ${libgt_include_dir})
file(MAKE_DIRECTORY "${prefix}/lib")
set_property(TARGET gtest::loc PROPERTY IMPORTED_CONFIGURATIONS Release)
set_property(TARGET gtest::loc PROPERTY IMPORTED_LOCATION_RELEASE ${libgt_library})
set_property(TARGET gtest::loc PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${libgt_include_dir})
add_dependencies(gtest::loc gtest)

