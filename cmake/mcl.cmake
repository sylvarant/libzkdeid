# by AJHL
# TODO bind to a commit? this may be susceptible to big github related changes?
set(prefix "${CMAKE_BINARY_DIR}/deps")
set(libmcl_library "${prefix}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}mcl${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(libmcl_include_dir "${prefix}/include/")

ExternalProject_Add(libmcl
    PREFIX "${prefix}"
    GIT_REPOSITORY "https://github.com/herumi/mcl.git"
    GIT_SHALLOW 1
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release
    LOG_BUILD 1
    INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config Release --target install
)    

add_library(mcl::loc STATIC IMPORTED)
file(MAKE_DIRECTORY ${libmcl_include_dir})
file(MAKE_DIRECTORY "${prefix}/lib")
set_property(TARGET mcl::loc PROPERTY IMPORTED_CONFIGURATIONS Release)
set_property(TARGET mcl::loc PROPERTY IMPORTED_LOCATION_RELEASE ${libmcl_library})
set_property(TARGET mcl::loc PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${libmcl_include_dir})
add_dependencies(mcl::loc libmcl)

