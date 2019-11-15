cmake_minimum_required(VERSION 3.1)
project(customer_cone CXX)

# Check if the user provided CXXFLAGS, set defaults otherwise.
if(NOT CMAKE_CXX_FLAGS)
    set(CMAKE_CXX_FLAGS                   "-std=c++14 -Wextra -Wall -pedantic ${EXTRA_FLAGS}")
endif()
if(NOT CMAKE_CXX_FLAGS_DEBUG)
    set(CMAKE_CXX_FLAGS_DEBUG             "-O0 -g -fno-omit-frame-pointer -fsanitize=address")
endif()
if(NOT CMAKE_CXX_FLAGS_MINSIZEREL)
    set(CMAKE_CXX_FLAGS_MINSIZEREL        "-Os")
endif()
if(NOT CMAKE_CXX_FLAGS_RELEASE)
    set(CMAKE_CXX_FLAGS_RELEASE           "-O3 -DNDEBUG")
endif()
if(NOT CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO    "-O2 -g -fno-omit-frame-pointer")
endif()

# Set build default build type to RelWithDebInfo if not set.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")

include(ExternalProject)

set(PCAPPLUSPLUS_SOURCE_DIR "${CMAKE_BINARY_DIR}/pcapplusplus-src")
set(PCAPPLUSPLUS_BINARY_DIR "${CMAKE_BINARY_DIR}/pcapplusplus-build")

set(CAF_SOURCE_DIR "${CMAKE_BINARY_DIR}/caf-src")
set(CAF_BINARY_DIR "${CMAKE_BINARY_DIR}/caf-build")
set(CAF_INSTALL_DIR "${CMAKE_BINARY_DIR}/caf-install")

ExternalProject_Add(PCAPPLUSPLUS
        GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
        GIT_TAG e1a3da2d791fe2544258b0145ced81edbd0549bd
        PREFIX ${CMAKE_CURRENT_BINARY_DIR}/PCAPPLUSPLUS
        PATCH_COMMAND patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/patch/fixes-possible-memory-leaks.diff
        CONFIGURE_COMMAND <SOURCE_DIR>/configure-linux.sh  --default
        UPDATE_DISCONNECTED 1
        BUILD_COMMAND make
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE 1
        )

ExternalProject_Add(CAF
        GIT_REPOSITORY https://github.com/actor-framework/actor-framework.git
        GIT_TAG b05a4b7b2a6f59b0508db84ea68e5ada2224f904
        UPDATE_DISCONNECTED 1
        PREFIX ${CMAKE_CURRENT_BINARY_DIR}/CAF
        CONFIGURE_COMMAND <SOURCE_DIR>/configure  --no-examples --no-opencl --no-openssl --no-python --no-tools --no-curl-examples --no-unit-tests --no-summary --build-dir=<SOURCE_DIR>/build --prefix=<SOURCE_DIR>/install
        BUILD_COMMAND make -C <SOURCE_DIR>/build
        INSTALL_COMMAND make -C <SOURCE_DIR>/build install
        )
set( boost_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/boost )
set( boost_INCLUDE_DIR ${boost_INSTALL}/include )
set( boost_LIB_DIR ${boost_INSTALL}/lib )

ExternalProject_Add(
        EXTERNAL_BOOST
        PREFIX boost
        URL https://dl.bintray.com/boostorg/release/1.71.0/source/boost_1_71_0.tar.bz2
        URL_HASH SHA1=5b0a3cef23f0c124dde5bbb64324f615ac843ace
        BUILD_IN_SOURCE 1
        UPDATE_DISCONNECTED 1
        CONFIGURE_COMMAND ./bootstrap.sh
        --with-libraries=filesystem
        --with-libraries=iostreams
        --prefix=<INSTALL_DIR>
        BUILD_COMMAND
        ./b2 install link=static variant=release threading=multi runtime-link=static
        INSTALL_COMMAND ""
        INSTALL_DIR ${boost_INSTALL} )

set(BOOST_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/libboost_filesystem.a
        ${CMAKE_CURRENT_BINARY_DIR}/boost/lib/libboost_iostreams.a
        )

set(BOOST_INCLUDES
        ${CMAKE_CURRENT_BINARY_DIR}/boost/include/
        )

file(GLOB_RECURSE headers "${CMAKE_CURRENT_SOURCE_DIR}/customer_cone/*.hpp")
file(GLOB_RECURSE sources "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE tests "${CMAKE_CURRENT_SOURCE_DIR}/test/*.cpp")

file(GLOB_RECURSE pcappluplus_headers "${CMAKE_CURRENT_SOURCE_DIR}/build/PCAPPLUSPLUS/src/PCAPPLUSPLUS/Dist/header/*.h")

SET(PCAPPLUSPLUS
        ${CMAKE_CURRENT_SOURCE_DIR}/build/PCAPPLUSPLUS/src/PCAPPLUSPLUS/Dist/libPcap++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/build/PCAPPLUSPLUS/src/PCAPPLUSPLUS/Dist/libPacket++.a
        ${CMAKE_CURRENT_SOURCE_DIR}/build/PCAPPLUSPLUS/src/PCAPPLUSPLUS/Dist/libCommon++.a
        )

SET(CAF
        ${CMAKE_CURRENT_SOURCE_DIR}/build/CAF/src/CAF/build/lib/libcaf_core.so
        ${CMAKE_CURRENT_SOURCE_DIR}/build/CAF/src/CAF/build/lib/libcaf_io.so
        ${CMAKE_CURRENT_SOURCE_DIR}/build/CAF/src/CAF/build/lib/libcaf_io.so
        )

SET(CAF_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/build/CAF/src/CAF/install/include/)

find_package(BZip2)
find_package(ZLIB)
find_package (Threads)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/." ${CAF_INCLUDES} ${BZIP2_INCLUDE_DIR} ${BOOST_INCLUDES} "${CMAKE_CURRENT_SOURCE_DIR}/build/PCAPPLUSPLUS/src/PCAPPLUSPLUS/Dist/header" ${CAF_INCLUDES})
add_library(libcustomer_cone ${sources} ${headers} ${tests})
add_dependencies(libcustomer_cone CAF PCAPPLUSPLUS EXTERNAL_BOOST)

add_executable(cc main.cpp)
target_link_libraries(cc libcustomer_cone ${CMAKE_THREAD_LIBS_INIT}  ${CAF} ${PCAPPLUSPLUS} ${ZLIB_LIBRARIES} ${BOOST_LIBRARIES} ${BZIP2_LIBRARIES})

add_executable(cc_test ${tests})

target_link_libraries(cc_test libcustomer_cone ${CAF} ${CMAKE_THREAD_LIBS_INIT} ${BOOST_LIBRARIES} ${ZLIB_LIBRARIES} ${BZIP2_LIBRARIES})


# Found this in VAST (libvast/CMakeLists.txt).
macro(make_test suite)
    string(REPLACE " " "_" test_name ${suite})
    set(cc_test ${CMAKE_CURRENT_SOURCE_DIR}/build/cc_test)
    add_test(${test_name} ${cc_test} -v 3 -r 600 -s "^${suite}$" ${ARGN})
endmacro()

# Find all test suites and extract their names.
foreach(test ${tests})
    file(STRINGS ${test} contents)
    foreach(line ${contents})
        if ("${line}" MATCHES "SUITE")
            string(REGEX REPLACE "#define CAF_SUITE \(.*\)" "\\1" suite ${line})
            list(APPEND suites ${suite})
        endif()
    endforeach()
endforeach()
list(REMOVE_DUPLICATES suites)

enable_testing()

foreach(suite ${suites})
    make_test("${suite}")
endforeach()