#
# Copyright (c) 2017 Hirochika Asai <asai@jar.jp>
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

cmake_minimum_required (VERSION 2.6)

project (fexporter)

#set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_C_FLAGS_DEBUG "-O0")
#set (CMAKE_BUILD_TYPE Release)
set (CMAKE_C_FLAGS_RELEASE "-O3")

# Define the build time
execute_process (COMMAND uname -a
  OUTPUT_VARIABLE _output OUTPUT_STRIP_TRAILING_WHITESPACE)
if(WIN32)
 execute_process (COMMAND cmd /C win_date.bat
    OUTPUT_VARIABLE BUILD_DATETIME)
else(WIN32)
  execute_process (COMMAND date "+%Y%m%d-%H%M%S"
    OUTPUT_VARIABLE BUILD_DATETIME)
endif(WIN32)
string(STRIP ${BUILD_DATETIME} BUILD_DATETIME)

execute_process (COMMAND git symbolic-ref --short HEAD
  OUTPUT_VARIABLE GIT_CURRENT_BRANCH)

add_definitions (-DBUILD_DATETIME=\"${BUILD_DATETIME}\")

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "build")

set (fexporter_VERSION "current-${BUILD_DATETIME}")
#set (fexporter_VERSION_MAJOR "0")
#set (fexporter_VERSION_MINOR "1")
#set (fexporter_VERSION_PATCH "0")

# fexporterd
add_executable(fexporterd fexporterd.c flowtable.c flowtable.h ifutil.c ifutil.h
      ipfix.h)
# link the libraries to the executable
target_link_libraries (fexporterd pcap)

# testing
#include(CTest)
#set (CTEST_PROJECT_NAME "fexporter")
# does the application run
#add_executable(fexporter_test_basic tests/basic.c)
#add_test (BasicTest ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/fexporter_test_basic)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_PACKAGE_VENDOR "Hirochika Asai")
set (CPACK_RESOURCE_FILE_LICENSE
     "${CMAKE_CURRENT_SOURCE_DIR}/License.txt")
if(fexporter_VERSION)
  set (CPACK_PACKAGE_VERSION "${fexporter_VERSION}")
else(fexporter_VERSION)
  set (CPACK_PACKAGE_VERSION_MAJOR "${fexporter_VERSION_MAJOR}")
  set (CPACK_PACKAGE_VERSION_MINOR "${fexporter_VERSION_MINOR}")
  set (CPACK_PACKAGE_VERSION_PATCH "${fexporter_VERSION_PATCH}")
endif(fexporter_VERSION)
include (CPack)

add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
set (CPACK_IGNORE_FILES "/CVS/;/\\.svn/;/\\.bzr/;/\\.hg/;/\\.git/;\\.swp\$;\\.#;/#;/build/")
add_custom_target(git-dist
  COMMAND cmake ..
  COMMAND make dist
  COMMAND cp fexporter-*-Source.tar.* ../../
  WORKING_DIRECTORY .working/build
  DEPENDS git-working-prepare)

add_custom_target(git-working-prepare
  COMMAND rm -rf .working
  COMMAND git clone . .working -b ${GIT_CURRENT_BRANCH}
  COMMAND mkdir .working/build
  WORKING_DIRECTORY .)

add_custom_target(git-test
  COMMAND cmake ..
  COMMAND make
  COMMAND make test
  WORKING_DIRECTORY .working/build
  DEPENDS git-working-prepare)
