cmake_minimum_required (VERSION 2.6)

project (fexporter)

#set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_BUILD_TYPE Release)

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
add_executable(fexporterd fexporterd.c)
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
