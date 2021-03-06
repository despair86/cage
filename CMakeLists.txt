cmake_minimum_required(VERSION 3.8) # setting this is required
project(cage)            # this sets the project name

###############################################################################
## file globbing ##############################################################
###############################################################################

# These instructions search the directory tree when cmake is
# invoked and put all files that match the pattern in the variables
# `sources` and `data`.
file(GLOB_RECURSE keygen_sources   src/keygen/*.c)
file(GLOB_RECURSE bech32_sources   src/bech32/*.c)
file(GLOB_RECURSE common_sources   src/common/*.c)
file(GLOB_RECURSE polarssl_sources src/crypto/*.c)
file(GLOB_RECURSE cage_sources     src/cage/*.c)

# You can use set(sources src/main.cpp) etc if you don't want to
# use globbing to find files automatically.

###############################################################################
## target definitions #########################################################
###############################################################################

# The data is just added to the executable, because in some IDEs (QtCreator)
# files are invisible when they are not explicitly part of the project.
add_executable(cage-keygen ${keygen_sources})
add_executable(cage ${cage_sources})

if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
  set(SOLARIS ON)
  #set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES} -lsocket -lnsl")
  IF(CMAKE_C_COMPILER_ID MATCHES "SunPro")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mt")
  ELSE()
    add_definitions(-D_POSIX_PTHREAD_SEMANTICS -D_REENTRANT)
  ENDIF()
  set(CMAKE_C_STANDARD_LIBRARIES "${CMAKE_C_STANDARD_LIBRARIES} -lsocket -lnsl")
endif()

if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
  if(MSVC_VERSION LESS 1900)
    add_definitions(-Dsnprintf=_snprintf)
  endif()
  include_directories(include/msvc)
endif()

# this library is not installed with the apps.
add_library(cage-crypto STATIC ${polarssl_sources} ${bech32_sources} ${common_sources})

# Just for cage-keygen add some compiler flags.
#target_compile_options(cage-keygen PUBLIC)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(cage-keygen PUBLIC include)
target_include_directories(cage-crypto PUBLIC include)
target_include_directories(cage PUBLIC include)

# link polarssl for crypto (we have x25519 here!)
target_link_libraries(cage-keygen cage-crypto)
target_link_libraries(cage cage-crypto)

# This copies all resource files in the build directory.
# We need this, because we want to work with paths relative to the executable.
#file(COPY ${data} DESTINATION resources)

###############################################################################
## packaging ##################################################################
###############################################################################

# All install commands get the same destination. this allows us to use paths
# relative to the executable.
install(TARGETS cage-keygen DESTINATION bin)
install(TARGETS cage DESTINATION bin)

# Now comes everything we need, to create a package
# there are a lot more variables you can set, and some
# you need to set for some package types, but we want to
# be minimal here.
set(CPACK_PACKAGE_NAME "cage")
set(CPACK_PACKAGE_VERSION "0.1.0")

# We don't want to split our program up into several incomplete pieces.
set(CPACK_MONOLITHIC_INSTALL 1)

# This must be last
include(CPack)
