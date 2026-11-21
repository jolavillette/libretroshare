## ------------------------------------------------------------------------- ##
 # mk/cmake/fetch_provider_packages/Fetchrestbed-extra.cmake
 # This file is part of libRetroShare.
 #
 # Copyright (C) 2026      David Bears <dbear4q@gmail.com>
 #
 # SPDX-License-Identifier: AGPL-3.0-or-later
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU Affero General Public License as
 # published by the Free Software Foundation, either version 3 of the
 # License, or (at your option) any later version.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 # GNU Affero General Public License for more details.
 #
 # You should have received a copy of the GNU Affero General Public License
 # along with this program.  If not, see <https://www.gnu.org/licenses/>.
## ------------------------------------------------------------------------- ##

# 3.11: FetchContent
# 3.14: FetchContent_MakeAvailable()
cmake_minimum_required(VERSION 3.14...4.4)

include(FetchContent)

set(FETCH_restbed_GIT_TAG "" CACHE STRING
	"git tag to use for fetching restbed"
)
mark_as_advanced(FETCH_restbed_GIT_TAG)
if(NOT FETCH_restbed_GIT_TAG)
	# use the most recent commit that provides set_signal_handler
	# TODO: update RS to use get_io_context
	set(FETCH_restbed_GIT_TAG
		6001a322809b5005b8bcccdf593fdda6f0173691
	)
endif()

set(BUILD_TESTS OFF CACHE BOOL "build restbed tests")
set(BUILD_SSL OFF CACHE BOOL "enable restbed SSL support")
set(BUILD_DEVEL_PACKAGE OFF CACHE BOOL "install restbed headers")
# restbed is linked statically into libretroshare: its shared variant is never
# used, do not build it
set(BUILD_SHARED_LIBRARY OFF CACHE BOOL "build the restbed shared library")

FetchContent_Declare(restbed
	GIT_REPOSITORY "https://github.com/Corvusoft/restbed.git"
	GIT_TAG ${FETCH_restbed_GIT_TAG}
	GIT_PROGRESS TRUE
	# an internal dependency: its targets are built when something links them,
	# and its install rules (librestbed.a and .so into the library directory)
	# are not part of ours
	EXCLUDE_FROM_ALL
)

# restbed is built unmodified, from fetched or local sources alike. Two things
# in its CMake files have to be handled from here.
#
# Its Findasio.cmake stops the configure when asio.hpp is not found. Locate
# asio first, on the system or by fetching it: its module then finds it.
find_path(asio_INCLUDE asio.hpp)
if(NOT asio_INCLUDE)
	include(Fetchasio)
endif()
#
# Its CMakeLists.txt replaces a default install prefix by its own
# "distribution" directory, for the whole build. Tell it the prefix is not the
# default one while it is added.
set(fetch_restbed_prefix_default ${CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT})
set(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT FALSE)
FetchContent_MakeAvailable(restbed)
set(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT ${fetch_restbed_prefix_default})
unset(fetch_restbed_prefix_default)
set(restbed_FOUND TRUE)

if(BUILD_SHARED_LIBS)
  set(RESTBED_TARGETS restbed-shared restbed-static)
else()
  set(RESTBED_TARGETS restbed-static restbed-shared)
endif()

foreach(RESTBED_TARGET ${RESTBED_TARGETS})
  if(TARGET ${RESTBED_TARGET})
    if(NOT TARGET restbed::${RESTBED_TARGET})
      add_library(restbed::${RESTBED_TARGET} ALIAS ${RESTBED_TARGET})
      if(WIN32)
        target_link_libraries(${RESTBED_TARGET} PRIVATE ws2_32 wsock32)
      endif()
    endif()
    if(NOT TARGET restbed::restbed)
      add_library(restbed::restbed ALIAS ${RESTBED_TARGET})
    endif()
  endif()
endforeach()
