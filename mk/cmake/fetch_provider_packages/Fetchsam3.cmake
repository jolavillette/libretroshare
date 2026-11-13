## ------------------------------------------------------------------------- ##
 # mk/cmake/fetch_provider_packages/Fetchsam3.cmake
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

cmake_minimum_required(VERSION 3.0...4.4)

if(NOT TARGET sam3_external)
include(ExternalProject)
include(EnvironmentModification)

set(FETCH_sam3_GIT_TAG "" CACHE STRING
	"git tag to use for fetching sam3"
)
mark_as_advanced(FETCH_sam3_GIT_TAG)
if(NOT FETCH_sam3_GIT_TAG)
	set(FETCH_sam3_GIT_TAG origin/master)
endif()

# sam3 is an ExternalProject, which FETCHCONTENT_SOURCE_DIR_<NAME> does not
# reach, so honour FETCHCONTENT_SOURCE_DIR_SAM3 here the way FetchContent does
# for the other packages: the tree is taken as is (no git, no patch). URL copies
# it into the prefix, so the in-source build never writes into it.
set(FETCHCONTENT_SOURCE_DIR_SAM3 "" CACHE PATH
	"When not empty, overrides where to find pre-populated content for sam3"
)
if(FETCHCONTENT_SOURCE_DIR_SAM3)
	if(NOT IS_DIRECTORY "${FETCHCONTENT_SOURCE_DIR_SAM3}")
		message(FATAL_ERROR "Manually specified source directory is missing:\n"
			"  FETCHCONTENT_SOURCE_DIR_SAM3 --> ${FETCHCONTENT_SOURCE_DIR_SAM3}"
		)
	endif()
	set(sam3_external_DOWNLOAD_OPTIONS URL "${FETCHCONTENT_SOURCE_DIR_SAM3}")
else()
	find_package(Git REQUIRED)
	find_package(Patch REQUIRED)
	set(sam3_external_DOWNLOAD_OPTIONS
		GIT_REPOSITORY "https://github.com/i2p/libsam3.git"
		GIT_TAG ${FETCH_sam3_GIT_TAG}
		GIT_PROGRESS TRUE
		PATCH_COMMAND ${GIT_EXECUTABLE} reset --hard
		COMMAND ${Patch_EXECUTABLE} -tNp1 -i
			"${CMAKE_CURRENT_LIST_DIR}/sam3.patch"
	)
endif()

set(sam3_external_SOURCE_DIR "sam3_external-prefix/src/sam3_external")
set(sam3_external_BINARY_DIR ${sam3_external_SOURCE_DIR})
set(sam3_external_LDFLAGS "-fPIC")
if(WIN32)
	list(APPEND sam3_external_LDFLAGS
		"-lmingw32" "-lws2_32" "-lwsock32" "-mwindows"
	)
endif()

list(JOIN sam3_external_LDFLAGS " " sam3_external_LDFLAGS)
set(sam3_external_BUILD_ENVIRONMENT
	"CC=set:${CMAKE_C_COMPILER}"
	"AR=set:${CMAKE_AR}"
	"LDFLAGS=set:${sam3_external_LDFLAGS}"
)
EnvironmentModification(envmod_build ${sam3_external_BUILD_ENVIRONMENT})

ExternalProject_Add(sam3_external
	${sam3_external_DOWNLOAD_OPTIONS}
	CONFIGURE_COMMAND ""
  BUILD_COMMAND ${envmod_build} make build
	INSTALL_COMMAND ""
	BUILD_IN_SOURCE TRUE
	BUILD_ALWAYS TRUE
	EXCLUDE_FROM_ALL YES
	BUILD_BYPRODUCTS "${sam3_external_BINARY_DIR}/libsam3.a"
	BUILD_ENVIRONMENT_MODIFICATION ${sam3_external_BUILD_ENVIRONMENT}
)
endif()

ExternalProject_Get_Property(sam3_external SOURCE_DIR BINARY_DIR)
set(sam3_FOUND TRUE)

if(NOT TARGET sam3::libsam3)
  add_library(sam3::libsam3 STATIC IMPORTED)
  set_target_properties(sam3::libsam3 PROPERTIES
    IMPORTED_LOCATION "${BINARY_DIR}/libsam3.a"
    INTERFACE_INCLUDE_DIRECTORIES
      "${SOURCE_DIR}/src/libsam3;${SOURCE_DIR}/src/libsam3a"
  )
  add_dependencies(sam3::libsam3 sam3_external)

  # make the directory so that CMake doesn't complain before sam3 is built
  file(MAKE_DIRECTORY "${SOURCE_DIR}/src/libsam3" "${SOURCE_DIR}/src/libsam3a")

  if(WIN32)
    target_link_libraries(sam3::libsam3 INTERFACE ws2_32)
  endif()
endif()
