## ------------------------------------------------------------------------- ##
 # mk/cmake/fetch_provider_packages/Fetchrnp.cmake
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

set(FETCH_RapidJSON_GIT_TAG "" CACHE STRING
	"git tag to use for fetching RapidJSON"
)
mark_as_advanced(FETCH_RapidJSON_GIT_TAG)
if(NOT FETCH_RapidJSON_GIT_TAG)
	# A commit, not a branch: everybody builds the same sources, and git does
	# not go back to the network once they are there.
	# RetroShare's rapidjson submodule.
	set(FETCH_RapidJSON_GIT_TAG
		f54b0e47a08782a6131cc3d60f94d038fa6e0a51
	)
endif()

set(RAPIDJSON_BUILD_EXAMPLES OFF CACHE BOOL "Build rapidjson examples.")
set(RAPIDJSON_BUILD_TESTS OFF CACHE BOOL
	"Build rapidjson perftests and unittests."
)
set(CMAKE_EXPORT_NO_PACKAGE_REGISTRY TRUE)

include(FetchContent)
FetchContent_Declare(RapidJSON
	GIT_REPOSITORY "https://github.com/Tencent/rapidjson.git"
	GIT_TAG ${FETCH_RapidJSON_GIT_TAG}
	GIT_PROGRESS TRUE
	EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(RapidJSON)
set(RapidJSON_FOUND TRUE)

target_include_directories(RapidJSON INTERFACE
  "$<BUILD_INTERFACE:${RapidJSON_SOURCE_DIR}/include>"
)
