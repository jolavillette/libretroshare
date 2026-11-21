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
	# The commit RetroShare's builds use (master's submodule commit f54b0e47 does
	# not compile with GCC 14 and later).
	set(FETCH_RapidJSON_GIT_TAG
		9bd618f545ab647e2c3bcbf2f1d87423d6edf800
	)
endif()

# RapidJSON is header-only: fetch its sources and use the include directory.
# Its own CMakeLists.txt is not run (at this commit it asks for CMake 2.8, which
# CMake 4 refuses) and its submodule (googletest, for its tests) is not fetched.
# SOURCE_SUBDIR names a directory without a CMakeLists.txt, which is how
# FetchContent is told to populate only.
include(FetchContent)
FetchContent_Declare(RapidJSON
	GIT_REPOSITORY "https://github.com/Tencent/rapidjson.git"
	GIT_TAG ${FETCH_RapidJSON_GIT_TAG}
	GIT_PROGRESS TRUE
	GIT_SUBMODULES ""
	SOURCE_SUBDIR include
)
FetchContent_MakeAvailable(RapidJSON)
set(RapidJSON_FOUND TRUE)

# FixRapidJSONTarget.cmake makes the RapidJSON target from this variable
set(RAPIDJSON_INCLUDE_DIRS "${rapidjson_SOURCE_DIR}/include")
