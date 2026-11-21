## ------------------------------------------------------------------------- ##
 # mk/cmake/fetch_provider_packages/Fetchudp-discovery-cpp.cmake
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

# 3.6 : FetchContent_Declare(GIT_SHALLOW)
# 3.8 : FetchContent_Declare(GIT_PROGRESS)
# 3.11: FetchContent
# 3.13: CMP0077
# 3.14: FetchContent_MakeAvailable()
cmake_minimum_required(VERSION 3.14...4.4)

set(FETCH_udp-discovery-cpp_GIT_TAG "" CACHE STRING
	"git tag to use for fetching udp-discovery-cpp"
)
mark_as_advanced(FETCH_udp-discovery-cpp_GIT_TAG)
if(NOT FETCH_udp-discovery-cpp_GIT_TAG)
	# A commit, not a branch: everybody builds the same sources, and git does
	# not go back to the network once they are there.
	# RetroShare's udp-discovery-cpp submodule.
	set(FETCH_udp-discovery-cpp_GIT_TAG
		f3a3103a6c52e5707629e8d0a7e279a7758fe845
	)
endif()

set(BUILD_TEST FALSE)

include(FetchContent)
FetchContent_Declare(udp-discovery-cpp
	GIT_REPOSITORY "https://github.com/truvorskameikin/udp-discovery-cpp.git"
	GIT_TAG ${FETCH_udp-discovery-cpp_GIT_TAG}
	GIT_PROGRESS TRUE
	PATCH_COMMAND sed -i -e "s/^cmake_minimum_required(VERSION 3.0)\$/cmake_minimum_required(VERSION 3.0...4.4)/" CMakeLists.txt
)
FetchContent_MakeAvailable(udp-discovery-cpp)
set(udp-discovery-cpp_FOUND TRUE)

add_library(udp-discovery-cpp::udp-discovery ALIAS udp-discovery)

target_include_directories(udp-discovery PUBLIC
	"${udp-discovery-cpp_SOURCE_DIR}"
)

target_compile_definitions(udp-discovery PRIVATE UNICODE _UNICODE)


if(WIN32)
	# Legacy C submodules trip strict GCC >= 15 diagnostics that are now errors by
	# default; downgrade them to warnings for now.
	target_compile_options(udp-discovery PRIVATE
	  -Wno-error=incompatible-pointer-types
	  -Wno-error=int-conversion
	  -Wno-error=implicit-function-declaration
	)
endif()
