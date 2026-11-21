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

include(FetchContent)

set(FETCH_rnp_GIT_TAG "" CACHE STRING
	"git tag to use for fetching rnp"
)
mark_as_advanced(FETCH_rnp_GIT_TAG)
if(NOT FETCH_rnp_GIT_TAG)
	# A commit, not a branch: everybody builds the same sources, and git does
	# not go back to the network once they are there.
	# RetroShare's librnp submodule.
	set(FETCH_rnp_GIT_TAG
		ec78117269461b2cdce15a085033a8c6bff6d7e3
	)
endif()

FetchContent_Declare(rnp
	GIT_REPOSITORY "https://github.com/rnpgp/rnp.git"
	GIT_TAG ${FETCH_rnp_GIT_TAG}
	GIT_PROGRESS TRUE
	EXCLUDE_FROM_ALL
)
# rnp finds its dependencies with its own Find modules. Do not let our
# CMAKE_FIND_PACKAGE_PREFER_CONFIG reach it: a config package found first
# (e.g. Botan's) defines the targets those modules would have defined.
set(fetch_rnp_prefer_config ${CMAKE_FIND_PACKAGE_PREFER_CONFIG})
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG FALSE)
# rnp's test suite is not needed here, and configuring it downloads googletest.
set(fetch_rnp_build_testing ${BUILD_TESTING})
set(BUILD_TESTING OFF)
FetchContent_MakeAvailable(rnp)
set(BUILD_TESTING ${fetch_rnp_build_testing})
unset(fetch_rnp_build_testing)
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG ${fetch_rnp_prefer_config})
unset(fetch_rnp_prefer_config)
set(rnp_FOUND TRUE)

add_library(rnp::librnp ALIAS librnp)
