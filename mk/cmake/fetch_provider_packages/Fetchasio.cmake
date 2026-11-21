## ------------------------------------------------------------------------- ##
 # mk/cmake/fetch_provider_packages/Fetchasio.cmake
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

set(FETCH_asio_GIT_TAG "" CACHE STRING
	"git tag to use for fetching asio"
)
mark_as_advanced(FETCH_asio_GIT_TAG)
if(NOT FETCH_asio_GIT_TAG)
	# A commit, not a branch: everybody builds the same sources, and git does
	# not go back to the network once they are there.
	# Tag asio-1-36-0, a released version.
	set(FETCH_asio_GIT_TAG
		231cb29bab30f82712fcd54faaea42424cc6e710
	)
endif()

# asio already located, on the system or by an earlier fetch. restbed's own
# Findasio.cmake reports success as ASIO_FOUND, which the provider does not
# read, so the provider comes here although nothing has to be fetched.
if(asio_INCLUDE AND EXISTS "${asio_INCLUDE}/asio.hpp")
	set(asio_FOUND TRUE)
	return()
endif()

include(FetchContent)
FetchContent_Declare(asio
	GIT_REPOSITORY "https://github.com/chriskohlhoff/asio.git"
	GIT_TAG ${FETCH_asio_GIT_TAG}
	GIT_PROGRESS TRUE
	EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(asio)
set(asio_FOUND TRUE)

# Look for the headers instead of assuming where they are: asio/include in the
# releases up to 1.36, include at the top of the repository in later sources.
# find_path() stores the result in the cache, where restbed's Findasio.cmake,
# which searches asio.hpp into this very variable, finds it set.
unset(asio_INCLUDE CACHE)
find_path(asio_INCLUDE asio.hpp
	PATHS "${asio_SOURCE_DIR}/asio/include" "${asio_SOURCE_DIR}/include"
	NO_DEFAULT_PATH
)
if(NOT asio_INCLUDE)
	message(FATAL_ERROR "asio.hpp not found in the fetched asio sources")
endif()
add_compile_definitions(ASIO_STANDALONE=YES)
