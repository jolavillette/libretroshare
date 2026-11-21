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
	# asio master of 2026-11-07: the headers are in include/ at the top of the
	# repository there (in asio/include/ up to the 1.36 releases), which is
	# what asio_INCLUDE below expects.
	set(FETCH_asio_GIT_TAG
		190a8d8daf1cc62909b4e0c72ff491ba264ca98e
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

# in the cache: restbed's Findasio.cmake looks for asio.hpp with find_path()
# into this very variable, and finds it set
set(asio_INCLUDE "${asio_SOURCE_DIR}/include" CACHE PATH "asio headers" FORCE)
add_compile_definitions(ASIO_STANDALONE=YES)
