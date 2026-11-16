# RetroShare
# Copyright (C) 2026  Retroshare Team <contact@retroshare.cc>
#
# SPDX-License-Identifier: CC0-1.0

# Build time version stamping, run with `cmake -P` at every build.
#
# Writes rsversion_build.h, which holds the two libretroshare version strings
# that change at every commit. Only rsinit.cc includes that header, so a new
# commit rebuilds one object instead of the whole library, and the strings
# always describe the commit that is being built.
#
# The file is written through configure_file(), which leaves it untouched when
# its content does not change: a build without a new commit rebuilds nothing.
#
# Expected variables:
#   RS_STAMP_SOURCE_DIR  libretroshare source directory
#   RS_STAMP_TEMPLATE    rsversion_build.h.in
#   RS_STAMP_OUTPUT      rsversion_build.h to write
#   GIT_EXECUTABLE       git, may be empty
#   RS_STAMP_FIXED_VERSION  ON when the version was given on the CMake command
#                        line: the extra version is then not generated here
#   RS_STAMP_MAJOR, RS_STAMP_MINOR, RS_STAMP_MINI  version numbers known at
#                        configure time, used to detect a tag change

set(V_DESCRIBE_REGEXP "^v([0-9]+).([0-9]+).([0-9]+)(.*)$")
set(V_SOURCE_VERSION_FILE "${RS_STAMP_SOURCE_DIR}/Source_Version")

# Source tarball fallback: the tarball preparation script stores the output of
# `git describe --tags --long --match v*.*.*` in a Source_Version file.
set(V_SOURCE_VERSION "")
if(EXISTS "${V_SOURCE_VERSION_FILE}")
	file(READ "${V_SOURCE_VERSION_FILE}" V_SOURCE_VERSION)
	string(STRIP "${V_SOURCE_VERSION}" V_SOURCE_VERSION)
endif()

# Extra version, e.g. "-963-g49d11c2f"
set(RS_BUILD_EXTRA_VERSION_SET OFF)
set(RS_BUILD_EXTRA_VERSION "")
if(NOT RS_STAMP_FIXED_VERSION)
	set(V_DESCRIBE "")
	if(GIT_EXECUTABLE)
		execute_process(
			COMMAND "${GIT_EXECUTABLE}" describe --tags --long --match v*.*.*
			WORKING_DIRECTORY "${RS_STAMP_SOURCE_DIR}"
			OUTPUT_VARIABLE V_DESCRIBE
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
			RESULT_VARIABLE V_GIT_RESULT )
		if(NOT V_GIT_RESULT EQUAL 0)
			set(V_DESCRIBE "")
		endif()
	endif()
	if(NOT V_DESCRIBE MATCHES "${V_DESCRIBE_REGEXP}")
		set(V_DESCRIBE "${V_SOURCE_VERSION}")
	endif()

	if(V_DESCRIBE MATCHES "${V_DESCRIBE_REGEXP}")
		set(RS_BUILD_EXTRA_VERSION_SET ON)
		set(RS_BUILD_EXTRA_VERSION "${CMAKE_MATCH_4}")

		# The three version numbers are compile definitions set at configure
		# time, they only change with a new tag.
		if( NOT "${RS_STAMP_MAJOR}" STREQUAL "" AND
		    NOT "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}" STREQUAL
		        "${RS_STAMP_MAJOR}.${RS_STAMP_MINOR}.${RS_STAMP_MINI}" )
			message(WARNING
				"libRetroShare version is now "
				"${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3} but the build "
				"was configured for "
				"${RS_STAMP_MAJOR}.${RS_STAMP_MINOR}.${RS_STAMP_MINI}, "
				"run cmake again to update it")
		endif()
	endif()
endif()

# Engine build hash, e.g. "0.6.7-963-g49d11c2f-dirty"
set(RS_BUILD_LIB_VERSION_HASH_SET OFF)
set(RS_BUILD_LIB_VERSION_HASH "")
if(GIT_EXECUTABLE)
	execute_process(
		COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
		WORKING_DIRECTORY "${RS_STAMP_SOURCE_DIR}"
		OUTPUT_VARIABLE RS_BUILD_LIB_VERSION_HASH
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_QUIET
		RESULT_VARIABLE V_GIT_RESULT )
	if(NOT V_GIT_RESULT EQUAL 0)
		set(RS_BUILD_LIB_VERSION_HASH "")
	endif()
endif()
if(RS_BUILD_LIB_VERSION_HASH STREQUAL "")
	set(RS_BUILD_LIB_VERSION_HASH "${V_SOURCE_VERSION}")
endif()
if(NOT RS_BUILD_LIB_VERSION_HASH STREQUAL "")
	string(REGEX REPLACE "^v" "" RS_BUILD_LIB_VERSION_HASH
		"${RS_BUILD_LIB_VERSION_HASH}")
	set(RS_BUILD_LIB_VERSION_HASH_SET ON)
endif()

configure_file("${RS_STAMP_TEMPLATE}" "${RS_STAMP_OUTPUT}" @ONLY)
