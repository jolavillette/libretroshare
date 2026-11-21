## ------------------------------------------------------------------------- ##
 # mk/cmake/RetroShareInstallRpath.cmake
 # This file is part of libRetroShare.
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

cmake_minimum_required(VERSION 3.13...4.4)

# retroshare_install_rpath(<target> <executable install directory>)
#
# For a program that links libretroshare. When libretroshare is a shared
# library built in the same build, it is installed with the program, in
# RS_LIB_INSTALL_DIR: give the installed executable a run-time search path
# relative to itself, so that it finds the library wherever the install tree
# is put. <executable install directory> is where the executable file is
# installed, relative to the install prefix (inside the bundle on macOS).
#
# Does nothing on Windows (a program loads its DLLs from its own directory),
# with a static libretroshare, or with a libretroshare found installed.
function(retroshare_install_rpath target executable_install_dir)
	if(WIN32)
		return()
	endif()
	get_target_property(imported retroshare::retroshare IMPORTED)
	get_target_property(type retroshare::retroshare TYPE)
	if(imported OR NOT type STREQUAL "SHARED_LIBRARY")
		return()
	endif()
	if(IS_ABSOLUTE "${RS_LIB_INSTALL_DIR}")
		return()
	endif()
	if(APPLE)
		set(origin "@executable_path")
	else()
		set(origin "$ORIGIN")
	endif()
	file(RELATIVE_PATH library_from_executable
		"/${executable_install_dir}" "/${RS_LIB_INSTALL_DIR}"
	)
	set_property(TARGET ${target} APPEND PROPERTY
		INSTALL_RPATH "${origin}/${library_from_executable}"
	)
endfunction()
