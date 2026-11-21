/*******************************************************************************
 * libretroshare/src/util: rsstd.h                                             *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (c) 2010, Thomas Kister                                           *
 *                                                                             *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU Lesser General Public License as              *
 * published by the Free Software Foundation, either version 3 of the          *
 * License, or (at your option) any later version.                             *
 *                                                                             *
 * This program is distributed in the hope that it will be useful,             *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the                *
 * GNU Lesser General Public License for more details.                         *
 *                                                                             *
 * You should have received a copy of the GNU Lesser General Public License    *
 * along with this program. If not, see <https://www.gnu.org/licenses/>.       *
 *                                                                             *
 *******************************************************************************/
#ifndef RSSTRING_H_
#define RSSTRING_H_

#include <string>
#include <stdarg.h>

namespace librs {
	namespace util {

		bool ConvertUtf8ToUtf16(const std::string& source, std::wstring& dest);
		bool ConvertUtf16ToUtf8(const std::wstring& source, std::string& dest);
#if 0
		bool is_alphanumeric(char c) ;
		bool is_alphanumeric(const std::string& s);
#endif
} } // librs::util

#ifdef WIN32
#define INT64FMT "%I64d"
#define UINT64FMT "%I64u"
#else
#define INT64FMT "%lld"
#define UINT64FMT "%llu"
#endif

int rs_sprintf_args(std::string &str, const char *fmt, va_list ap);
int rs_sprintf(std::string &str, const char *fmt, ...);
int rs_sprintf_append_args(std::string &str, const char *fmt, va_list ap);
int rs_sprintf_append(std::string &str, const char *fmt, ...);

void stringToUpperCase(const std::string& s, std::string &upper);
void stringToLowerCase(const std::string& s, std::string &lower);

/**
 * Case-fold an UTF-8 string so that two strings differing only by letter case
 * compare equal byte by byte. Unlike stringToLowerCase() this is not limited
 * to ASCII: it handles Latin-1, Latin Extended-A, Latin Extended Additional,
 * Greek, Cyrillic, Armenian and fullwidth Latin letters. It does not depend on
 * the C/C++ locale. Invalid UTF-8 bytes are copied unchanged.
 */
std::string utf8FoldCase(const std::string& s);

/** Case-insensitive (see utf8FoldCase) substring search on UTF-8 strings. */
bool utf8ContainsIgnoreCase(const std::string& haystack, const std::string& needle);

/** Case-insensitive (see utf8FoldCase) equality of UTF-8 strings. */
bool utf8EqualsIgnoreCase(const std::string& a, const std::string& b);

bool isHexaString(const std::string& s);

#endif // RSSTRING_H_
