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

#include "rsstring.h"

#ifdef WINDOWS_SYS
#include <windows.h>
#include <malloc.h>
#else
#include <vector>
#include <stdarg.h>
#include <stdlib.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <algorithm>

namespace librs { namespace util {

bool ConvertUtf8ToUtf16(const std::string& source, std::wstring& dest)
{
	if (source.empty()) {
		dest.clear();
		return true;
	}

#ifdef WINDOWS_SYS
	int nbChars = MultiByteToWideChar(CP_UTF8, 0, source.c_str(), -1, 0, 0);
	if(nbChars == 0) {
		return false;
	}

	wchar_t* utf16Name = new wchar_t[nbChars];
	if( MultiByteToWideChar(CP_UTF8, 0, source.c_str(), -1, utf16Name, nbChars) == 0) {
		delete[] utf16Name;
		return false;
	}

	dest = utf16Name;
	delete[] utf16Name;
#else
	std::vector<wchar_t> res;
	std::string::size_type len = source.length();

	unsigned int i = 0;
	unsigned long temp;

	while (i < len) {
		char src = source[i];
		if ((src & 0x80) == 0) { // ASCII : 0000 0000-0000 007F 0xxxxxxx
			temp = src;
			++i;
		} else if ((src & 0xE0) == 0xC0) { // 0000 0080-0000 07FF 110xxxxx 10xxxxxx
			temp = (src & 0x1F);
			temp <<= 6;
			temp += (source[i + 1] & 0x3F);
			i += 2;
		} else if ((src & 0xF0) == 0xE0) { // 0000 0800-0000 FFFF 1110xxxx 10xxxxxx 10xxxxxx
			temp = (src & 0x0F);
			temp <<= 6;
			temp += (source[i + 1] & 0x3F);
			temp <<= 6;
			temp += (source[i + 2] & 0x3F);
			i += 3;
		} else if ((src & 0xF8) == 0xF0) { // 0001 0000-001F FFFF 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
			temp = (src & 0x07);
			temp <<= 6;
			temp += (source[i + 1] & 0x3F);
			temp <<= 6;
			temp += (source[i + 2] & 0x3F);
			temp <<= 6;
			temp += (source[i + 3] & 0x3F);
			i += 4;
		} else if ((src & 0xFC) == 0xF8) { // 0020 0000-03FF FFFF 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			temp = (src & 0x03);
			temp <<= 6;
			temp += (source[i + 1] & 0x3F);
			temp <<= 6;
			temp += (source[i + 2] & 0x3F);
			temp <<= 6;
			temp += (source[i + 3] & 0x3F);
			temp <<= 6;
			temp += (source[i + 4] & 0x3F);
			i += 5;
		} else if ((src & 0xFE) == 0xFC) { // 0400 0000-7FFF FFFF 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			temp = (src & 0x01);
			temp <<= 6;
			temp += (source[i + 1] & 0x3F);
			temp <<= 6;
			temp += (source[i + 2] & 0x3F);
			temp <<= 6;
			temp += (source[i + 3] & 0x3F);
			temp <<= 6;
			temp += (source[i + 4] & 0x3F);
			temp <<= 6;
			temp += (source[i + 5] & 0x3F);
			i += 6;
		} else {
			temp = '?';
		}
		// Need to transform to UTF-16 > handle surrogates
		if (temp > 0xFFFF) {
			// First high surrogate
			res.push_back(0xD800 + wchar_t(temp >> 10));
			// Now low surrogate
			res.push_back(0xDC00 + wchar_t(temp & 0x3FF));
		} else {
			res.push_back(wchar_t(temp));
		}
	}
	// Check whether first wchar_t is the BOM 0xFEFF
	if (res[0] == 0xFEFF) {
		dest.append(&res[1], res.size() - 1);
	} else {
		dest.append(&res[0], res.size());
	}
#endif

	return true;
}

bool ConvertUtf16ToUtf8(const std::wstring& source, std::string& dest)
{
#ifdef WINDOWS_SYS
	int nbChars = WideCharToMultiByte(CP_UTF8, 0, source.c_str(), -1, 0, 0, 0, 0);
	if(nbChars == 0) {
		return false;
	}

	char* utf8Name = new char[nbChars];
	if( WideCharToMultiByte(CP_UTF8, 0, source.c_str(), -1, utf8Name, nbChars, 0, 0) == 0) {
		delete[] utf8Name;
		return false;
	}

	dest = utf8Name;
	delete[] utf8Name;
#else
	std::vector<char> res;

	std::wstring::size_type len = source.length();
	unsigned int i = 0;
	unsigned long temp;

	while (i < len) {
		if ((source[i] & 0xD800) == 0xD800) { // surrogate
			temp = (source[i] - 0xD800);
			temp <<= 10;
			temp += (source[i + 1] - 0xDC00);
			i += 2;
		} else {
			temp = source[i];
			++i;
		}
		if (temp < 0x00000080) { // ASCII : 0000 0000-0000 007F 0xxxxxxx
			res.push_back(char(temp));
		} else if (temp < 0x00000800) { // 0000 0080-0000 07FF 110xxxxx 10xxxxxx
			res.push_back(char(0xC0 | (temp >> 6)));
			res.push_back(char(0x80 | (temp & 0x3F)));
		} else if (temp < 0x00010000) { // 0000 0800-0000 FFFF 1110xxxx 10xxxxxx 10xxxxxx
			res.push_back(char(0xE0 | (temp >> 12)));
			res.push_back(char(0x80 | ((temp >> 6) & 0x3F)));
			res.push_back(char(0x80 | (temp & 0x3F)));
		} else if (temp < 0x00200000) { // 0001 0000-001F FFFF 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
			res.push_back(char(0xF0 | (temp >> 18)));
			res.push_back(char(0x80 | ((temp >> 12) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 6) & 0x3F)));
			res.push_back(char(0x80 | (temp & 0x3F)));
		} else if (temp < 0x04000000) { // 0020 0000-03FF FFFF 111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			res.push_back(char(0xF8 | (temp >> 24)));
			res.push_back(char(0x80 | ((temp >> 18) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 12) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 6) & 0x3F)));
			res.push_back(char(0x80 | (temp & 0x3F)));
		} else if (temp < 0x80000000) { // 0400 0000-7FFF FFFF 1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
			res.push_back(char(0xFC | (temp >> 30)));
			res.push_back(char(0x80 | ((temp >> 24) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 18) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 12) & 0x3F)));
			res.push_back(char(0x80 | ((temp >> 6) & 0x3F)));
			res.push_back(char(0x80 | (temp & 0x3F)));
		}
	}

	dest.append(&res[0], res.size());
#endif

	return true;
}

#if 0
bool is_alphanumeric(char c)
{
	return (c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z');
}

bool is_alphanumeric(const std::string& s)
{
	for( uint32_t i=0; i < s.size(); ++i)
		if(!is_alphanumeric(s[i])) return false;
	return true;
}
#endif

} } // librs::util

#ifdef WINDOWS_SYS
// asprintf() and vasprintf() are missing in Win32
static int vasprintf(char **sptr, const char *fmt, va_list argv)
{
	int wanted = __mingw_vsnprintf(*sptr = NULL, 0, fmt, argv);
	if ((wanted > 0) && ((*sptr = (char*) malloc(wanted + 1)) != NULL)) {
		return __mingw_vsprintf(*sptr, fmt, argv);
	}

	return wanted;
}

//static int asprintf(char **sptr, const char *fmt, ...)
//{
//	int retval;
//	va_list argv;
//	va_start( argv, fmt );
//	retval = vasprintf(sptr, fmt, argv);
//	va_end(argv);
//	return retval;
//}
#endif

int rs_sprintf_args(std::string &str, const char *fmt, va_list ap)
{
	char *buffer = NULL;

	int retval = vasprintf(&buffer, fmt, ap);

	if (retval >= 0) {
		if (buffer) {
			str = buffer;
			free(buffer);
		} else {
			str.clear();
		}
	} else {
		str.clear();
	}

	return retval;
}

int rs_sprintf(std::string &str, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int retval = rs_sprintf_args(str, fmt, ap);
	va_end(ap);

	return retval;
}

int rs_sprintf_append_args(std::string &str, const char *fmt, va_list ap)
{
	char *buffer = NULL;

	int retval = vasprintf(&buffer, fmt, ap);

	if (retval >= 0) {
		if (buffer) {
			str.append(buffer);
			free(buffer);
		}
	}

	return retval;
}

int rs_sprintf_append(std::string &str, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	int retval = rs_sprintf_append_args(str, fmt, ap);
	va_end(ap);

	return retval;
}

void stringToUpperCase(const std::string& s, std::string &upper)
{
	upper = s ;

	for(uint32_t i=0;i<upper.size();++i)
		if(upper[i] > 96 && upper[i] < 123)
			upper[i] -= 97-65 ;
}

void stringToLowerCase(const std::string& s, std::string &lower)
{
	lower = s ;

	for(uint32_t i=0;i<lower.size();++i)
		if(lower[i] > 64 && lower[i] < 91)
			lower[i] += 97-65 ;
}

/* Simple (one to one) lower case mapping of a code point. Only covers the
 * scripts in which case matters and that file names commonly use. */
static uint32_t foldCodePoint(uint32_t c)
{
	if(c < 0x80) return (c >= 'A' && c <= 'Z') ? c + 32 : c;

	// Latin-1 Supplement
	if(c >= 0xC0 && c <= 0xDE && c != 0xD7) return c + 32;

	// Latin Extended-A
	if(c == 0x130) return 'i'; // LATIN CAPITAL LETTER I WITH DOT ABOVE
	if(c >= 0x100 && c <= 0x137) return c | 1;
	if(c >= 0x139 && c <= 0x148) return (c & 1) ? c + 1 : c;
	if(c >= 0x14A && c <= 0x177) return c | 1;
	if(c == 0x178) return 0xFF;
	if(c >= 0x179 && c <= 0x17E) return (c & 1) ? c + 1 : c;

	// Greek
	if(c == 0x386) return 0x3AC;
	if(c >= 0x388 && c <= 0x38A) return c + 37;
	if(c == 0x38C) return 0x3CC;
	if(c == 0x38E || c == 0x38F) return c + 63;
	if(c >= 0x391 && c <= 0x3AB && c != 0x3A2) return c + 32;
	if(c == 0x3C2) return 0x3C3; // final sigma

	// Cyrillic
	if(c >= 0x400 && c <= 0x40F) return c + 80;
	if(c >= 0x410 && c <= 0x42F) return c + 32;
	if(c >= 0x460 && c <= 0x481) return c | 1;
	if(c >= 0x48A && c <= 0x4BF) return c | 1;
	if(c == 0x4C0) return 0x4CF;
	if(c >= 0x4C1 && c <= 0x4CE) return (c & 1) ? c + 1 : c;
	if(c >= 0x4D0 && c <= 0x52F) return c | 1;

	// Armenian
	if(c >= 0x531 && c <= 0x556) return c + 48;

	// Latin Extended Additional (Vietnamese, Welsh...)
	if(c >= 0x1E00 && c <= 0x1E95) return c | 1;
	if(c >= 0x1EA0 && c <= 0x1EFF) return c | 1;

	// Fullwidth Latin
	if(c >= 0xFF21 && c <= 0xFF3A) return c + 32;

	return c;
}

static void appendUtf8(std::string& out, uint32_t c)
{
	if(c < 0x80) out += static_cast<char>(c);
	else if(c < 0x800)
	{
		out += static_cast<char>(0xC0 | (c >> 6));
		out += static_cast<char>(0x80 | (c & 0x3F));
	}
	else if(c < 0x10000)
	{
		out += static_cast<char>(0xE0 | (c >> 12));
		out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
		out += static_cast<char>(0x80 | (c & 0x3F));
	}
	else
	{
		out += static_cast<char>(0xF0 | (c >> 18));
		out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
		out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
		out += static_cast<char>(0x80 | (c & 0x3F));
	}
}

static bool isAscii(const std::string& s)
{
	for(unsigned char ch : s) if(ch >= 0x80) return false;
	return true;
}

std::string utf8FoldCase(const std::string& s)
{
	std::string out;
	out.reserve(s.size());

	const size_t n = s.size();
	size_t i = 0;
	while(i < n)
	{
		const unsigned char b0 = static_cast<unsigned char>(s[i]);

		if(b0 < 0x80)
		{
			out += static_cast<char>((b0 >= 'A' && b0 <= 'Z') ? b0 + 32 : b0);
			++i;
			continue;
		}

		size_t len; uint32_t c, min;
		if((b0 & 0xE0) == 0xC0)      { len = 2; c = b0 & 0x1F; min = 0x80; }
		else if((b0 & 0xF0) == 0xE0) { len = 3; c = b0 & 0x0F; min = 0x800; }
		else if((b0 & 0xF8) == 0xF0) { len = 4; c = b0 & 0x07; min = 0x10000; }
		else { out += s[i++]; continue; } // stray continuation or invalid byte

		bool valid = i + len <= n;
		for(size_t k = 1; valid && k < len; ++k)
		{
			const unsigned char bk = static_cast<unsigned char>(s[i+k]);
			if((bk & 0xC0) != 0x80) valid = false;
			else c = (c << 6) | (bk & 0x3F);
		}
		// Reject overlong forms, surrogates and out of range values so that
		// re-encoding never changes bytes we do not fold.
		if(valid && (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)))
			valid = false;

		if(!valid) { out += s[i++]; continue; }

		appendUtf8(out, foldCodePoint(c));
		i += len;
	}

	return out;
}

bool utf8ContainsIgnoreCase(const std::string& haystack, const std::string& needle)
{
	if(isAscii(haystack) && isAscii(needle))
	{
		auto eq = [](char a, char b)
		{
			if(a >= 'A' && a <= 'Z') a += 32;
			if(b >= 'A' && b <= 'Z') b += 32;
			return a == b;
		};
		return std::search( haystack.begin(), haystack.end(),
		                    needle.begin(), needle.end(), eq ) != haystack.end();
	}

	return utf8FoldCase(haystack).find(utf8FoldCase(needle)) != std::string::npos;
}

bool utf8EqualsIgnoreCase(const std::string& a, const std::string& b)
{
	return utf8FoldCase(a) == utf8FoldCase(b);
}

bool isHexaString(const std::string& s)
{
	for(uint32_t i=0;i<s.length();++i)
		if(!((s[i] >= 'A' && s[i] <= 'F') || (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
		return false ;

	return true ;
}
