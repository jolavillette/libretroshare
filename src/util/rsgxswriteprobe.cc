/*******************************************************************************
 * libretroshare/src/util: rsgxswriteprobe.cc                                  *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright (C) 2026  Retroshare Team <contact@retroshare.cc>                 *
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
#include "util/rsgxswriteprobe.h"

#include <chrono>
#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <thread>

#include "retroshare/rsversion.h"

namespace
{
std::mutex sMtx;
FILE* sFile = nullptr;
bool sCapReached = false;
long sBytes = 0;
const long CAP_BYTES = 512L * 1024 * 1024;

struct TxCount { long n = 0; long changes = 0; long failed = 0; };
std::map<std::string, std::map<std::string, TxCount> > sCounts;	// db -> tag -> count
std::chrono::steady_clock::time_point sLastSummary = std::chrono::steady_clock::now();
const int SUMMARY_PERIOD_S = 60;

thread_local std::string tTag;

// Caller must hold sMtx.
void locked_writeLine(const char* layer, const std::string& msg)
{
	if(!sFile || sCapReached) return;

	const auto now = std::chrono::system_clock::now();
	const std::time_t t = std::chrono::system_clock::to_time_t(now);
	const long ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
	std::tm tmv = *std::localtime(&t);
	char stamp[32];
	std::strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);

	const unsigned tid = (unsigned)(std::hash<std::thread::id>()(std::this_thread::get_id()) & 0xffff);

	const int written = std::fprintf(sFile, "%s.%03ld [%04x] %-2s %s\n", stamp, ms, tid, layer, msg.c_str());
	std::fflush(sFile);

	if(written > 0) sBytes += written;
	if(sBytes > CAP_BYTES)
	{
		std::fprintf(sFile, "%s.%03ld [%04x] -- log size cap reached, probe stops here\n", stamp, ms, tid);
		std::fflush(sFile);
		sCapReached = true;
	}
}

// Caller must hold sMtx.
void locked_maybeSummary()
{
	const auto now = std::chrono::steady_clock::now();
	if(std::chrono::duration_cast<std::chrono::seconds>(now - sLastSummary).count() < SUMMARY_PERIOD_S)
		return;

	for(const auto& db : sCounts)
	{
		std::ostringstream oss;
		long total = 0, totalChanges = 0, totalFailed = 0;
		for(const auto& tag : db.second)
		{
			total += tag.second.n; totalChanges += tag.second.changes; totalFailed += tag.second.failed;
			oss << " " << tag.first << "=" << tag.second.n << "/" << tag.second.changes;
			if(tag.second.failed) oss << "(failed " << tag.second.failed << ")";
		}
		std::ostringstream line;
		line << "SUMMARY last " << SUMMARY_PERIOD_S << "s db=" << db.first
		     << " tx=" << total << " changes=" << totalChanges << " failed=" << totalFailed
		     << " by tag (tx/changes):" << oss.str();
		locked_writeLine("--", line.str());
	}
	sCounts.clear();
	sLastSummary = now;
}
}

namespace GxsWriteProbe
{
void init(const std::string& gxsDir)
{
	std::lock_guard<std::mutex> lock(sMtx);
	if(sFile) return;

	const std::string path = gxsDir + "/gxs-write-probe.log";
	sFile = std::fopen(path.c_str(), "a");
	if(!sFile) return;

	std::ostringstream oss;
	oss << "==== probe start, libretroshare " << RS_MAJOR_VERSION << "." << RS_MINOR_VERSION << "." << RS_MINI_VERSION << RS_EXTRA_VERSION
	    << ", cap " << (CAP_BYTES >> 20) << " MB, summary every " << SUMMARY_PERIOD_S << "s";
	locked_writeLine("--", oss.str());
	locked_writeLine("--", "line format: date time [thread] LAYER message ; LAYER = DB (sqlite), DS (data service), GX (gen exchange), NS (net service), GT (gxs trans)");
}

bool enabled()
{
	return sFile != nullptr && !sCapReached;
}

void write(const char* layer, const std::string& msg)
{
	std::lock_guard<std::mutex> lock(sMtx);
	locked_writeLine(layer, msg);
	locked_maybeSummary();
}

FILE* file()
{
	return sFile;
}

void countTx(const std::string& db, const std::string& tag, int changes, bool ok)
{
	std::lock_guard<std::mutex> lock(sMtx);
	TxCount& c = sCounts[db][tag.empty() ? "untagged" : tag];
	++c.n;
	c.changes += changes;
	if(!ok) ++c.failed;
	locked_maybeSummary();
}

std::string currentTag()
{
	return tTag;
}

ScopedTag::ScopedTag(const std::string& tag) : mPrevious(tTag)
{
	tTag = tag;
}

ScopedTag::~ScopedTag()
{
	tTag = mPrevious;
}
}
