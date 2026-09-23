/*******************************************************************************
 * libretroshare/src/util: rsgxswriteprobe.h                                   *
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
#pragma once

#include <cstdio>
#include <sstream>
#include <string>

/**
 * Debug-only probe that records every write reaching the GXS databases, and
 * the upper-layer events that cause them, into <account>/gxs/gxs-write-probe.log.
 *
 * Purpose: track down a runaway write pattern reported on Windows (rollback
 * journal of gxstrans_db created/deleted several times per second). The log is
 * always on in this build, self-contained (no --log-file needed), flushed at
 * every line so that it survives a kill, and capped in size.
 *
 * Layers:
 *   DB  RetroDb statements/transactions (ground truth: one TX line = one
 *       journal create/delete when changes > 0)
 *   DS  RsDataService write API calls, which also set the thread-local tag
 *       reported by the DB lines
 *   GX  RsGenExchange producers (received data, meta changes, publish, delete)
 *   NS  RsGxsNetService sync traffic (requests, responses, completed transactions)
 *   GT  p3GxsTrans (cleanup thread, group policy, mail queues)
 */
namespace GxsWriteProbe
{
/// Opens the log file in gxsDir on first call, no-op afterwards.
void init(const std::string& gxsDir);

bool enabled();

/// Writes one timestamped line. Thread-safe, flushes immediately.
void write(const char* layer, const std::string& msg);

/// Underlying file, for print_stacktrace(). May be nullptr.
FILE* file();

/// Feeds the per-minute summary (transactions per database and per tag).
void countTx(const std::string& db, const std::string& tag, int changes, bool ok);

/// Thread-local tag naming the RsDataService operation in progress.
std::string currentTag();

struct ScopedTag
{
	explicit ScopedTag(const std::string& tag);
	~ScopedTag();
private:
	std::string mPrevious;
};

/// First 8 hex chars of an id, enough to correlate lines.
template<class ID> std::string shortId(const ID& id)
{
	const std::string s = id.toStdString();
	return s.size() > 8 ? s.substr(0, 8) : s;
}
}

#define GXS_PROBE(layer, expr) do { \
		if(GxsWriteProbe::enabled()) { \
			std::ostringstream _probe_oss; _probe_oss << expr; \
			GxsWriteProbe::write(layer, _probe_oss.str()); } \
	} while(false)
