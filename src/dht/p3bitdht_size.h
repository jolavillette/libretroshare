/*******************************************************************************
 * libretroshare/src/dht: p3bitdht_size.h                                      *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * This program is free software: you can redistribute it and/or modify        *
 * it under the terms of the GNU Lesser General Public License as              *
 * published by the Free Software Foundation, either version 3 of the          *
 * License, or (at your option) any later version.                             *
 *                                                                             *
 * This program is distributed in the hope that it will be useful,             *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               *
 * GNU Lesser General Public License for more details.                         *
 *                                                                             *
 * You should have received a copy of the GNU Lesser General Public License    *
 * along with this program. If not, see <https://www.gnu.org/licenses/>.       *
 *                                                                             *
 ******************************************************************************/
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "bitdht/bdiface.h"
#include "retroshare/rsdht.h"
#include "util/rsthreads.h"
#include "util/rstime.h"

class UdpBitDht;

/* Estimates how many nodes the DHT and its RetroShare part have, as ranges.
 *
 * Random-target lookups (libbitdht BITDHT_QFLAGS_MEASURE), two kinds run side
 * by side: over the whole DHT, and over RetroShare nodes only
 * (BITDHT_QFLAGS_MEASURE_APPL). The XOR distance d_k of the k-th closest node
 * to a random target gives the density: N = median of (k - 1/3) / d_k over
 * the recent lookups (unbiased, and one lookup stuck far from its target
 * cannot drag it). Two counts per lookup:
 *   - reachable: the nodes that answered us;
 *   - heard: those plus the silent ones at least two nodes reported (one
 *     report only is often a stale entry or a forged id).
 * The range shown goes from the low end of the reachable confidence interval
 * to the high end of the heard one (bootstrap over the lookups, 10-90 %).
 *
 * Two RetroShare checks, independent of the lookups:
 *   - the RS nodes of our own routing table, each minute; with the RS nodes
 *     the lookups met over the same 24 h they give a Chapman estimate of the
 *     distinct RS nodes online during the day;
 *   - our friends present in the DHT: the share of them our table holds
 *     calibrates how much of the RS network the table sees.
 *
 * The data survive restarts (dht-size.txt in the account directory). */
class DhtSizeEstimator
{
public:
	DhtSizeEstimator();

	/* true when tick() would do its once-a-minute work */
	bool due();

	/* From p3BitDht::tick(). friendsInDht = DHT ids of our friends the DHT
	 * currently finds. */
	void tick(UdpBitDht *dht, const std::vector<bdNodeId> &friendsInDht);

	/* Writes the data to disk (also done every SAVE_PERIOD). */
	void save();

	void getEstimate(RsDhtSizeEstimate &est);

private:
	/* one lookup result: k-th distance over the answered nodes and over the
	 * heard ones (fraction of the id space) */
	struct Sample { rstime_t t; int kA; double dA; int kH; double dH; };

	struct Kind
	{
		Kind() : flags(0), running(false), start(0), lastEnd(0) {}
		uint32_t flags;
		bool running;
		bdNodeId id;
		rstime_t start;
		rstime_t lastEnd;
		std::deque<Sample> samples;
	};
	enum { KIND_ALL = 0, KIND_RS = 1, NKINDS = 2 };

	struct PollStat { rstime_t t; uint32_t rsInTable; uint32_t friends; uint32_t friendsInTable; };

	void lookup_locked(UdpBitDht *dht, Kind &k, int kind, rstime_t now);
	void poll_locked(UdpBitDht *dht, const std::vector<bdNodeId> &friendsInDht, rstime_t now);
	void prune_locked(rstime_t now);
	void estimate_locked(rstime_t now);
	void load_locked();
	void save_locked();

	RsMutex mMtx;
	bool mLoaded;
	std::string mFile;

	Kind mKinds[NKINDS];
	std::map<std::string, rstime_t> mTableSeen; /* RS nodes of our table, last seen */
	std::map<std::string, rstime_t> mWalkSeen;  /* RS nodes RS lookups met, last seen */
	std::deque<PollStat> mPolls;                /* last 24 h, not saved */
	rstime_t mObsStart;                         /* first poll of the data kept */

	rstime_t mLastPoll;
	rstime_t mLastSave;

	RsDhtSizeEstimate mEst;
};
