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

/* Estimates the size of the DHT and of its RetroShare part, as ranges.
 *
 * RetroShare nodes: every minute the RS nodes (DHT_ENGINE flag) of our
 * routing table are recorded with the time intervals they were in it.
 * Low end = distinct RS nodes seen over the last 24 h; high end = bias
 * corrected Chao1 over up to 7 occasions spread on the last 7 days, which
 * adds the nodes we are likely to have missed.
 *
 * Whole DHT: when libbitdht offers BITDHT_QFLAGS_MEASURE, one find_node
 * towards a random id every few minutes. The XOR distance d_k of the k-th
 * closest node gives N ~ (k - 1) / d_k. Low end = over the nodes that
 * answered us; high end = over every node heard of near the target, the
 * silent ones included (most DHT nodes do not answer an unknown node).
 * Medians over the recent lookups.
 *
 * The data survive restarts (dht-size.txt in the account directory). */
class DhtSizeEstimator
{
public:
	DhtSizeEstimator();

	/* From p3BitDht::tick(); does its work at most once a minute. */
	void tick(UdpBitDht *dht);

	/* Writes the data to disk (also done every SAVE_PERIOD). */
	void save();

	void getEstimate(RsDhtSizeEstimate &est);

private:
	struct Interval { rstime_t s; rstime_t e; };
	struct Node
	{
		Node() : last(0), inTable(false) {}
		rstime_t last;
		bool inTable;
		std::vector<Interval> iv;
	};
	struct LookupSample { rstime_t t; double answered; double heard; };

	void poll_locked(UdpBitDht *dht, rstime_t now);
	void lookup_locked(UdpBitDht *dht, rstime_t now);
	void estimate_locked(rstime_t now);
	void prune_locked(rstime_t now);
	void load_locked();
	void save_locked();

	RsMutex mMtx;
	bool mLoaded;
	std::string mFile;

	std::map<std::string, Node> mNodes;  /* RS nodes, by hex DHT id */
	std::vector<Interval> mObs;          /* when we were polling */
	rstime_t mDataStart;

	bool mLookupRunning;
	bdNodeId mLookupId;
	rstime_t mLookupStart;
	rstime_t mLastLookupEnd;
	std::deque<LookupSample> mLookupSamples;

	rstime_t mLastPoll;
	rstime_t mLastSave;

	RsDhtSizeEstimate mEst;
};
