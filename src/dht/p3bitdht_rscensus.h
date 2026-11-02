/*******************************************************************************
 * libretroshare/src/dht: p3bitdht_rscensus.h                                  *
 *                                                                             *
 * TEMPORARY DIAGNOSTICS - do not upstream.                                    *
 *                                                                             *
 * Census of the RetroShare (libbitdht engine) nodes seen in our DHT routing   *
 * table, and every estimator of their number we could think of, logged side   *
 * by side under the "DHT-RS" tag so they can be compared on a live node.      *
 *                                                                             *
 * Every minute the 160 buckets are read. Each RS node (DHT_ENGINE flag) is    *
 * remembered by its DHT id with the time intervals during which it was in     *
 * the table. The census survives restarts (dht-rs-census.csv in the account   *
 * directory); the per-poll libbitdht estimates go to dht-rs-samples.csv.      *
 * The total DHT size is also measured by random-target lookups.              *
 *                                                                             *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU Lesser General Public License as              *
 * published by the Free Software Foundation, either version 3 of the          *
 * License, or (at your option) any later version.                             *
 *                                                                             *
 ******************************************************************************/
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "bitdht/bdiface.h"
#include "util/rsthreads.h"
#include "util/rstime.h"

class UdpBitDht;
class bdDhtFunctions;

class DhtRsCensus
{
public:
	DhtRsCensus();

	/* Called from p3BitDht::tick(); does its work at most once a minute.
	 * bdAll / bdRs = the two numbers libbitdht reports today. */
	void tick(UdpBitDht *dht, bdDhtFunctions *fns, uint32_t bdAll, uint32_t bdRs);

	/* Writes the census to disk (called on DHT shutdown). */
	void save();

private:
	struct Interval { rstime_t s; rstime_t e; };

	struct Node
	{
		Node() : first(0), last(0), polls(0), bucket(-1), inTable(false), enter(0) {}
		rstime_t first;
		rstime_t last;
		uint32_t polls;
		int bucket;
		bool inTable;
		rstime_t enter;
		std::vector<Interval> iv;
	};

	struct Sample { rstime_t t; uint32_t rsBd; uint32_t allBd; };

	/* Random-target lookups measuring the total DHT size: a find_node towards
	 * a random id; the XOR distance of the k-th closest node that answered
	 * gives N ~ (k - 1) / d_k (d_k as a fraction of the id space). */
	struct Lookup { bdNodeId id; rstime_t start; };
	struct LookupSample
	{
		rstime_t t;
		double n;           /* (k - 1) / d_k */
		int k;
		uint32_t answered;  /* nodes of mClosest that answered */
		uint32_t answeredRs;
	};

	void lookups_locked(UdpBitDht *dht, rstime_t now);

	void poll_locked(UdpBitDht *dht, bdDhtFunctions *fns, rstime_t now,
	                 uint32_t bdAll, uint32_t bdRs);
	void load_locked();
	void save_locked();
	void prune_locked(rstime_t now);

	/* true if the node was in the table at some point of [a, b] */
	static bool seenIn(const Node &n, rstime_t a, rstime_t b);
	/* observed (polled) time inside [a, b], seconds */
	rstime_t observed_locked(rstime_t a, rstime_t b) const;
	/* masks of the k equal occasions of [now - w, now] each node was seen in */
	void occasions_locked(rstime_t now, rstime_t w, int k, std::vector<uint32_t> &masks) const;

	RsMutex mMtx;
	bool mLoaded;
	std::string mCensusFile;
	std::string mSamplesFile;

	std::map<std::string, Node> mNodes;
	std::vector<Interval> mObs;              /* when we were polling */
	std::deque<Sample> mSamples;             /* last 24 h of libbitdht estimates */
	std::deque<std::pair<rstime_t, rstime_t> > mGone; /* (time, dwell) last 1 h */

	std::map<std::string, Lookup> mLookups;  /* running, by hex target */
	std::deque<LookupSample> mLookupSamples; /* last LOOKUP_KEEP results */
	uint32_t mLookupsLost;                   /* vanished (DHT restart) or empty */

	rstime_t mSessionStart;
	rstime_t mDataStart;
	rstime_t mLastPoll;
	rstime_t mLastEst;
	rstime_t mLastSave;
};
