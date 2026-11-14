/*******************************************************************************
 * libretroshare/src/dht: p3bitdht_rscensus.cc                                 *
 *                                                                             *
 * TEMPORARY DIAGNOSTICS - do not upstream. See p3bitdht_rscensus.h.           *
 *                                                                             *
 * This program is free software: you can redistribute it and/or modify       *
 * it under the terms of the GNU Lesser General Public License as              *
 * published by the Free Software Foundation, either version 3 of the          *
 * License, or (at your option) any later version.                             *
 *                                                                             *
 ******************************************************************************/

#include "dht/p3bitdht_rscensus.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

#include "bitdht/bdiface.h"
#include "bitdht/bdpeer.h"
#include "bitdht/bdstddht.h"
#include "udp/udpbitdht.h"
#include "retroshare/rsinit.h"
#include "util/rsdebug.h"
#include "util/rsdir.h"

static const rstime_t POLL_PERIOD      = 60;
static const rstime_t EST_FAST_PERIOD  = 60;    /* first 30 min of a session */
static const rstime_t EST_SLOW_PERIOD  = 300;
static const rstime_t FAST_PHASE       = 1800;
static const rstime_t SAVE_PERIOD      = 600;
static const rstime_t OBS_GAP          = 3 * POLL_PERIOD; /* longer = we were not polling */
static const rstime_t HOUR             = 3600;
static const rstime_t DAY              = 24 * HOUR;
static const rstime_t WEEK             = 7 * DAY;
static const int      NBUCKETS         = BITDHT_KEY_BITLEN; /* 160 */

/* random-target lookups (total DHT size) */
/* 0: the probe no longer runs its own lookups. feature/dht-size-estimates
 * runs two measure lookups of its own, and with these two more they starved
 * each other of libbitdht's measure budget: most ran into the 300 s cap and
 * were thrown away (2026-11-03). The census part of the probe still runs. */
static const size_t   LOOKUP_PARALLEL  = 0;     /* running at once */
static const size_t   LOOKUP_KEEP      = 30;    /* results the median is taken over */
static const int      LOOKUP_K         = 8;     /* k-th closest answering node */
/* libbitdht's own 300 s cap is only checked once every peer of the closest
 * list was asked, and its send budget is shared round-robin with every
 * friend query: the first live lookups were still QUERYING after 360 s. */
#ifdef BITDHT_QFLAGS_MEASURE
/* libbitdht feature/dht-measure-lookups: direct, prioritised, ends at 300 s */
static const uint32_t LOOKUP_QFLAGS    = BITDHT_QFLAGS_MEASURE;
static const char    *LOOKUP_MODE      = "measure";
static const rstime_t LOOKUP_TIMEOUT   = 360;
#else
static const uint32_t LOOKUP_QFLAGS    = BITDHT_QFLAGS_NONE;
static const char    *LOOKUP_MODE      = "plain";
static const rstime_t LOOKUP_TIMEOUT   = 1200;
#endif

static const char *SCHEMA_KEYS =
	"rs_bd,rs_bd_recalc,rs_bd_old,rs_bd_fixfull,rs_cum,rs_cum_fixfull,"
	"rs_bd_med24h,rs_count_now,rs_count_1h,rs_count_24h,rs_count_7d,"
	"rs_chapman_1h,rs_chapman_1h_nostable,rs_chapman_24h,rs_schnabel_24h,"
	"rs_chao1_24h,rs_chao1_7d,"
	"all_bd,all_bd_recalc,all_bd_old,all_cum,all_bd_med24h,"
	"all_lookup,all_lookup_n,all_lookup_any,all_lookup_any_n,rs_lookup,all_lookup_heard";

/*****************************************************************************
 * Instant estimators, from the per-bucket counts.
 *   n[i]   = entries of bucket i matching the flag filter
 *   occ[i] = all entries of bucket i (real occupancy)
 * Bucket i holds the nodes at XOR distance [2^i, 2^(i+1)), i.e. a fraction
 * 2^(i-160) of the id space.
 *****************************************************************************/

/* Exact copy of bdSpace::calcNetworkSizeWithFlag (libbitdht, current). */
static uint32_t estBd(const std::vector<int> &n, int K, int bucketBits)
{
	unsigned long long sum = 0;
	uint32_t count = 0;
	for (int i = 0; i < NBUCKETS; ++i)
	{
		int shift = BITDHT_KEY_BITLEN - i;
		if (shift > BITDHT_ULLONG_BITS - bucketBits - 1)
			continue;
		unsigned long long no_peers = ((unsigned long long) 1 << shift) * n[i];
		if (n[i] < K && n[i] > 0)
		{
			sum += no_peers;
			count++;
		}
	}
	return count ? (uint32_t)(sum / count) : 0;
}

/* Same formula, but "full" is tested on the real bucket occupancy. */
static double estBdFixFull(const std::vector<int> &n, const std::vector<int> &occ,
                           int K, int bucketBits)
{
	double sum = 0;
	uint32_t count = 0;
	for (int i = 0; i < NBUCKETS; ++i)
	{
		int shift = BITDHT_KEY_BITLEN - i;
		if (shift > BITDHT_ULLONG_BITS - bucketBits - 1)
			continue;
		if (n[i] > 0 && occ[i] < K)
		{
			sum += std::ldexp((double) n[i], shift);
			count++;
		}
	}
	return count ? sum / count : 0;
}

/* Exact copy of bdSpace::calcNetworkSizeWithFlag_old (libbitdht). */
static uint32_t estBdOld(const std::vector<int> &n, int K, int bucketBits)
{
	unsigned long long sum = 0;
	unsigned long long no_peers = 0;
	uint32_t count = 0;
	bool doPrint = false;
	bool doAvg = false;

	for (int i = 0; i < NBUCKETS; ++i)
	{
		int size = n[i];
		int shift = BITDHT_KEY_BITLEN - i;
		bool toBig = false;
		if (shift > BITDHT_ULLONG_BITS - bucketBits - 1)
		{
			toBig = true;
			shift = BITDHT_ULLONG_BITS - bucketBits - 1;
		}
		unsigned long long no_nets = ((unsigned long long) 1 << shift);

		if (size && !doAvg && !doPrint)
			doAvg = true;
		if (size && !doPrint)
			doPrint = true;
		if (size == 0)
		{
			sum = 0;
			no_peers = 0;
			count = 0;
		}
		if (!toBig)
			no_peers = no_nets * size;
		if (doPrint && doAvg && !toBig)
		{
			if (size == K)
				doAvg = false;
			if (no_peers != 0)
			{
				sum += no_peers;
				count++;
			}
		}
	}
	return count ? (uint32_t)(sum / count) : 0;
}

/* Cumulative estimator: all the nodes of the buckets closer than the first
 * saturated one, divided by the fraction of the id space those buckets cover.
 * sat[i] decides saturation (n itself, or the real occupancy). */
static double estCum(const std::vector<int> &n, const std::vector<int> &sat, int K, int bucketBits)
{
	/* Same outlier guard as libbitdht: buckets closer than 2^-(64-bits-1) of
	 * the space can only hold forged ids (nodes that copy a prefix of ours;
	 * seen live: a full bucket 39). They are ignored, for saturation too. */
	const int lo = BITDHT_KEY_BITLEN - (BITDHT_ULLONG_BITS - bucketBits - 1);

	int firstFull = NBUCKETS;
	for (int i = lo; i < NBUCKETS; ++i)
		if (sat[i] >= K) { firstFull = i; break; }

	int j = firstFull - 1;
	if (j < lo)
		return 0;
	double sum = 0;
	for (int i = lo; i <= j; ++i)
		sum += n[i];
	/* buckets 0..j cover 2^(j+1) / 2^160 of the space */
	return std::ldexp(sum, BITDHT_KEY_BITLEN - (j + 1));
}

static double chapman(double n1, double n2, double m)
{
	return (n1 + 1) * (n2 + 1) / (m + 1) - 1;
}

static double median(std::vector<double> v)
{
	if (v.empty())
		return 0;
	std::sort(v.begin(), v.end());
	size_t h = v.size() / 2;
	return (v.size() % 2) ? v[h] : (v[h - 1] + v[h]) / 2;
}

static std::string fmt(double v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%.0f", v);
	return buf;
}

static std::string cov(rstime_t secs)
{
	return std::to_string((long long)(secs / 60)) + "m";
}

/*****************************************************************************/

DhtRsCensus::DhtRsCensus()
	: mMtx("DhtRsCensus"), mLoaded(false),
	  mLookupsLost(0),
	  mSessionStart(0), mDataStart(0), mLastPoll(0), mLastEst(0), mLastSave(0)
{
}

bool DhtRsCensus::seenIn(const Node &n, rstime_t a, rstime_t b)
{
	for (const Interval &i : n.iv)
		if (i.s <= b && i.e >= a)
			return true;
	return false;
}

rstime_t DhtRsCensus::observed_locked(rstime_t a, rstime_t b) const
{
	rstime_t t = 0;
	for (const Interval &i : mObs)
	{
		rstime_t s = std::max(i.s, a);
		rstime_t e = std::min(i.e, b);
		if (e > s)
			t += e - s;
	}
	return t;
}

void DhtRsCensus::occasions_locked(rstime_t now, rstime_t w, int k,
                                   std::vector<uint32_t> &masks) const
{
	masks.clear();
	if (k < 1 || w <= 0)
		return;
	rstime_t start = now - w;
	for (const auto &it : mNodes)
	{
		uint32_t mask = 0;
		for (int o = 0; o < k; ++o)
		{
			rstime_t a = start + (w * o) / k;
			rstime_t b = start + (w * (o + 1)) / k;
			if (seenIn(it.second, a, b))
				mask |= (1u << o);
		}
		if (mask)
			masks.push_back(mask);
	}
}

void DhtRsCensus::tick(UdpBitDht *dht, bdDhtFunctions *fns, uint32_t bdAll, uint32_t bdRs)
{
	RS_STACK_MUTEX(mMtx);

	rstime_t now = time(NULL);
	if (now - mLastPoll < POLL_PERIOD)
		return;
	if (!dht || !fns)
		return;

	if (!mLoaded)
	{
		mLoaded = true;
		std::string dir = RsAccounts::AccountDirectory();
		if (!dir.empty())
		{
			mCensusFile = dir + "/dht-rs-census.csv";
			mSamplesFile = dir + "/dht-rs-samples.csv";
			load_locked();
		}
		mSessionStart = now;
		if (mDataStart == 0)
			mDataStart = now;

		RsInfo() << "DHT-RS schema v=4 keys=" << SCHEMA_KEYS;
		RsInfo() << "DHT-RS start census_loaded=" << mNodes.size()
		         << " data_start=" << mDataStart
		         << " census_file=" << mCensusFile
		         << " lookup_mode=" << LOOKUP_MODE;
	}

	mLastPoll = now;
	lookups_locked(dht, now);
	poll_locked(dht, fns, now, bdAll, bdRs);

	if (now - mLastSave >= SAVE_PERIOD)
	{
		save_locked();
		mLastSave = now;
	}
}

void DhtRsCensus::poll_locked(UdpBitDht *dht, bdDhtFunctions *fns, rstime_t now,
                              uint32_t bdAll, uint32_t bdRs)
{
	const int K = fns->bdNodesPerBucket();
	const int bucketBits = fns->bdBucketBitSize();

	/* observed time */
	if (!mObs.empty() && now - mObs.back().e <= OBS_GAP)
		mObs.back().e = now;
	else
		mObs.push_back(Interval{now, now});

	/* ---- read the table ---- */
	std::vector<int> nAll(NBUCKETS, 0), nRs(NBUCKETS, 0), occ(NBUCKETS, 0);
	std::map<std::string, int> present; /* RS id -> bucket */

	/* bucket 0 (XOR distance < 2) can only hold our own node: skipped */
	for (int i = 1; i < NBUCKETS; ++i)
	{
		bdBucket b;
		dht->getDhtBucket(i, b);
		occ[i] = (int) b.entries.size();
		for (const bdPeer &p : b.entries)
		{
			if (p.mPeerFlags & ~0u)
				nAll[i]++;
			if (p.mPeerFlags & BITDHT_PEER_STATUS_DHT_ENGINE)
			{
				nRs[i]++;
				std::string id;
				bdStdPrintNodeId(id, &(p.mPeerId.id), false);
				present[id] = i;
			}
		}
	}

	/* ---- update the census ---- */
	for (const auto &pi : present)
	{
		bool isNew = (mNodes.find(pi.first) == mNodes.end());
		Node &n = mNodes[pi.first];
		if (isNew)
		{
			n.first = now;
			RsInfo() << "DHT-RS new id=" << pi.first.substr(0, 8) << " bucket=" << pi.second;
		}
		if (!n.inTable)
		{
			n.inTable = true;
			n.enter = now;
			n.iv.push_back(Interval{now, now});
			if (!isNew)
				RsInfo() << "DHT-RS back id=" << pi.first.substr(0, 8) << " bucket=" << pi.second
				         << " away_min=" << (now - n.last) / 60;
		}
		else
			n.iv.back().e = now;
		n.last = now;
		n.polls++;
		n.bucket = pi.second;
	}
	for (auto &it : mNodes)
	{
		Node &n = it.second;
		if (n.inTable && present.find(it.first) == present.end())
		{
			n.inTable = false;
			rstime_t dwell = n.last - n.enter;
			mGone.push_back(std::make_pair(now, dwell));
			RsInfo() << "DHT-RS gone id=" << it.first.substr(0, 8) << " bucket=" << n.bucket
			         << " dwell_min=" << dwell / 60;
		}
	}

	/* ---- per-poll libbitdht samples ---- */
	mSamples.push_back(Sample{now, bdRs, bdAll});
	while (!mSamples.empty() && mSamples.front().t < now - DAY)
		mSamples.pop_front();
	while (!mGone.empty() && mGone.front().first < now - HOUR)
		mGone.pop_front();

	uint32_t allNow = 0, rsFull = 0;
	for (int i = 0; i < NBUCKETS; ++i)
	{
		allNow += occ[i];
		if (nRs[i] >= K)
			rsFull++;
	}

	if (!mSamplesFile.empty())
	{
		std::ofstream f(mSamplesFile, std::ios::app);
		f << now << "," << bdRs << "," << bdAll << "," << present.size() << "," << allNow << "\n";
	}

	prune_locked(now);

	/* ---- estimates ---- */
	rstime_t estPeriod = (now - mSessionStart < FAST_PHASE) ? EST_FAST_PERIOD : EST_SLOW_PERIOD;
	if (mLastEst != 0 && now - mLastEst < estPeriod)
		return;
	mLastEst = now;

	/* every query libbitdht runs (ours + one per friend): they share its
	 * per-iteration send budget */
	size_t dhtQueries = 0;
	{
		std::map<bdNodeId, bdQueryStatus> qs;
		dht->getDhtQueries(qs);
		dhtQueries = qs.size();
	}

	const rstime_t dataAge = now - mDataStart;
	const rstime_t sessAge = now - mSessionStart;
	const size_t rsNow = present.size();

	/* instant */
	uint32_t rsBdRecalc  = estBd(nRs, K, bucketBits);
	uint32_t allBdRecalc = estBd(nAll, K, bucketBits);
	uint32_t rsBdOld     = estBdOld(nRs, K, bucketBits);
	uint32_t allBdOld    = estBdOld(nAll, K, bucketBits);
	double rsBdFixFull   = estBdFixFull(nRs, occ, K, bucketBits);
	double rsCum         = estCum(nRs, nRs, K, bucketBits);
	double rsCumFixFull  = estCum(nRs, occ, K, bucketBits);
	double allCum        = estCum(nAll, nAll, K, bucketBits);

	/* medians of the libbitdht numbers */
	std::vector<double> vRs, vAll;
	for (const Sample &s : mSamples)
	{
		vRs.push_back(s.rsBd);
		vAll.push_back(s.allBd);
	}
	double rsMed = median(vRs), allMed = median(vAll);
	rstime_t medCov = mSamples.empty() ? 0 : now - mSamples.front().t;

	/* counts */
	size_t c1h = 0, c24h = 0, c7d = 0, new1h = 0;
	for (const auto &it : mNodes)
	{
		const Node &n = it.second;
		if (n.last >= now - HOUR) c1h++;
		if (n.last >= now - DAY)  c24h++;
		if (n.last >= now - WEEK) c7d++;
		if (n.first >= now - HOUR) new1h++;
	}

	/* Chapman between two consecutive windows of length h (h = 1 h, or half
	 * of the elapsed time while shorter). With fewer than 2 polls it falls
	 * back to the current table count. */
	auto twoWindows = [&](rstime_t h, bool skipStable,
	                      size_t &n1, size_t &n2, size_t &m, size_t &stable) -> double
	{
		n1 = n2 = m = stable = 0;
		if (h < POLL_PERIOD)
			return (double) rsNow;
		rstime_t a0 = now - 2 * h, a1 = now - h;
		for (const auto &it : mNodes)
		{
			const Node &n = it.second;
			bool isStable = false;
			for (const Interval &i : n.iv)
				if (i.s <= a0 + 90 && i.e >= now - 90)
					isStable = true;
			if (isStable)
				stable++;
			if (skipStable && isStable)
				continue;
			bool inA = seenIn(n, a0, a1);
			bool inB = seenIn(n, a1, now);
			if (inA) n1++;
			if (inB) n2++;
			if (inA && inB) m++;
		}
		return chapman(n1, n2, m);
	};

	rstime_t h1 = std::min(HOUR, sessAge / 2);
	size_t n1, n2, m, stable, sn1, sn2, sm, sstable, dn1, dn2, dm, dstable;
	double chap1h   = twoWindows(h1, false, n1, n2, m, stable);
	double chap1hNs = twoWindows(h1, true, sn1, sn2, sm, sstable);
	rstime_t h24 = std::min(DAY, dataAge / 2);
	double chap24h  = twoWindows(h24, false, dn1, dn2, dm, dstable);

	/* occasions: up to 24 (24 h window) / 7 (7 d window), never shorter than a poll */
	auto nOcc = [](rstime_t w, int kmax) -> int
	{
		int k = (int)(w / POLL_PERIOD);
		return std::max(1, std::min(kmax, k));
	};

	rstime_t w24 = std::min(DAY, dataAge);
	int k24 = nOcc(w24, 24);
	std::vector<uint32_t> masks24;
	occasions_locked(now, w24, k24, masks24);

	/* Schnabel over the k24 occasions: N = sum(C_t M_t) / (sum(R_t) + 1) */
	double schnabel = 0;
	{
		double num = 0, recap = 0;
		for (int t = 0; t < k24; ++t)
		{
			double C = 0, R = 0, M = 0;
			uint32_t before = (1u << t) - 1;
			for (uint32_t mk : masks24)
			{
				bool caught = mk & (1u << t);
				bool marked = mk & before;
				if (caught) C++;
				if (marked) M++;
				if (caught && marked) R++;
			}
			num += C * M;
			recap += R;
		}
		schnabel = (k24 < 2) ? (double) masks24.size() : num / (recap + 1);
	}

	/* bias-corrected Chao1: M + f1 (f1 - 1) / (2 (f2 + 1)) */
	auto chao1 = [](const std::vector<uint32_t> &masks, size_t &f1, size_t &f2) -> double
	{
		f1 = f2 = 0;
		for (uint32_t mk : masks)
		{
			int c = __builtin_popcount(mk);
			if (c == 1) f1++;
			else if (c == 2) f2++;
		}
		double M = masks.size();
		return M + (double) f1 * ((double) f1 - 1) / (2.0 * ((double) f2 + 1));
	};
	size_t f1_24, f2_24, f1_7, f2_7;
	double chao24 = chao1(masks24, f1_24, f2_24);

	rstime_t w7 = std::min(WEEK, dataAge);
	int k7 = nOcc(w7, 7);
	std::vector<uint32_t> masks7;
	occasions_locked(now, w7, k7, masks7);
	double chao7 = chao1(masks7, f1_7, f2_7);

	/* random-target lookups: median of the last results; the RS share of
	 * the nodes that answered, times that total */
	/* all_lookup: converged lookups only; all_lookup_any: every result */
	double allLookup = 0, allLookupAny = 0, rsLookup = 0, allLookupHeard = 0;
	size_t nLookup = 0;
	rstime_t lookupCov = 0;
	{
		std::vector<double> v, vAny, vHeard;
		double ans = 0, ansRs = 0;
		for (const LookupSample &ls : mLookupSamples)
		{
			vAny.push_back(ls.n);
			if (!ls.converged)
				continue;
			v.push_back(ls.n);
			if (ls.nHeard > 0)
				vHeard.push_back(ls.nHeard);
			ans += ls.answered;
			ansRs += ls.answeredRs;
		}
		allLookup = median(v);
		allLookupAny = median(vAny);
		allLookupHeard = median(vHeard);
		nLookup = v.size();
		if (ans > 0)
			rsLookup = allLookup * ansRs / ans;
		if (!mLookupSamples.empty())
			lookupCov = now - mLookupSamples.front().t;
	}

	/* churn */
	std::vector<double> dwells;
	for (const auto &g : mGone)
		dwells.push_back(g.second / 60.0);

	std::ostringstream est;
	est << "DHT-RS est"
	    << " rs_bd=" << bdRs
	    << " rs_bd_recalc=" << rsBdRecalc
	    << " rs_bd_old=" << rsBdOld
	    << " rs_bd_fixfull=" << fmt(rsBdFixFull)
	    << " rs_cum=" << fmt(rsCum)
	    << " rs_cum_fixfull=" << fmt(rsCumFixFull)
	    << " rs_bd_med24h=" << fmt(rsMed) << " rs_bd_med24h_cov=" << cov(medCov)
	    << " rs_count_now=" << rsNow
	    << " rs_count_1h=" << c1h << " rs_count_1h_cov=" << cov(observed_locked(now - HOUR, now))
	    << " rs_count_24h=" << c24h << " rs_count_24h_cov=" << cov(observed_locked(now - DAY, now))
	    << " rs_count_7d=" << c7d << " rs_count_7d_cov=" << cov(observed_locked(now - WEEK, now))
	    << " rs_chapman_1h=" << fmt(chap1h) << " rs_chapman_1h_cov=" << cov(2 * h1)
	    << " rs_chapman_1h_nostable=" << fmt(chap1hNs) << " rs_chapman_1h_nostable_cov=" << cov(2 * h1)
	    << " rs_chapman_24h=" << fmt(chap24h) << " rs_chapman_24h_cov=" << cov(observed_locked(now - 2 * h24, now))
	    << " rs_schnabel_24h=" << fmt(schnabel) << " rs_schnabel_24h_cov=" << cov(observed_locked(now - w24, now))
	    << " rs_chao1_24h=" << fmt(chao24) << " rs_chao1_24h_cov=" << cov(observed_locked(now - w24, now))
	    << " rs_chao1_7d=" << fmt(chao7) << " rs_chao1_7d_cov=" << cov(observed_locked(now - w7, now))
	    << " all_bd=" << bdAll
	    << " all_bd_recalc=" << allBdRecalc
	    << " all_bd_old=" << allBdOld
	    << " all_cum=" << fmt(allCum)
	    << " all_bd_med24h=" << fmt(allMed) << " all_bd_med24h_cov=" << cov(medCov)
	    << " all_lookup=" << fmt(allLookup) << " all_lookup_cov=" << cov(lookupCov)
	    << " all_lookup_n=" << nLookup
	    << " all_lookup_any=" << fmt(allLookupAny) << " all_lookup_any_n=" << mLookupSamples.size()
	    << " rs_lookup=" << fmt(rsLookup)
	    << " all_lookup_heard=" << fmt(allLookupHeard);
	RsInfo() << est.str();

	std::ostringstream raw;
	raw << "DHT-RS raw"
	    << " K=" << K
	    << " rs_now=" << rsNow << " all_now=" << allNow << " rs_full_buckets=" << rsFull
	    << " new_1h=" << new1h << " gone_1h=" << mGone.size()
	    << " median_dwell_min=" << fmt(median(dwells))
	    << " c1h_window_min=" << h1 / 60
	    << " n1=" << n1 << " n2=" << n2 << " m=" << m << " m_stable=" << stable
	    << " ns_n1=" << sn1 << " ns_n2=" << sn2 << " ns_m=" << sm
	    << " c24h_window_min=" << h24 / 60
	    << " d_n1=" << dn1 << " d_n2=" << dn2 << " d_m=" << dm
	    << " occ24=" << k24 << " M_24h=" << masks24.size() << " f1_24h=" << f1_24 << " f2_24h=" << f2_24
	    << " occ7=" << k7 << " M_7d=" << masks7.size() << " f1_7d=" << f1_7 << " f2_7d=" << f2_7
	    << " census=" << mNodes.size()
	    << " lookups_running=" << mLookups.size() << " lookups_lost=" << mLookupsLost
	    << " dht_queries=" << dhtQueries;
	RsInfo() << raw.str();

	std::ostringstream bk;
	bk << "DHT-RS buckets";
	for (int i = NBUCKETS - 1; i >= 0; --i)
		if (occ[i] > 0)
			bk << " " << i << "=" << nRs[i] << "/" << occ[i];
	RsInfo() << bk.str();
}

/* XOR distance as a fraction of the id space (first 8 bytes are plenty). */
static double metricFraction(const bdMetric &m)
{
	double d = 0;
	for (int i = 0; i < 8; ++i)
		d += std::ldexp((double) m.data[i], -8 * (i + 1));
	return d;
}

void DhtRsCensus::lookups_locked(UdpBitDht *dht, rstime_t now)
{
	/* ---- collect the finished ones ---- */
	for (auto it = mLookups.begin(); it != mLookups.end(); )
	{
		bdQuerySummary q;
		bool have = dht->getDhtQueryStatus(&(it->second.id), q) == 1;
		bool done = have && (q.mState == BITDHT_QUERY_FOUND_CLOSEST ||
		                     q.mState == BITDHT_QUERY_SUCCESS ||
		                     q.mState == BITDHT_QUERY_PEER_UNREACHABLE ||
		                     q.mState == BITDHT_QUERY_FAILURE);
		bool timedOut = now - it->second.start > LOOKUP_TIMEOUT;

		/* libbitdht only turns a queued find into a query at its next REFRESH
		 * step (~10 s), or after a DHT restart: give it time to appear */
		bool queued = !have && now - it->second.start < 120;

		if ((have && !done && !timedOut) || queued)
		{
			if (have)
			{
				double d1 = -1, dk = -1;
				uint32_t ans = 0;
				for (const auto &c : q.mClosest)
					if (c.second.mLastRecvTime != 0)
					{
						double f = metricFraction(c.first);
						if (d1 < 0) d1 = f;
						if (++ans == (uint32_t) LOOKUP_K) dk = f;
					}
				RsInfo() << "DHT-RS lookup_progress target=" << it->first.substr(0, 8)
				         << " state=" << q.mState << " secs=" << (now - it->second.start)
				         << " closest=" << q.mClosest.size()
				         << " potential=" << q.mPotentialPeers.size()
				         << " answered=" << ans << " d1=" << d1 << " dk=" << dk;
			}
			++it;
			continue;
		}

		/* only the nodes that answered us: an id merely reported by a third
		 * party may be forged */
		std::vector<double> d;
		uint32_t rs = 0;
		if (have)
			for (const auto &c : q.mClosest)
				if (c.second.mLastRecvTime != 0)
				{
					d.push_back(metricFraction(c.first));
					if (c.second.mPeerFlags & BITDHT_PEER_STATUS_DHT_ENGINE)
						rs++;
				}
		std::sort(d.begin(), d.end());
		int k = std::min<int>(LOOKUP_K, (int) d.size());

		/* every node heard of near the target, answered or not (closest and
		 * potential lists overlap: dedup by distance, unique per id). If this
		 * estimate is far above the answered one, the gap is nodes that do not
		 * answer us; if both stay close, the lookup does not discover enough. */
		std::set<bdMetric> heardSet;
		if (have)
		{
			for (const auto &c : q.mClosest) heardSet.insert(c.first);
			for (const auto &c : q.mPotentialPeers) heardSet.insert(c.first);
		}
		std::vector<double> dh;
		for (const bdMetric &m : heardSet) dh.push_back(metricFraction(m));
		int kh = std::min<int>(LOOKUP_K, (int) dh.size());
		double nHeard = (kh >= 2 && dh[kh - 1] > 0) ? (kh - 1) / dh[kh - 1] : 0;
		/* heard of, closer than the k-th answered node, but silent */
		uint32_t silentInside = 0;
		if (k >= 1)
			for (double x : dh)
				if (x < d[k - 1]) silentInside++;
		/* the k - 1 answered nodes closer than d[k - 1] are in dh too */
		silentInside = silentInside > (uint32_t) (k - 1) ? silentInside - (k - 1) : 0;

		if (k >= 2 && d[k - 1] > 0)
		{
			/* a measure query that hit libbitdht's 300 s cap also ends in a
			 * "done" state: only an end before the cap counts as converged */
			bool converged = done && q.mSearchTime <= 300;
			LookupSample ls{now, (k - 1) / d[k - 1], k, (uint32_t) d.size(), rs, converged, nHeard};
			mLookupSamples.push_back(ls);
			while (mLookupSamples.size() > LOOKUP_KEEP)
				mLookupSamples.pop_front();
			RsInfo() << "DHT-RS lookup target=" << it->first.substr(0, 8)
			         << " state=" << q.mState << " converged=" << converged
			         << " search_secs=" << q.mSearchTime
			         << " secs=" << (now - it->second.start)
			         << " closest=" << q.mClosest.size() << " answered=" << d.size()
			         << " answered_rs=" << rs << " k=" << k
			         << " d1=" << d[0] << " dk=" << d[k - 1]
			         << " n=" << fmt(ls.n)
			         << " heard=" << dh.size() << " silent_inside=" << silentInside
			         << " dk_heard=" << (kh >= 1 ? dh[kh - 1] : -1)
			         << " n_heard=" << fmt(nHeard);
		}
		else
		{
			mLookupsLost++;
			RsInfo() << "DHT-RS lookup target=" << it->first.substr(0, 8)
			         << " lost have=" << have << " state=" << (have ? (int) q.mState : -1)
			         << " secs=" << (now - it->second.start)
			         << " answered=" << d.size();
		}

		dht->removeFindNode(&(it->second.id));
		it = mLookups.erase(it);
	}

	/* ---- start new ones ---- */
	while (mLookups.size() < LOOKUP_PARALLEL)
	{
		Lookup l;
		bdStdRandomNodeId(&l.id);
		l.start = now;
		std::string key;
		bdStdPrintNodeId(key, &l.id, false);
		dht->addFindNode(&l.id, LOOKUP_QFLAGS);
		mLookups[key] = l;
	}
}

void DhtRsCensus::prune_locked(rstime_t now)
{
	const rstime_t keep = now - WEEK - DAY;
	for (auto it = mNodes.begin(); it != mNodes.end(); )
	{
		std::vector<Interval> &iv = it->second.iv;
		iv.erase(std::remove_if(iv.begin(), iv.end(),
		                        [keep](const Interval &i) { return i.e < keep; }),
		         iv.end());
		if (iv.empty() && !it->second.inTable)
			it = mNodes.erase(it);
		else
			++it;
	}
	mObs.erase(std::remove_if(mObs.begin(), mObs.end(),
	                          [keep](const Interval &i) { return i.e < keep; }),
	           mObs.end());
	if (mDataStart < keep)
		mDataStart = keep;
}

void DhtRsCensus::save()
{
	RS_STACK_MUTEX(mMtx);
	save_locked();
}

/* Format:
 *   # dht-rs-census v1 data_start=<t>
 *   # obs <s>-<e>;<s>-<e>;...
 *   dht_id,first_seen,last_seen,polls_seen,last_bucket,intervals
 *   <id>,<t>,<t>,<n>,<b>,<s>-<e>;<s>-<e>
 */
void DhtRsCensus::save_locked()
{
	if (mCensusFile.empty())
		return;

	std::string tmp = mCensusFile + ".tmp";
	{
		std::ofstream f(tmp, std::ios::trunc);
		if (!f)
			return;
		f << "# dht-rs-census v1 data_start=" << mDataStart << "\n";
		f << "# obs ";
		for (size_t i = 0; i < mObs.size(); ++i)
			f << (i ? ";" : "") << mObs[i].s << "-" << mObs[i].e;
		f << "\n";
		f << "dht_id,first_seen,last_seen,polls_seen,last_bucket,intervals\n";
		for (const auto &it : mNodes)
		{
			const Node &n = it.second;
			f << it.first << "," << n.first << "," << n.last << "," << n.polls << "," << n.bucket << ",";
			for (size_t i = 0; i < n.iv.size(); ++i)
				f << (i ? ";" : "") << n.iv[i].s << "-" << n.iv[i].e;
			f << "\n";
		}
	}
	RsDirUtil::renameFile(tmp, mCensusFile);
}

static void parseIntervals(const std::string &s, std::vector<std::pair<rstime_t, rstime_t> > &out)
{
	std::stringstream ss(s);
	std::string tok;
	while (std::getline(ss, tok, ';'))
	{
		long long a = 0, b = 0;
		if (sscanf(tok.c_str(), "%lld-%lld", &a, &b) == 2)
			out.push_back(std::make_pair((rstime_t) a, (rstime_t) b));
	}
}

void DhtRsCensus::load_locked()
{
	{
		std::ifstream f(mCensusFile);
		std::string line;
		while (f && std::getline(f, line))
		{
			if (line.empty())
				continue;
			if (line.rfind("# dht-rs-census", 0) == 0)
			{
				size_t p = line.find("data_start=");
				if (p != std::string::npos)
					mDataStart = (rstime_t) atoll(line.c_str() + p + 11);
				continue;
			}
			if (line.rfind("# obs ", 0) == 0)
			{
				std::vector<std::pair<rstime_t, rstime_t> > v;
				parseIntervals(line.substr(6), v);
				for (auto &p : v)
					mObs.push_back(Interval{p.first, p.second});
				continue;
			}
			if (line.rfind("dht_id,", 0) == 0 || line[0] == '#')
				continue;

			std::vector<std::string> cols;
			std::stringstream ss(line);
			std::string c;
			while (std::getline(ss, c, ','))
				cols.push_back(c);
			if (cols.size() < 5)
				continue;

			Node &n = mNodes[cols[0]];
			n.first = (rstime_t) atoll(cols[1].c_str());
			n.last = (rstime_t) atoll(cols[2].c_str());
			n.polls = (uint32_t) strtoul(cols[3].c_str(), NULL, 10);
			n.bucket = atoi(cols[4].c_str());
			n.inTable = false;
			if (n.bucket == 0)
			{
				/* our own node, counted by the first probe version */
				mNodes.erase(cols[0]);
				continue;
			}
			if (cols.size() > 5)
			{
				std::vector<std::pair<rstime_t, rstime_t> > v;
				parseIntervals(cols[5], v);
				for (auto &p : v)
					n.iv.push_back(Interval{p.first, p.second});
			}
		}
	}
	{
		rstime_t now = time(NULL);
		std::ifstream f(mSamplesFile);
		std::string line;
		while (f && std::getline(f, line))
		{
			long long t = 0;
			unsigned long rs = 0, all = 0;
			if (sscanf(line.c_str(), "%lld,%lu,%lu", &t, &rs, &all) == 3 && t >= now - DAY)
				mSamples.push_back(Sample{(rstime_t) t, (uint32_t) rs, (uint32_t) all});
		}
	}
}
