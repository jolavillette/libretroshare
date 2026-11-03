/*******************************************************************************
 * libretroshare/src/dht: p3bitdht_size.cc                                     *
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

#include "dht/p3bitdht_size.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include "bitdht/bdpeer.h"
#include "bitdht/bdstddht.h"
#include "udp/udpbitdht.h"
#include "retroshare/rsinit.h"
#include "util/rsdebug.h"
#include "util/rsdir.h"

static const rstime_t POLL_PERIOD     = 60;
static const rstime_t OBS_GAP         = 3 * POLL_PERIOD; /* longer = we were not polling */
static const rstime_t SAVE_PERIOD     = 1800;
static const rstime_t HOUR            = 3600;
static const rstime_t DAY             = 24 * HOUR;
static const rstime_t WEEK            = 7 * DAY;
static const int      RS_OCCASIONS    = 7;
static const int      NBUCKETS        = BITDHT_KEY_BITLEN;

static const rstime_t LOOKUP_PERIOD   = 120;  /* pause between two lookups */
static const rstime_t LOOKUP_TIMEOUT  = 360;  /* libbitdht ends them at 300 s */
static const rstime_t LOOKUP_MAX_AGE  = 300;  /* BITDHT_MAX_QUERY_AGE */
static const size_t   LOOKUP_KEEP     = 24;
static const size_t   LOOKUP_MIN      = 6;
static const int      LOOKUP_K        = 8;
/* closer than 2^-40 of the id space: a node copying the target id (no real
 * node is expected there below ~10^9 nodes) */
static const double   FORGED_DIST     = 9.094947017729282e-13;

static const char    *FILE_NAME       = "dht-size.txt";

static double median(std::vector<double> v)
{
	if (v.empty())
		return 0;
	std::sort(v.begin(), v.end());
	size_t h = v.size() / 2;
	return (v.size() % 2) ? v[h] : (v[h - 1] + v[h]) / 2;
}

/* first 64 bits of an XOR distance, as a fraction of the id space */
static double metricFraction(const bdMetric &m)
{
	double d = 0;
	for (int i = 0; i < 8; ++i)
		d += std::ldexp((double) m.data[i], -8 * (i + 1));
	return d;
}

/* (k - 1) / d_k over the sorted distances, forged ones skipped; 0 if too few */
static double sizeFromDistances(std::vector<double> d)
{
	d.erase(std::remove_if(d.begin(), d.end(),
	                       [](double x) { return x < FORGED_DIST; }), d.end());
	std::sort(d.begin(), d.end());
	int k = std::min<int>(LOOKUP_K, (int) d.size());
	if (k < 2 || d[k - 1] <= 0)
		return 0;
	return (k - 1) / d[k - 1];
}

/*****************************************************************************/

DhtSizeEstimator::DhtSizeEstimator()
	: mMtx("DhtSizeEstimator"), mLoaded(false), mDataStart(0),
	  mLookupRunning(false), mLookupStart(0), mLastLookupEnd(0),
	  mLastPoll(0), mLastSave(0)
{
	bdZeroNodeId(&mLookupId);
}

void DhtSizeEstimator::getEstimate(RsDhtSizeEstimate &est)
{
	RS_STACK_MUTEX(mMtx);
	est = mEst;
}

void DhtSizeEstimator::save()
{
	RS_STACK_MUTEX(mMtx);
	save_locked();
}

void DhtSizeEstimator::tick(UdpBitDht *dht)
{
	RS_STACK_MUTEX(mMtx);

	rstime_t now = time(NULL);
	if (!dht || now - mLastPoll < POLL_PERIOD)
		return;

	if (!mLoaded)
	{
		mLoaded = true;
		std::string dir = RsAccounts::AccountDirectory();
		if (!dir.empty())
		{
			mFile = dir + "/" + FILE_NAME;
			load_locked();
		}
		if (mDataStart == 0)
			mDataStart = now;
		mLastSave = now;
	}

	mLastPoll = now;
	lookup_locked(dht, now);
	poll_locked(dht, now);
	prune_locked(now);
	estimate_locked(now);

	if (now - mLastSave >= SAVE_PERIOD)
	{
		save_locked();
		mLastSave = now;
		RsInfo() << "DHT size estimate: RS " << mEst.rsMin << "-" << mEst.rsMax
		         << " (observed " << mEst.rsObservedSecs / 3600 << " h of 7 d), DHT "
		         << mEst.allMin << "-" << mEst.allMax << " (" << mEst.allSamples
		         << " lookups)";
	}
}

void DhtSizeEstimator::poll_locked(UdpBitDht *dht, rstime_t now)
{
	if (!mObs.empty() && now - mObs.back().e <= OBS_GAP)
		mObs.back().e = now;
	else
		mObs.push_back(Interval{now, now});

	std::set<std::string> present;
	/* bucket 0 (XOR distance < 2) can only hold our own node */
	for (int i = 1; i < NBUCKETS; ++i)
	{
		bdBucket b;
		dht->getDhtBucket(i, b);
		for (const bdPeer &p : b.entries)
			if (p.mPeerFlags & BITDHT_PEER_STATUS_DHT_ENGINE)
			{
				std::string id;
				bdStdPrintNodeId(id, &(p.mPeerId.id), false);
				present.insert(id);
			}
	}

	for (const std::string &id : present)
	{
		Node &n = mNodes[id];
		if (!n.inTable)
		{
			n.inTable = true;
			/* a short absence (or our own restart) extends the last stay */
			if (!n.iv.empty() && now - n.iv.back().e <= OBS_GAP)
				n.iv.back().e = now;
			else
				n.iv.push_back(Interval{now, now});
		}
		else
			n.iv.back().e = now;
		n.last = now;
	}
	for (auto &it : mNodes)
		if (it.second.inTable && present.find(it.first) == present.end())
			it.second.inTable = false;
}

void DhtSizeEstimator::lookup_locked(UdpBitDht *dht, rstime_t now)
{
#ifdef BITDHT_QFLAGS_MEASURE
	if (mLookupRunning)
	{
		bdQuerySummary q;
		bool have = dht->getDhtQueryStatus(&mLookupId, q) == 1;
		bool done = have && (q.mState == BITDHT_QUERY_FOUND_CLOSEST ||
		                     q.mState == BITDHT_QUERY_SUCCESS ||
		                     q.mState == BITDHT_QUERY_PEER_UNREACHABLE ||
		                     q.mState == BITDHT_QUERY_FAILURE);
		bool timedOut = now - mLookupStart > LOOKUP_TIMEOUT;
		/* libbitdht turns a queued find into a query at its next refresh */
		bool queued = !have && now - mLookupStart < 120;

		if ((have && !done && !timedOut) || queued)
			return;

		/* only a lookup libbitdht ended by itself before its age cap */
		if (done && q.mSearchTime <= LOOKUP_MAX_AGE)
		{
			std::vector<double> answered, heard;
			std::set<bdMetric> all;
			for (const auto &c : q.mClosest)
			{
				if (c.second.mLastRecvTime != 0)
					answered.push_back(metricFraction(c.first));
				all.insert(c.first);
			}
			for (const auto &c : q.mPotentialPeers)
				all.insert(c.first);
			for (const bdMetric &m : all)
				heard.push_back(metricFraction(m));

			double nA = sizeFromDistances(answered);
			double nH = sizeFromDistances(heard);
			if (nA > 0 && nH > 0)
			{
				mLookupSamples.push_back(LookupSample{now, nA, std::max(nA, nH)});
				while (mLookupSamples.size() > LOOKUP_KEEP)
					mLookupSamples.pop_front();
			}
		}

		dht->removeFindNode(&mLookupId);
		mLookupRunning = false;
		mLastLookupEnd = now;
	}

	if (now - mLastLookupEnd >= LOOKUP_PERIOD)
	{
		bdStdRandomNodeId(&mLookupId);
		dht->addFindNode(&mLookupId, BITDHT_QFLAGS_MEASURE);
		mLookupStart = now;
		mLookupRunning = true;
	}
#else
	(void) dht;
	(void) now;
#endif
}

void DhtSizeEstimator::prune_locked(rstime_t now)
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
	while (!mLookupSamples.empty() && mLookupSamples.front().t < now - DAY)
		mLookupSamples.pop_front();
}

void DhtSizeEstimator::estimate_locked(rstime_t now)
{
	RsDhtSizeEstimate est;

	/* ---- RS nodes ---- */
	auto observed = [this](rstime_t a, rstime_t b) -> rstime_t
	{
		rstime_t t = 0;
		for (const Interval &i : mObs)
		{
			rstime_t s = std::max(i.s, a), e = std::min(i.e, b);
			if (e > s)
				t += e - s;
		}
		return t;
	};

	uint32_t seen24h = 0;
	for (const auto &it : mNodes)
		if (it.second.last >= now - DAY)
			seen24h++;

	/* occasions: up to RS_OCCASIONS equal slices of the last 7 days (of the
	 * time since the data start while shorter); a slice we barely observed
	 * would make every node look rare, so those are left out */
	const rstime_t w = std::min(WEEK, now - mDataStart);
	std::vector<std::pair<rstime_t, rstime_t> > occ;
	int k = std::max(1, std::min<int>(RS_OCCASIONS, (int)(w / POLL_PERIOD)));
	for (int o = 0; o < k; ++o)
	{
		rstime_t a = now - w + (w * o) / k;
		rstime_t b = now - w + (w * (o + 1)) / k;
		if (observed(a, b) * 10 >= (b - a))
			occ.push_back(std::make_pair(a, b));
	}

	double chao = seen24h;
	if (occ.size() >= 2)
	{
		double M = 0, f1 = 0, f2 = 0;
		for (const auto &it : mNodes)
		{
			int c = 0;
			for (const auto &o : occ)
				for (const Interval &i : it.second.iv)
					if (i.s <= o.second && i.e >= o.first)
					{
						c++;
						break;
					}
			if (c == 0)
				continue;
			M++;
			if (c == 1) f1++;
			else if (c == 2) f2++;
		}
		/* bias-corrected Chao1 */
		chao = M + f1 * (f1 - 1) / (2.0 * (f2 + 1));
	}

	est.rsMin = seen24h;
	est.rsMax = (uint32_t) std::max<double>(seen24h, std::lround(chao));
	est.rsObservedSecs = (uint32_t) observed(now - WEEK, now);

	/* ---- whole DHT ---- */
	if (mLookupSamples.size() >= LOOKUP_MIN)
	{
		std::vector<double> a, h;
		for (const LookupSample &s : mLookupSamples)
		{
			a.push_back(s.answered);
			h.push_back(s.heard);
		}
		est.allMin = (uint32_t) std::min<double>(median(a), 4e9);
		est.allMax = (uint32_t) std::min<double>(std::max(median(a), median(h)), 4e9);
	}
	est.allSamples = (uint32_t) mLookupSamples.size();

	mEst = est;
}

/* Format:
 *   # rs-dht-size v1
 *   D <data_start>
 *   O <s>-<e>;<s>-<e>;...          when we were polling
 *   N <dht id> <s>-<e>;...         an RS node and its stays in our table
 *   L <time> <answered> <heard>    a lookup result
 */
void DhtSizeEstimator::save_locked()
{
	if (mFile.empty())
		return;

	std::string tmp = mFile + ".tmp";
	{
		std::ofstream f(tmp, std::ios::trunc);
		if (!f)
			return;
		f << "# rs-dht-size v1\n";
		f << "D " << mDataStart << "\n";
		f << "O ";
		for (size_t i = 0; i < mObs.size(); ++i)
			f << (i ? ";" : "") << mObs[i].s << "-" << mObs[i].e;
		f << "\n";
		for (const auto &it : mNodes)
		{
			if (it.second.iv.empty())
				continue;
			f << "N " << it.first << " ";
			for (size_t i = 0; i < it.second.iv.size(); ++i)
				f << (i ? ";" : "") << it.second.iv[i].s << "-" << it.second.iv[i].e;
			f << "\n";
		}
		char buf[96];
		for (const LookupSample &s : mLookupSamples)
		{
			snprintf(buf, sizeof(buf), "L %lld %.0f %.0f\n",
			         (long long) s.t, s.answered, s.heard);
			f << buf;
		}
		if (!f)
			return;
	}
	RsDirUtil::renameFile(tmp, mFile);
}

static void parseIntervals(const std::string &s, std::vector<std::pair<rstime_t, rstime_t> > &out)
{
	std::stringstream ss(s);
	std::string tok;
	while (std::getline(ss, tok, ';'))
	{
		long long a = 0, b = 0;
		if (sscanf(tok.c_str(), "%lld-%lld", &a, &b) == 2 && a <= b)
			out.push_back(std::make_pair((rstime_t) a, (rstime_t) b));
	}
}

void DhtSizeEstimator::load_locked()
{
	std::ifstream f(mFile);
	std::string line;
	while (f && std::getline(f, line))
	{
		if (line.size() < 2 || line[1] != ' ')
			continue;
		const std::string rest = line.substr(2);
		switch (line[0])
		{
		case 'D':
			mDataStart = (rstime_t) atoll(rest.c_str());
			break;
		case 'O':
		{
			std::vector<std::pair<rstime_t, rstime_t> > v;
			parseIntervals(rest, v);
			for (const auto &p : v)
				mObs.push_back(Interval{p.first, p.second});
			break;
		}
		case 'N':
		{
			size_t sp = rest.find(' ');
			if (sp == std::string::npos || sp == 0)
				break;
			std::vector<std::pair<rstime_t, rstime_t> > v;
			parseIntervals(rest.substr(sp + 1), v);
			if (v.empty())
				break;
			Node &n = mNodes[rest.substr(0, sp)];
			for (const auto &p : v)
			{
				n.iv.push_back(Interval{p.first, p.second});
				n.last = std::max(n.last, p.second);
			}
			break;
		}
		case 'L':
		{
			long long t = 0;
			double a = 0, h = 0;
			if (sscanf(rest.c_str(), "%lld %lf %lf", &t, &a, &h) == 3 && a > 0 && h > 0)
				mLookupSamples.push_back(LookupSample{(rstime_t) t, a, h});
			break;
		}
		default:
			break;
		}
	}
	while (mLookupSamples.size() > LOOKUP_KEEP)
		mLookupSamples.pop_front();
}
