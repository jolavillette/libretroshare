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
#include <random>
#include <set>
#include <sstream>

#include "bitdht/bdpeer.h"
#include "bitdht/bdstddht.h"
#include "udp/udpbitdht.h"
#include "retroshare/rsinit.h"
#include "util/rsdebug.h"
#include "util/rsdir.h"

static const rstime_t POLL_PERIOD     = 60;
static const rstime_t SAVE_PERIOD     = 1800;
static const rstime_t DAY             = 24 * 3600;
static const int      NBUCKETS        = BITDHT_KEY_BITLEN;

static const rstime_t LOOKUP_PERIOD   = 60;   /* pause between two lookups of a kind */
static const rstime_t LOOKUP_TIMEOUT  = 360;  /* libbitdht ends them at 300 s */
static const rstime_t LOOKUP_MAX_AGE  = 300;  /* BITDHT_MAX_QUERY_AGE */
static const size_t   LOOKUP_KEEP     = 24;   /* per kind */
static const size_t   LOOKUP_FULL     = 12;   /* fewer: provisional */
static const int      K_ANSWERED      = 8;
static const int      K_HEARD         = 12;
static const uint32_t MIN_REPORTERS   = 2;
static const int      BOOTSTRAP       = 200;
static const uint32_t CHAPMAN_MIN_OVERLAP = 3;
/* closer than 2^-40 of the id space: a node copying the target id (no real
 * node is expected there below ~10^9 nodes) */
static const double   FORGED_DIST     = 9.094947017729282e-13;

static const char    *FILE_NAME       = "dht-size.txt";
static const char    *FILE_HEADER     = "# rs-dht-size v2";

/* first 64 bits of an XOR distance, as a fraction of the id space */
static double metricFraction(const bdMetric &m)
{
	double d = 0;
	for (int i = 0; i < 8; ++i)
		d += std::ldexp((double) m.data[i], -8 * (i + 1));
	return d;
}

/* k-th smallest distance, forged ones skipped; false if fewer than 2 */
static bool kthDistance(std::vector<double> d, int kmax, int &k, double &dk)
{
	d.erase(std::remove_if(d.begin(), d.end(),
	                       [](double x) { return x < FORGED_DIST; }), d.end());
	std::sort(d.begin(), d.end());
	k = std::min<int>(kmax, (int) d.size());
	if (k < 2)
		return false;
	dk = d[k - 1];
	return dk > 0;
}

/* N per lookup = (k - 1/3) / d_k: d_k * N follows Gamma(k, 1), whose median
 * is ~k - 1/3, so the median of these is unbiased. A median, not a pooled
 * sum(k - 1) / sum(d_k): one lookup stuck far from its target (seen live:
 * d_k 400x the others) would drag a pooled value down by an order of
 * magnitude. Returned with its 10-90 % bootstrap interval. */
struct Pooled { double n; double lo; double hi; };

static double median(std::vector<double> v)
{
	if (v.empty())
		return 0;
	std::sort(v.begin(), v.end());
	size_t h = v.size() / 2;
	return (v.size() % 2) ? v[h] : (v[h - 1] + v[h]) / 2;
}

static Pooled pooled(const std::vector<std::pair<int, double> > &s)
{
	Pooled p{0, 0, 0};
	std::vector<double> n;
	for (const auto &x : s)
		if (x.second > 0)
			n.push_back((x.first - 1.0 / 3.0) / x.second);
	if (n.empty())
		return p;
	p.n = median(n);
	p.lo = p.hi = p.n;
	if (n.size() < 3)
		return p;

	/* fixed seed: the same samples always give the same interval */
	std::mt19937 rng(0x5eed);
	std::uniform_int_distribution<size_t> pick(0, n.size() - 1);
	std::vector<double> b, r(n.size());
	for (int i = 0; i < BOOTSTRAP; ++i)
	{
		for (size_t j = 0; j < r.size(); ++j)
			r[j] = n[pick(rng)];
		b.push_back(median(r));
	}
	std::sort(b.begin(), b.end());
	p.lo = b[(size_t)(0.1 * (b.size() - 1))];
	p.hi = b[(size_t)(0.9 * (b.size() - 1))];
	return p;
}

static uint32_t clampU32(double v)
{
	if (!(v > 0))
		return 0;
	return (uint32_t) std::min<long long>(std::llround(v), 4000000000LL);
}

static uint32_t errPercent(const Pooled &p)
{
	return p.n > 0 ? clampU32(50.0 * (p.hi - p.lo) / p.n) : 0;
}

static std::string hexId(const bdNodeId &id)
{
	std::string s;
	bdStdPrintNodeId(s, &id, false);
	return s;
}

/*****************************************************************************/

DhtSizeEstimator::DhtSizeEstimator()
	: mMtx("DhtSizeEstimator"), mLoaded(false), mObsStart(0),
	  mLastPoll(0), mLastSave(0)
{
#ifdef BITDHT_QFLAGS_MEASURE
	mKinds[KIND_ALL].flags = BITDHT_QFLAGS_MEASURE;
#ifdef BITDHT_QFLAGS_MEASURE_APPL
	mKinds[KIND_RS].flags = BITDHT_QFLAGS_MEASURE | BITDHT_QFLAGS_MEASURE_APPL;
#endif
#endif
	for (int i = 0; i < NKINDS; ++i)
		bdZeroNodeId(&mKinds[i].id);
}

bool DhtSizeEstimator::due()
{
	RS_STACK_MUTEX(mMtx);
	return time(NULL) - mLastPoll >= POLL_PERIOD;
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

void DhtSizeEstimator::tick(UdpBitDht *dht, const std::vector<bdNodeId> &friendsInDht)
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
		if (mObsStart == 0)
			mObsStart = now;
		mLastSave = now;
	}

	mLastPoll = now;
	for (int i = 0; i < NKINDS; ++i)
		lookup_locked(dht, mKinds[i], i, now);
	poll_locked(dht, friendsInDht, now);
	prune_locked(now);
	estimate_locked(now);

	if (now - mLastSave >= SAVE_PERIOD)
	{
		save_locked();
		mLastSave = now;
		RsInfo() << "DHT size estimate: RS " << mEst.rsMin << "-" << mEst.rsMax
		         << (mEst.rsProvisional ? " provisional" : "")
		         << " (reachable " << mEst.rsReachable << " +-" << mEst.rsReachableErr
		         << "%, heard " << mEst.rsHeard << " +-" << mEst.rsHeardErr
		         << "%, " << mEst.rsLookups << " lookups; table 24h " << mEst.rsSeen24h
		         << ", distinct 24h " << mEst.rsDistinct24h
		         << ", friend-calibrated " << mEst.rsFriendCalibrated
		         << "), DHT " << mEst.allMin << "-" << mEst.allMax
		         << (mEst.allProvisional ? " provisional" : "")
		         << " (reachable " << mEst.allReachable << " +-" << mEst.allReachableErr
		         << "%, heard " << mEst.allHeard << " +-" << mEst.allHeardErr
		         << "%, " << mEst.allLookups << " lookups)";
	}
}

void DhtSizeEstimator::lookup_locked(UdpBitDht *dht, Kind &k, int kind, rstime_t now)
{
	if (!k.flags)
		return;

	if (k.running)
	{
		bdQuerySummary q;
		bool have = dht->getDhtQueryStatus(&k.id, q) == 1;
		bool done = have && (q.mState == BITDHT_QUERY_FOUND_CLOSEST ||
		                     q.mState == BITDHT_QUERY_SUCCESS ||
		                     q.mState == BITDHT_QUERY_PEER_UNREACHABLE ||
		                     q.mState == BITDHT_QUERY_FAILURE);
		bool timedOut = now - k.start > LOOKUP_TIMEOUT;
		/* libbitdht turns a queued find into a query at its next refresh */
		bool queued = !have && now - k.start < 120;

		if ((have && !done && !timedOut) || queued)
			return;

		/* only a lookup libbitdht ended by itself before its age cap */
		if (done && q.mSearchTime <= LOOKUP_MAX_AGE)
		{
			std::vector<double> answered, heard;
			std::set<bdMetric> seen;
			auto reporters = [&q](const bdMetric &m) -> uint32_t
			{
				auto it = q.mReporters.find(m);
				return it == q.mReporters.end() ? 0 : it->second;
			};
			for (const auto &c : q.mClosest)
			{
				bool ans = (c.second.mLastRecvTime != 0);
				if (ans)
				{
					answered.push_back(metricFraction(c.first));
					if (kind == KIND_RS)
						mWalkSeen[hexId(c.second.mPeerId.id)] = now;
				}
				if ((ans || reporters(c.first) >= MIN_REPORTERS) && seen.insert(c.first).second)
					heard.push_back(metricFraction(c.first));
			}
			for (const auto &c : q.mPotentialPeers)
				if (reporters(c.first) >= MIN_REPORTERS && seen.insert(c.first).second)
					heard.push_back(metricFraction(c.first));

			Sample s{now, 0, 0, 0, 0};
			if (kthDistance(answered, K_ANSWERED, s.kA, s.dA) &&
			    kthDistance(heard, K_HEARD, s.kH, s.dH))
			{
				k.samples.push_back(s);
				while (k.samples.size() > LOOKUP_KEEP)
					k.samples.pop_front();
				RsDbg() << "DHT size lookup " << (kind == KIND_RS ? "rs" : "all")
				        << " secs=" << q.mSearchTime << " answered=" << answered.size()
				        << " heard=" << heard.size() << " kA=" << s.kA << " dA=" << s.dA
				        << " kH=" << s.kH << " dH=" << s.dH;
			}
		}

		dht->removeFindNode(&k.id);
		k.running = false;
		k.lastEnd = now;
	}

	if (now - k.lastEnd >= LOOKUP_PERIOD)
	{
		bdStdRandomNodeId(&k.id);
		dht->addFindNode(&k.id, k.flags);
		k.start = now;
		k.running = true;
	}
}

void DhtSizeEstimator::poll_locked(UdpBitDht *dht, const std::vector<bdNodeId> &friendsInDht,
                                   rstime_t now)
{
	std::set<std::string> present;
	/* bucket 0 (XOR distance < 2) can only hold our own node */
	for (int i = 1; i < NBUCKETS; ++i)
	{
		bdBucket b;
		dht->getDhtBucket(i, b);
		for (const bdPeer &p : b.entries)
			if (p.mPeerFlags & BITDHT_PEER_STATUS_DHT_ENGINE)
				present.insert(hexId(p.mPeerId.id));
	}
	for (const std::string &id : present)
		mTableSeen[id] = now;

	PollStat ps{now, (uint32_t) present.size(), (uint32_t) friendsInDht.size(), 0};
	for (const bdNodeId &f : friendsInDht)
		if (present.count(hexId(f)))
			ps.friendsInTable++;
	mPolls.push_back(ps);
}

void DhtSizeEstimator::prune_locked(rstime_t now)
{
	const rstime_t keep = now - DAY;
	for (auto *m : {&mTableSeen, &mWalkSeen})
		for (auto it = m->begin(); it != m->end(); )
		{
			if (it->second < keep)
				it = m->erase(it);
			else
				++it;
		}
	while (!mPolls.empty() && mPolls.front().t < keep)
		mPolls.pop_front();
	for (int i = 0; i < NKINDS; ++i)
		while (!mKinds[i].samples.empty() && mKinds[i].samples.front().t < keep)
			mKinds[i].samples.pop_front();
	if (mObsStart < keep)
		mObsStart = keep;
}

void DhtSizeEstimator::estimate_locked(rstime_t now)
{
	(void) now;
	RsDhtSizeEstimate est;
	est.lookupsAvailable = (mKinds[KIND_ALL].flags != 0);

	/* ---- lookups ---- */
	auto fill = [](const std::deque<Sample> &ss, uint32_t &mn, uint32_t &mx, bool &prov,
	               uint32_t &reach, uint32_t &reachErr, uint32_t &heard,
	               uint32_t &heardErr, uint32_t &count)
	{
		std::vector<std::pair<int, double> > a, h;
		for (const Sample &s : ss)
		{
			a.push_back(std::make_pair(s.kA, s.dA));
			h.push_back(std::make_pair(s.kH, s.dH));
		}
		count = (uint32_t) ss.size();
		prov = ss.size() < LOOKUP_FULL;
		if (ss.empty())
			return;
		Pooled pa = pooled(a), ph = pooled(h);
		reach = clampU32(pa.n);
		reachErr = errPercent(pa);
		heard = clampU32(std::max(ph.n, pa.n));
		heardErr = errPercent(ph);
		mn = clampU32(pa.lo);
		mx = std::max(mn, clampU32(std::max(ph.hi, pa.hi)));
	};
	fill(mKinds[KIND_ALL].samples, est.allMin, est.allMax, est.allProvisional,
	     est.allReachable, est.allReachableErr, est.allHeard, est.allHeardErr, est.allLookups);
	fill(mKinds[KIND_RS].samples, est.rsMin, est.rsMax, est.rsProvisional,
	     est.rsReachable, est.rsReachableErr, est.rsHeard, est.rsHeardErr, est.rsLookups);

	/* ---- our routing table (maps pruned to the last 24 h) ---- */
	est.rsSeen24h = (uint32_t) mTableSeen.size();

	uint32_t overlap = 0;
	for (const auto &w : mWalkSeen)
		if (mTableSeen.count(w.first))
			overlap++;
	if (overlap >= CHAPMAN_MIN_OVERLAP)
		est.rsDistinct24h = clampU32((mTableSeen.size() + 1.0) * (mWalkSeen.size() + 1.0)
		                             / (overlap + 1.0) - 1.0);

	double inTable = 0, friends = 0, friendsInTable = 0, polls = 0;
	for (const PollStat &p : mPolls)
	{
		if (p.friends == 0)
			continue;
		inTable += p.rsInTable;
		friends += p.friends;
		friendsInTable += p.friendsInTable;
		polls++;
	}
	if (friendsInTable > 0)
		est.rsFriendCalibrated = clampU32(inTable / polls * friends / friendsInTable);
	if (!mPolls.empty())
		est.rsFriendsInDht = mPolls.back().friends;

	mEst = est;
}

/* Format:
 *   # rs-dht-size v2
 *   S <first poll of the data kept>
 *   T <dht id> <last seen>              RS node of our routing table
 *   W <dht id> <last seen>              RS node an RS lookup met
 *   L <kind> <time> <kA> <dA> <kH> <dH> lookup result (kind 0 all, 1 rs)
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
		f << FILE_HEADER << "\n";
		f << "S " << mObsStart << "\n";
		for (const auto &it : mTableSeen)
			f << "T " << it.first << " " << it.second << "\n";
		for (const auto &it : mWalkSeen)
			f << "W " << it.first << " " << it.second << "\n";
		char buf[128];
		for (int i = 0; i < NKINDS; ++i)
			for (const Sample &s : mKinds[i].samples)
			{
				snprintf(buf, sizeof(buf), "L %d %lld %d %.10g %d %.10g\n",
				         i, (long long) s.t, s.kA, s.dA, s.kH, s.dH);
				f << buf;
			}
		if (!f)
			return;
	}
	RsDirUtil::renameFile(tmp, mFile);
}

void DhtSizeEstimator::load_locked()
{
	std::ifstream f(mFile);
	std::string line;
	if (!std::getline(f, line) || line != FILE_HEADER)
		return; /* missing, or an older format: start afresh */

	while (std::getline(f, line))
	{
		if (line.size() < 3 || line[1] != ' ')
			continue;
		std::istringstream is(line.substr(2));
		switch (line[0])
		{
		case 'S':
		{
			long long t = 0;
			if (is >> t)
				mObsStart = (rstime_t) t;
			break;
		}
		case 'T':
		case 'W':
		{
			std::string id;
			long long t = 0;
			if ((is >> id >> t) && id.size() == 40)
				(line[0] == 'T' ? mTableSeen : mWalkSeen)[id] = (rstime_t) t;
			break;
		}
		case 'L':
		{
			int kind = -1;
			long long t = 0;
			Sample s{0, 0, 0, 0, 0};
			if ((is >> kind >> t >> s.kA >> s.dA >> s.kH >> s.dH) &&
			    kind >= 0 && kind < NKINDS && s.kA >= 2 && s.kH >= 2 && s.dA > 0 && s.dH > 0)
			{
				s.t = (rstime_t) t;
				mKinds[kind].samples.push_back(s);
			}
			break;
		}
		default:
			break;
		}
	}
	for (int i = 0; i < NKINDS; ++i)
		while (mKinds[i].samples.size() > LOOKUP_KEEP)
			mKinds[i].samples.pop_front();
}
