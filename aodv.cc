/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <aodv/aodv.h>
#include <aodv/aodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#include <iostream>
#include <sstream>
#include<string>  
#include <unistd.h>

#include <cstdlib>
#include <time.h>
#include <cmath>


#include <fstream>
#include <bits/stdc++.h>

#include <vector>





#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

//#define DEBUG
//#define ERROR

#ifdef DEBUG
static int route_request = 0;
#endif

using namespace std;
/*
  TCL Hooks
*/


int hdr_aodv::offset_;
static class AODVHeaderClass : public PacketHeaderClass {
public:
        AODVHeaderClass() : PacketHeaderClass("PacketHeader/AODV",
                                              sizeof(hdr_all_aodv)) {
	  bind_offset(&hdr_aodv::offset_);
	} 
} class_rtProtoAODV_hdr;

static class AODVclass : public TclClass {
public:
        AODVclass() : TclClass("Agent/AODV") {}
        TclObject* create(int argc, const char*const* argv) {
          assert(argc == 5);
          //return (new AODV((nsaddr_t) atoi(argv[4])));
	  return (new AODV((nsaddr_t) Address::instance().str2addr(argv[4])));
        }
} class_rtProtoAODV;


int
AODV::command(int argc, const char*const* argv) {
  if(argc == 2) {
  Tcl& tcl = Tcl::instance();
    
    if(strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }

    //edited by atnatiyos for blackhole attack
    // Modification - blackhole attack code
    if(strncasecmp(argv[1], "blackhole", 9) == 0) {
      malicious = 1000;
      return TCL_OK;
    }
    
    if(strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

#ifndef AODV_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0);
#endif // LINK LAYER DETECTION

      rtimer.handle((Event*) 0);
      return TCL_OK;
     }               
  }
  else if(argc == 3) {
    if(strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }

    else if(strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if(logtarget == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if(strcmp(argv[1], "drop-target") == 0) {
    int stat = rqueue.command(argc,argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    }
    else if(strcmp(argv[1], "if-queue") == 0) {
    ifqueue = (PriQueue*) TclObject::lookup(argv[2]);
      
      if(ifqueue == 0)
	return TCL_ERROR;
      return TCL_OK;
    }
    else if (strcmp(argv[1], "port-dmux") == 0) {
    	dmux_ = (PortClassifier *)TclObject::lookup(argv[2]);
	if (dmux_ == 0) {
		fprintf (stderr, "%s: %s lookup of %s failed\n", __FILE__,
		argv[1], argv[2]);
		return TCL_ERROR;
	}
	return TCL_OK;
    }
  }
  return Agent::command(argc, argv);
}

/* 
   Constructor
*/

AODV::AODV(nsaddr_t id) : Agent(PT_AODV),
			  btimer(this), htimer(this), ntimer(this), 
			  rtimer(this), lrtimer(this), rqueue() {
 
  

  index = id;
  seqno = 2;
  bid = 1;

  LIST_INIT(&nbhead);
  LIST_INIT(&bihead);

  logtarget = 0;
  ifqueue = 0;

  //malicious node
  malicious = 999;
  count = 0;

timestamp_ = 0.1668089;
sequence_  = 1.02110689;
constant_  = 2.1;

update_time = -0.226162796;
hop_countCoefficient = -0.0003189793;

//1.02778297 -0.22162796  0.16368089


accuracy = fopen("accuracy.csv","a");  
regression = fopen("regression.csv","a");
replier = fopen("replier.csv","a");
passcomp = fopen("classification.csv","a");



//system("./stochastic.sh");
//extract();

}

/*
  Timers
*/


 void 
 AODV::split_c(string str)
 {
    std::stringstream sstr(str);
    std::vector<std::string> v;
    while(sstr.good())
    {
        std::string substr;
        getline(sstr, substr, ',');
        v.push_back(substr);
    }
    
    double T_timestamp_ = timestamp_;
    double T_sequence_ = sequence_;
    double T_constant_ = constant_;
    
    istringstream((v[0])) >> timestamp_;
    istringstream((v[1])) >> sequence_;
    istringstream((v[2])) >> constant_;

    if(T_timestamp_ != timestamp_){
      count = 0;
      
    }else{
      
    }
    }

void 
AODV::extract(){
  
fstream file;
file.open("./cofficients.csv");
if(!file.is_open())
{
cout<<"Unable to open the file."<<endl;

}
 
string line;
while(getline(file, line))
{
cout<<line<<endl;
split_c(line);
}
file.close();
}



void
BroadcastTimer::handle(Event*) {
  agent->id_purge();
  Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
}

void
HelloTimer::handle(Event*) {
   agent->sendHello();
   double interval = MinHelloInterval + 
                 ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
   assert(interval >= 0);
   Scheduler::instance().schedule(this, &intr, interval);
}

void
NeighborTimer::handle(Event*) {
  agent->nb_purge();
  Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
}

void
RouteCacheTimer::handle(Event*) {
  agent->rt_purge();
#define FREQUENCY 0.5 // sec
  Scheduler::instance().schedule(this, &intr, FREQUENCY);
}

void
LocalRepairTimer::handle(Event* p)  {  // SRD: 5/4/99
aodv_rt_entry *rt;
struct hdr_ip *ih = HDR_IP( (Packet *)p);

   /* you get here after the timeout in a local repair attempt */
   /*	fprintf(stderr, "%s\n", __FUNCTION__); */


    rt = agent->rtable.rt_lookup(ih->daddr());
	
    if (rt && rt->rt_flags != RTF_UP) {
    // route is yet to be repaired
    // I will be conservative and bring down the route
    // and send route errors upstream.
    /* The following assert fails, not sure why */
    /* assert (rt->rt_flags == RTF_IN_REPAIR); */
		
      //rt->rt_seqno++;
      agent->rt_down(rt);
      // send RERR
#ifdef DEBUG
      fprintf(stderr,"Dst - %d, failed local repair\n", rt->rt_dst);
#endif      
    }
    Packet::free((Packet *)p);
}


/*
   Broadcast ID Management  Functions
*/


void
AODV::id_insert(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = new BroadcastID(id, bid);

 assert(b);
 b->expire = CURRENT_TIME + BCAST_ID_SAVE;
 LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
AODV::id_lookup(nsaddr_t id, u_int32_t bid) {
BroadcastID *b = bihead.lh_first;
 
 // Search the list for a match of source and bid
 for( ; b; b = b->link.le_next) {
   if ((b->src == id) && (b->id == bid))
     return true;     
 }
 return false;
}

void
AODV::id_purge() {
BroadcastID *b = bihead.lh_first;
BroadcastID *bn;
double now = CURRENT_TIME;

 for(; b; b = bn) {
   bn = b->link.le_next;
   if(b->expire <= now) {
     LIST_REMOVE(b,link);
     delete b;
   }
 }
}

/*
  Helper Functions
*/

double
AODV::PerHopTime(aodv_rt_entry *rt) {
int num_non_zero = 0, i;
double total_latency = 0.0;

 if (!rt)
   return ((double) NODE_TRAVERSAL_TIME );
	
 for (i=0; i < MAX_HISTORY; i++) {
   if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
   }
 }
 if (num_non_zero > 0)
   return(total_latency / (double) num_non_zero);
 else
   return((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
*/

static void
aodv_rt_failed_callback(Packet *p, void *arg) {
  ((AODV*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
AODV::rt_ll_failed(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt;
nsaddr_t broken_nbr = ch->next_hop_;

#ifndef AODV_LINK_LAYER_DETECTION
 drop(p, DROP_RTR_MAC_CALLBACK);
#else 

 /*
  * Non-data packets and Broadcast Packets can be dropped.
  */
  if(! DATA_PACKET(ch->ptype()) ||
     (u_int32_t) ih->daddr() == IP_BROADCAST) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
	if((rt = rtable.rt_lookup(ih->daddr())) == 0) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef AODV_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */


  if (ch->num_forwards() > rt->rt_hops) {
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  }
  else	
#endif // LOCAL REPAIR	

  {
    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
while((p = ifqueue->filter(broken_nbr))) {
     drop(p, DROP_RTR_MAC_CALLBACK);
    }	
    nb_delete(broken_nbr);
  }

#endif // LINK LAYER DETECTION
}

void
AODV::handle_link_failure(nsaddr_t id) {
aodv_rt_entry *rt, *rtn;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);

 re->DestCount = 0;
 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next; 
   if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id) ) {
     assert (rt->rt_flags == RTF_UP);
     assert((rt->rt_seqno%2) == 0);
     rt->rt_seqno++;
     re->unreachable_dst[re->DestCount] = rt->rt_dst;
     re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
		     index, re->unreachable_dst[re->DestCount],
		     re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
     re->DestCount += 1;
     rt_down(rt);
   }
   // remove the lost neighbor from all the precursor lists
   rt->pc_delete(id);
 }   

 if (re->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr, false);
 }
 else {
   Packet::free(rerr);
 }
}

void
AODV::local_rt_repair(aodv_rt_entry *rt, Packet *p) {
#ifdef DEBUG
  fprintf(stderr,"%s: Dst - %d\n", __FUNCTION__, rt->rt_dst); 
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  sendRequest(rt->rt_dst,10000000,false);

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);

}


// edited by atnatiyos for adding tester request messages
void                   
AODV::test_request_adder(aodv_test_request *rt,nsaddr_t rep_dest,u_int32_t seqnum,nsaddr_t rp_sender,u_int32_t    hop_count,u_int32_t    routeID){

 rt->requesterID = rep_dest;
 rt->replied_seq_num = seqnum;
 rt->rp_sender = rp_sender; 
 rt->hop_count = hop_count;
 rt->routeID = routeID;
 
}

// void                   
// AODV::test_request_try(aodv_test_request *rt,u_int32_t trying){

//  rt->trail = trying;

 
// }


// return actual requester source
nsaddr_t
AODV::test_request_source(aodv_test_request* rt){

return rt->requesterID;


}

// return actual replied sequence number
u_int32_t
AODV::test_request_sequence(aodv_test_request* rt){
return rt->replied_seq_num;
}



// edited by atnatiyos for adding malicious nodes
void                   
AODV::malicious_adding(aodv_malicious_nodes *rt, nsaddr_t id){

 

rt->list_it = rt->coincidences.begin();
	
        
        
        bool not_in_list = true;
        
        for(; rt->list_it != rt->coincidences.end(); ++rt->list_it){
        
        rt->map_it = (*rt->list_it).begin();
	for(; rt->map_it != (*rt->list_it).end(); rt->map_it++)
	{
	  // for checking if the node is already in the malicious node list
    if(rt->map_it->first == id ){
      not_in_list = false;
      
    }
    }
}

if(not_in_list){
  

rt->coincidence[id] = CURRENT_TIME;
rt->coincidences.push_back(rt->coincidence);

}
}


///// malicious adder method
void
AODV::malicious_adder(nsaddr_t index,nsaddr_t M_node){

// adding malicious node to the list
aodv_malicious_nodes *rm; //for adding malicious nodes to the list
rm = mtable.m_lookup(index);
if(rm == 0){
rm = mtable.m_add(index);

}
 malicious_adding(rm,M_node);
}

// malicious node checker method
bool
AODV::malicious_node_checker(aodv_malicious_nodes* rt, nsaddr_t M_node){

rt->list_it = rt->coincidences.begin();
     for(; rt->list_it != rt->coincidences.end(); ++rt->list_it){
        
        rt->map_it = (*rt->list_it).begin();
	for(; rt->map_it != (*rt->list_it).end(); rt->map_it++)
	{

    
	  // for checking if the node is already in the malicious node list
    if(rt->map_it->first == M_node ){
     
      //for removing the node from malicious list by checking it expirdation
    if( CURRENT_TIME - rt->map_it->second > 50){
      // if the time is expired the pass the reply by removing the node from the malicious node list
      rt->coincidences.pop_front();
      return false;
    }else{
      
      return true;
      
    }
      
    }
    
  }
  
}

return false;
}

/*
trusted node adder
*/
void
AODV::trust(aodv_trust_entry *rt,double timestamp){
  
 
}

/*
check wheather the trust expired or not
*/
double
AODV::trust_expire(aodv_trust_entry *rt){
  if(rt != 0){
    return 0;
  }else{
    return 0;
  }
}

//edited by atnatiyos hold the info needed to calaculate the threshold
void
AODV::sequenceInfoTable(aodv_rt_entry *rt,double requesterStamp,u_int32_t seqnum){
  rt->rt_requesterTimestamp = requesterStamp;
  rt->rt_seqno = seqnum;
}



void
AODV::rt_update(aodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
	       	nsaddr_t nexthop, double expire_time,double update_timestamp,u_int8_t broadcast,u_int16_t  path) {

     rt->rt_seqno = seqnum;
     rt->rt_hops = metric;
     rt->rt_flags = RTF_UP;
     rt->rt_nexthop = nexthop;
     rt->rt_expire = expire_time;
     rt->rt_timestamp = CURRENT_TIME - update_timestamp;

     if(broadcast != 0){
      rt->rt_broadcast = broadcast;
     }

     rt->rt_path = path;

    
}

void
AODV::rt_down(aodv_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if(rt->rt_flags == RTF_DOWN) {
    return;
  }

  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
*/

void
AODV::rt_resolve(Packet *p) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
aodv_rt_entry *rt;

if(malicious == 100){
  drop(p,DROP_RTR_ROUTE_LOOP);
}
 /*
  *  Set the transmit failure callback.  That
  *  won't change.
  */
 ch->xmit_failure_ = aodv_rt_failed_callback;
 ch->xmit_failure_data_ = (void*) this;
	rt = rtable.rt_lookup(ih->daddr());
 if(rt == 0) {
	  rt = rtable.rt_add(ih->daddr());
 }

 /*
  * If the route is up, forward the packet 


  */
	
 if(rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   forward(rt, p, NO_DELAY);
 }
 /*
  *  if I am the source of the packet, then do a Route Request.
  */
	else if(ih->saddr() == index) {
   rqueue.enque(p);
   sendRequest(rt->rt_dst,10000000,false);
 }
 /*
  *	A local repair is in progress. Buffer the packet. 
  */
 else if (rt->rt_flags == RTF_IN_REPAIR) {
   rqueue.enque(p);
 }

 /*
  * I am trying to forward a packet for someone else to which
  * I don't have a route.
  */
 else {
 Packet *rerr = Packet::alloc();
 struct hdr_aodv_error *re = HDR_AODV_ERROR(rerr);
 /* 
  * For now, drop the packet and send error upstream.
  * Now the route errors are broadcast to upstream
  * neighbors - Mahesh 09/11/99
  */	
 
   assert (rt->rt_flags == RTF_DOWN);
   re->DestCount = 0;
   re->unreachable_dst[re->DestCount] = rt->rt_dst;
   re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
   re->DestCount += 1;
#ifdef DEBUG
   fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
   sendError(rerr, false);

   drop(p, DROP_RTR_NO_ROUTE);
 }

}

void
AODV::rt_purge() {
aodv_rt_entry *rt, *rtn;
double now = CURRENT_TIME;
double delay = 0.0;
Packet *p;

 for(rt = rtable.head(); rt; rt = rtn) {  // for each rt entry
   rtn = rt->rt_link.le_next;
   if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
   // if a valid route has expired, purge all packets from 
   // send buffer and invalidate the route.                    
	assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
       fprintf(stderr, "%s: calling drop()\n",
                       __FUNCTION__);
#endif // DEBUG
       drop(p, DROP_RTR_NO_ROUTE);
     }
     rt->rt_seqno++;
     assert (rt->rt_seqno%2);
     rt_down(rt);
   }
   else if (rt->rt_flags == RTF_UP) {
   // If the route is not expired,
   // and there are packets in the sendbuffer waiting,
   // forward them. This should not be needed, but this extra 
   // check does no harm.
     assert(rt->rt_hops != INFINITY2);
     while((p = rqueue.deque(rt->rt_dst))) {
       forward (rt, p, delay);
       delay += ARP_DELAY;
     }
   } 
   else if (rqueue.find(rt->rt_dst))
   // If the route is down and 
   // if there is a packet for this destination waiting in
   // the sendbuffer, then send out route request. sendRequest
   // will check whether it is time to really send out request
   // or not.
   // This may not be crucial to do it here, as each generated 
   // packet will do a sendRequest anyway.

     sendRequest(rt->rt_dst,10000000,false); 
   }

}

/*
  Packet Reception Routines
*/

void
AODV::recv(Packet *p, Handler*) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 assert(initialized());
 //assert(p->incoming == 0);
 // XXXXX NOTE: use of incoming flag has been depracated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.

 if(ch->ptype() == PT_AODV) {
   ih->ttl_ -= 1;
   recvAODV(p);
   return;
 }


 /*
  *  Must be a packet I'm originating...
  */
if((ih->saddr() == index) && (ch->num_forwards() == 0)) {
 /*
  * Add the IP Header.  
  * TCP adds the IP header too, so to avoid setting it twice, we check if
  * this packet is not a TCP or ACK segment.
  */
  if (ch->ptype() != PT_TCP && ch->ptype() != PT_ACK) {
    ch->size() += IP_HDR_LEN;
  }
   // Added by Parag Dadhania && John Novatnack to handle broadcasting
  if ( (u_int32_t)ih->daddr() != IP_BROADCAST) {
    ih->ttl_ = NETWORK_DIAMETER;
  }
}
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
else if(ih->saddr() == index) {
   drop(p, DROP_RTR_ROUTE_LOOP);
   return;
 }
 /*
  *  Packet I'm forwarding...
  */
 else {
 /*
  *  Check the TTL.  If it is zero, then discard.
  */
   if(--ih->ttl_ == 0) {
     drop(p, DROP_RTR_TTL);
     return;
   }
 }
// Added by Parag Dadhania && John Novatnack to handle broadcasting
 if ( (u_int32_t)ih->daddr() != IP_BROADCAST)
   rt_resolve(p);
 else
   forward((aodv_rt_entry*) 0, p, NO_DELAY);
}


void
AODV::recvAODV(Packet *p) {
 struct hdr_aodv *ah = HDR_AODV(p);

 assert(HDR_IP (p)->sport() == RT_PORT);
 assert(HDR_IP (p)->dport() == RT_PORT);

 /*
  * Incoming Packets.
  */
 switch(ah->ah_type) {

 case AODVTYPE_RREQ:
   recvRequest(p);
   break;

 case AODVTYPE_RREP:
   recvReply(p);
   break;

 case AODVTYPE_RERR:
   recvError(p);
   break;

 case AODVTYPE_HELLO:
   recvHello(p);
   break;
        
 default:
   fprintf(stderr, "Invalid AODV type (%x)\n", ah->ah_type);
   exit(1);
 }

}


void
AODV::recvRequest(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt;


  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if(rq->rq_src == index) {

#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  } 

 if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
   fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG
 
   Packet::free(p);
   return;
 }

 /*
  * Cache the broadcast ID
  */
 id_insert(rq->rq_src, rq->rq_bcast_id);



 /* 
  * We are either going to forward the REQUEST or generate a
  * REPLY. Before we do anything, we make sure that the REVERSE
  * route is in the route table.
  */
 aodv_rt_entry *rt0; // rt0 is the reverse route 
   
   rt0 = rtable.rt_lookup(rq->rq_src);
   if(rt0 == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rt0 = rtable.rt_add(rq->rq_src);
   }

/*
    edited by atnatiyos tefera
    create another entry to store requester timestamp for in each intermidiate node
    separately based on the sender and reciever uniquely
  */
string s_r;
      stringstream SR;

      SR << (int) rq->rq_src;
      SR >> s_r;

      string r_s;
      stringstream RS;

      RS << (int) rq->rq_dst;
      RS >> r_s;

      string sender_reciever = s_r +"00"+ r_s;
      int identification;
       std::istringstream(sender_reciever) >> identification;
      nsaddr_t sender_reciever_address = identification;



   rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));




bool pass = false;
if(rq->correct){
   pass = true;
   }
   if ( (rq->rq_src_seqno > rt0->rt_seqno ) ||
    	((rq->rq_src_seqno == rt0->rt_seqno) && 
	 (rq->rq_hop_count < rt0->rt_hops)) || pass ) {
 


             // calculating update rate for sender node

//check if the request is for the first time or their is prior information about sender

if(rt0->rt_timestamp != 0 && rq->rq_src_seqno - rt0->rt_seqno > 0){
  rt0->rt_updateRateTempo = ((CURRENT_TIME - rt0->rt_timestamp)/(rq->rq_src_seqno - rt0->rt_seqno));

  if(rt0->rt_updateRate != 0){
    rt0->rt_updateRate = ((rt0->rt_updateRate +rt0->rt_updateRateTempo)/2);
  }else{
    rt0->rt_updateRate = rt0->rt_updateRateTempo;
  }

}

  aodv_rt_entry *rtI;
    
    
     rtI = rtable.rt_lookup(sender_reciever_address);
     //rtable.rt_delete(sender_reciever_address);
   if(rtI == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rtI = rtable.rt_add(sender_reciever_address);
   } 



sequenceInfoTable(rtI,rq->rq_requesterTimestamp,rq->rq_dst_seqno);
 

   // If we have a fresher seq no. or lesser #hops for the 
   // same seq no., update the rt entry. Else don't bother.
rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
     	       max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)),0,rq->rq_bcast_id,NULL);
     if (rt0->rt_req_timeout > 0.0) {
     // Reset the soft state and 
     // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
     // This is because route is used in the forward direction,
     // but only sources get benefited by this change
       rt0->rt_req_cnt = 0;
       rt0->rt_req_timeout = 0.0; 
       rt0->rt_req_last_ttl = rq->rq_hop_count;
       rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
     }

     /* Find out whether any buffered packet can benefit from the 
      * reverse route.
      * May need some change in the following code - Mahesh 09/11/99
      */
     assert (rt0->rt_flags == RTF_UP);
     Packet *buffered_pkt;
     while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
       if (rt0 && (rt0->rt_flags == RTF_UP)) {
	assert(rt0->rt_hops != INFINITY2);
         forward(rt0, buffered_pkt, NO_DELAY);
       }
     }
   } 
   // End for putting reverse route in rt table


 /*
  * We have taken care of the reverse route stuff.
  * Now see whether we can send a route reply. 
  */

 rt = rtable.rt_lookup(rq->rq_dst);
// if(rt != 0 && rt->rt_updateRateTempo != 0){
//  rt->rt_updateRate = rt->rt_updateRateTempo;
// }
 // First check if I am the destination ..

 if(rq->rq_dst == index) {

#ifdef DEBUG
   fprintf(stderr, "%d - %s: destination sending reply\n",
                   index, __FUNCTION__);
#endif // DEBUG

               
   // Just to be safe, I use the max. Somebody may have
   // incremented the dst seqno.
   
   if(seqno >= rq->rq_dst_seqno){
    seqno = max(seqno, rq->rq_dst_seqno)+1;
   }else{
    
    sendRequest(rq->rq_src,10000000,true);
    seqno = max(seqno, seqno+1);
   }

//seqno = max(seqno, rq->rq_dst_seqno)+1;
  
   if (seqno%2) seqno++;
   rep = index;
   sendReply(rq->rq_src,           // IP Destination
             1,                    // Hop Count
             index,                // Dest IP Address
             seqno,                // Dest Sequence Num
             MY_ROUTE_TIMEOUT,     // Lifetime
             rq->rq_timestamp,
             index);    // timestamp
 
   Packet::free(p);
 }

//  Modification - generate fake replies by blackhole attacker
  else if(malicious==1000) {
    seqno = max(seqno, rq->rq_dst_seqno)+1;
    if (seqno%2) seqno++;
   //seqno = seqno + 2;
    

 //double malicious_sequence  = calculateThreshold(rq->rq_dst_seqno, rq->rq_requesterTimestamp , 1) - 1;

  int malicious_sequence = rand() % 20 + rq->rq_dst_seqno + 10;
    rep = index;
    sendReply(rq->rq_src,           // IP Destination
              2,                    // Hop Count
              rq->rq_dst,
              malicious_sequence,
             // seqno,
              MY_ROUTE_TIMEOUT,
              rq->rq_timestamp,
              index);    // timestamp
    //rt->pc_insert(rt0->rt_nexthop);
    Packet::free(p);
  }

 // I am not the destination, but I may have a fresh enough route.

 else if (rt && (rt->rt_hops != INFINITY2) && 
	  	(rt->rt_seqno >= rq->rq_dst_seqno) ) {

       
rep = index;
   //assert (rt->rt_flags == RTF_UP);
   assert(rq->rq_dst == rt->rt_dst);
   //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
   sendReply(rq->rq_src,
             rt->rt_hops + 1,
             rq->rq_dst,
             rt->rt_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp,
             index);
   // Insert nexthops to RREQ source and RREQ destination in the
   // precursor lists of destination and source respectively
   rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
   rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP  

   sendReply(rq->rq_dst,
             rq->rq_hop_count,
             rq->rq_src,
             rq->rq_src_seqno,
	     (u_int32_t) (rt->rt_expire - CURRENT_TIME),
	     //             rt->rt_expire - CURRENT_TIME,
             rq->rq_timestamp,
             index);
#endif
   
// TODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
   
// DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.

	Packet::free(p);
 }
 /*
  * Can't reply. So forward the  Route Request
  */
 else {
   ih->saddr() = index;
   ih->daddr() = IP_BROADCAST;
   rq->rq_hop_count += 1;
   // Maximum sequence number seen en route
   if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
   forward((aodv_rt_entry*) 0, p, DELAY);
 }

}
nsaddr_t
AODV::test_adder(nsaddr_t source, nsaddr_t destination,int hop_count, nsaddr_t to)
{
        /*
          for checking if the reply is for the testing or normal reply
      */
string s_r2;
      stringstream SR2;

      SR2 << source;//(int) rp->rp_src;
      SR2 >> s_r2;

      string r_s2;
      stringstream RS2;

      RS2 << destination;//(int) rp->rp_dst;
      RS2 >> r_s2;


      string h_c2;
      stringstream HC2;

      HC2 << hop_count;// rp->rp_hop_count;
      HC2>> h_c2;

   
      // string t_c2;
      // stringstream TC2;

      // TC2 << to;// rp->rp_hop_count;
      // TC2>> t_c2;

string sender_reciever2;
      
sender_reciever2 = s_r2 +"00"+ r_s2+"00"+h_c2;
    
      int identification2;
       std::istringstream(sender_reciever2) >> identification2;
      nsaddr_t sender_reciever_address2 = identification2;
      return sender_reciever_address2;

}

double
AODV::calculateThreshold(u_int32_t sequence, double time ,double update){

// for Linear regression
double threshold = ((sequence*sequence_ )+ (timestamp_*time) +  (update_time*update) + (constant_ ) - 10 );

//for polynomial regression
//double threshold = ((sequence*1.1505)+ (1.3093*time) +  (-1.1188 *update) + (-0.0768*sequence*update) + (-0.81745*sequence*time) + (0.3586*update*update) +(-0.3558*update*time) +(-0.0102*time*time)+(-0.0254*update*update*update)+(0.0177*update*update*time));

 return threshold; 
}

double
AODV::classify(u_int32_t sequence, double time ,double update,u_int32_t new_sequence ){

// for Linear regression
double threshold = ((sequence*-0.13070487 )+ (timestamp_*0.10105252) +  (abs(update_time)*0.00475285) + (new_sequence*0.14534141) + (-4.50860332 ) );

//double logarithm = log(threshold);
 double exponential = exp(-1*threshold);
 double classes = 1/(1+exponential);

 //std::cout<<classes<<"\n";

 return classes; 
}



void
AODV::recvReply(Packet *p) {
//struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt;
char suppress_reply = 0;
double delay = 0.0;
	
#ifdef DEBUG
 fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
#endif // DEBUG

rt = rtable.rt_lookup(rp->rp_dst);
        
 /*
  *  If I don't have a rt entry to this host... adding
  */
 if(rt == 0) {
   rt = rtable.rt_add(rp->rp_dst);
 }

// if(count == 20){
//   //extract();
// }
//  /*
//   *  Got a reply. So reset the "soft state" maintained for 
//   *  route requests in the request table. We don't really have
//   *  have a separate request table. It is just a part of the
//   *  routing table itself. 
//   */
//  // Note that rp_dst is the dest of the data packets, not the
//  // the dest of the reply, which is the src of the dattest_request_sequencea packets.

 

 /*
  * Add a forward route table entry... here I am following 
  * Perkins-Royer AODV paper almost literally - SRD 5/99
  */


//if not available trust set it for the first time
//  aodv_trust_entry *rtrust = trust_table.trust_lookup(rp->rp_src);
//   if(rtrust == 0){
// trust_table.trust_add(rp->rp_src,5);
//     }
       

//  aodv_trust_entry *rtrust1 = trust_table.trust_lookup(rp->rp_src);
// std::cout<<index<<" "<<rp->rp_src<<" "<<rtrust1->trust_level<<"\n";
  

 string s_r;
      stringstream SR;

      SR << (int) ih->daddr();
      SR >> s_r;

      string r_s;
      stringstream RS;

      RS << (int) rp->rp_dst;
      RS >> r_s;


      string sender_reciever = s_r +"00"+ r_s;
      int identification;
       std::istringstream(sender_reciever) >> identification;
      nsaddr_t sender_reciever_address = identification;




 //pull it from the revese table for comparision edited by atnatiyos
aodv_rt_entry *rt1 = rtable.rt_lookup(sender_reciever_address); 
bool pass = false;
bool replace_malicious_node_rt = false;
bool is_testing_request = false;


 int hopcount = rp->rp_hop_count;
 nsaddr_t sender_reciever_address2 = test_adder(rp->rp_src,rp->rp_dst,hopcount,ih->daddr());
// //nsaddr_t sender_reciever_address2x = test_adder(rp->rp_src,rp->rp_dst,rp->rp_hop_count,2);

 aodv_test_request *rt_request = trtable.tr_lookup(sender_reciever_address2);
// //aodv_test_request *rt_request2 = trtable.tr_lookup(sender_reciever_address2x);




if((rt->rt_seqno < rp->rp_dst_seqno) ||   // newer route 
      ((rt->rt_seqno == rp->rp_dst_seqno) &&  
       (rt->rt_hops > rp->rp_hop_count))){

// /*             EDITED BY ATNATIYOS
//     creating an access point to get and add malicious 
//     node that the current node can see
//     */

// aodv_malicious_nodes *rm; //for adding malicious nodes to the list
// rm = mtable.m_lookup(index);
// if(rm == 0){
// rm = mtable.m_add(index);
// }
// //is the node listed as malicious node ?
// bool node_is_malicious = malicious_node_checker(rm,rp->rp_src);

// /*
//    if the reply is for test request no need calculation is needed
// */





 if(rt_request == 0 && rp->rp_src != rp->rp_dst)
{


/*
   if the reply sender is in malicious list no need calculation
*/

// aodv_trust_entry *rtrust = trust_table.trust_lookup(rp->rp_src);
// double trust_recorded = trust_expire(rtrust);

// //--------------this for node blocker and trust node-----------------
// //!node_is_malicious && (rtrust == 0  || CURRENT_TIME - trust_recorded > 0)
// if(true){

// //due to the trust expired got deleted
// // if(CURRENT_TIME - trust_recorded > 0){
// //   trust_table.trust_delete(rp->rp_src);
// // }

  /*requester information already need to be saved in the sequence info table*/
if(rt1 != 0){
 double R_timestamp = rt1->rt_requesterTimestamp;
 u_int32_t  old_sequence = rt1->rt_seqno;
 double threshold_value = calculateThreshold(old_sequence, R_timestamp , rt->rt_updateRate);
 

 if(old_sequence !=0 || rt1->rt_requesterTimestamp != 0){
  /* pervious sequence is above 0 now compare reply with the threshold */
  if(rp->rp_dst_seqno < threshold_value){
    pass = true;
    
    
    fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,old_sequence,rt->rt_updateRate,R_timestamp,rp->rp_dst_seqno);
  }
//  else if(rp->rp_dst_seqno > threshold_value+ 100 ){
//   pass = false;

// classify(old_sequence, R_timestamp , rt->rt_updateRate,rp->rp_dst_seqno);

// fprintf(accuracy,"%d,droped,%f,threshold\n",rp->rp_src,rt1->rt_requesterTimestamp);  

// fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,old_sequence,rt->rt_updateRate,R_timestamp,rp->rp_dst_seqno);

//  }
 else if( rp->rp_dst_seqno >= threshold_value){
pass = false;

double classified = classify(old_sequence, R_timestamp , rt->rt_updateRate,rp->rp_dst_seqno);

//fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,old_sequence,rt->rt_updateRate,R_timestamp,rp->rp_dst_seqno);
/* 
send a testing request message 
creating entry for testing the reply message from test request
*/
 
 if(classified <= 0.7){

aodv_test_request *rtt;
     rtt = trtable.tr_lookup(sender_reciever_address2);

    //if previously undeleted file is their delete it   
     
      trtable.tr_delete(sender_reciever_address2);
      rtt = trtable.tr_add(sender_reciever_address2);  
          
      test_request_adder(rtt,ih->daddr(),rp->rp_dst_seqno,rp->rp_src,rp->rp_hop_count,rp->path_id); 
      /*
      how a reply receiving node don't have a route to the requester address????
      */
      aodv_rt_entry *rt_source2 = rtable.rt_lookup(ih->daddr());
      if(rt_source2 != 0){
        
        // timespec delay = {5,0}; 
        // timespec delayrem;
        // nanosleep(&delay, &delayrem);
      u_int32_t test_seq_number = rp->rp_dst_seqno - 2;
     int i = 0;

    sendRequest(rp->rp_dst,rp->rp_dst_seqno,false);
}

 }else{
  fprintf(passcomp,"%d,%d,%f,%f,%d,drop,1\n",rp->rp_src,rt1->rt_requesterTimestamp,rt1->rt_seqno,rt->rt_updateRate,rp->rp_dst_seqno);
  fprintf(accuracy,"%d,%f,drop\n",rp->rp_src,rt1->rt_requesterTimestamp);

  //trust_table.trust_change(rp->rp_src, -1);
  pass = false;
   }

     
      

 }

//  else{
// pass = true;
// fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,old_sequence,rt->rt_updateRate,R_timestamp,rp->rp_dst_seqno);

//  }

 
 }
 else if(old_sequence == 0 || rt1->rt_requesterTimestamp == 0){
   /*
  *  If I don't have a rt entry to this host... adding and if it is the first entry just pass it to be update
  */

 
        if(rt->rt_seqno == 0) {
           //rt = rtable.rt_add(rp->rp_dst);
           pass = false;
           //fprintf(passcomp,"%d,%d \n",rp->rp_src,2); 


aodv_test_request *rtt;
      rtt = trtable.tr_lookup(sender_reciever_address2);
      trtable.tr_delete(sender_reciever_address2);

      rtt = trtable.tr_add(sender_reciever_address2);
 
      test_request_adder(rtt,ih->daddr(),rp->rp_dst_seqno,rp->rp_src,rp->rp_hop_count,rp->path_id);
   
      aodv_rt_entry *rt_source2 = rtable.rt_lookup(ih->daddr());
      if(rt_source2 != 0){
  
   
      u_int32_t test_seq_number = rp->rp_dst_seqno - 2;
   
       
       sendRequest(rp->rp_dst,rp->rp_dst_seqno,false);
      }


        }
     else{
// enter this only if it is the sencond on the above reply message
//           /* the new reply has higher sequence than the stored one */
        if(rt->rt_seqno < rp->rp_dst_seqno){ 
          double  time_difference = rp->rp_timestamp - rt->rt_timestamp;
              
          // if the reply sequence is above the calculated threshold or not
          double th_value = calculateThreshold(rt->rt_seqno, time_difference , rt->rt_updateRate);
          
          
          
          if(rp->rp_dst_seqno < th_value ){
                pass = true;
                //fprintf(passcomp,"%d,%d \n",rp->rp_src,3);
                fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,rt->rt_seqno,rt->rt_updateRate,rp->rp_timestamp - rt->rt_timestamp ,rp->rp_dst_seqno);

          }
//           else if (rp->rp_dst_seqno > th_value+ 100 ){
//                 pass=false;


// fprintf(accuracy,"%d,droped,%f,first\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp);
// fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,rt->rt_seqno,rt->rt_updateRate,rp->rp_timestamp - rt->rt_timestamp ,rp->rp_dst_seqno);
// }
           else if(rp->rp_dst_seqno >= th_value){

                   pass = false;

  double classified = classify(old_sequence, R_timestamp , rt->rt_updateRate,rp->rp_dst_seqno);


if(classified <= 0.7){
 aodv_test_request *rtt;
      rtt = trtable.tr_lookup(sender_reciever_address2);
      trtable.tr_delete(sender_reciever_address2);

      rtt = trtable.tr_add(sender_reciever_address2);

      test_request_adder(rtt,ih->daddr(),rp->rp_dst_seqno,rp->rp_src,rp->rp_hop_count,rp->path_id);
   
      aodv_rt_entry *rt_source2 = rtable.rt_lookup(ih->daddr());
      if(rt_source2 != 0){
  
   
      u_int32_t test_seq_number = rp->rp_dst_seqno - 2;
   
       
       sendRequest(rp->rp_dst,rp->rp_dst_seqno,false);
      }
}
else{
  fprintf(passcomp,"%d,%d,%f,%f,%d,drop,1\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp,rt1->rt_seqno,rt->rt_updateRate,rp->rp_dst_seqno);
  fprintf(accuracy,"%d,%f,drop\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp);
  //trust_table.trust_change(rp->rp_src, -1);
  pass = false;
}
     
       
     } 

   

        
        } 

     }  

  }

//           /* how it going to update the table with less sequence number ?
//           the new reply has lower sequence than the stored one 
//           */
//              else if(rt->rt_seqno > rp->rp_dst_seqno){ 
         
//         double  time_difference =  rt->rt_timestamp - rp->rp_timestamp;

//           // if the reply sequence is above the calculated threshold or not
//           double th_value = calculateThreshold(old_sequence, R_timestamp , rt->rt_updateRate);

           
           
//           if(rt->rt_seqno < th_value){
//                   replace_malicious_node_rt = true;
//           }
// //           else{
// //             replace_malicious_node_rt = false; 
// //             pass = false;



// // fprintf(accuracy,"%d,droped\n",rp->rp_src);

          
            
// //             /*
// //             the change in the routing table should be applied for all nodes along the path
// //             so this comparision must done in all the nodes since the all might need to change
// //             their routing information
// //             */
// //           }

//         }

// }
// /* wheater the node hold requestor info or not*/
// }
// else{
//   /*node did not holde requestor info so drop reply*/
//   pass = false;


// // aodv_rt_entry *rt_source2 = rtable.rt_lookup(ih->daddr());

// //       if(rt_source2 != 0){
// // fprintf(accuracy,"%d,droped,%d\n",rp->rp_src,-5);
// // fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,old_sequence,R_timestamp,rt->rt_updateRate,rp->rp_dst_seqno)
// //       }


 
}



//  else if(rtrust != 0  && CURRENT_TIME - trust_recorded < 0){
// replace_malicious_node_rt = true;
//  }

// else{
// /* node is malicious*/
//    pass = false;
// }

// /*  is the reply for test request or normal request */

}

  
 else if(rp->rp_src == rp->rp_dst){
    pass = true;

//    if(rt1->rt_requesterTimestamp == 0){
// fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,rt->rt_seqno,rt->rt_updateRate,rp->rp_timestamp - rt->rt_timestamp ,rp->rp_dst_seqno);
//    }
//    else{
//     fprintf(regression,"%d,%d,%f,%f,%d\n",rp->rp_src,rt->rt_seqno,rt->rt_updateRate,rt1->rt_requesterTimestamp ,rp->rp_dst_seqno);
//    }

    
  }

//   /*
//   if the replied test has the same sequence as before the it should accept it but not drop it
//   */
 else if(rt_request != 0 ){


 
u_int32_t last_reply_sequence = test_request_sequence(rt_request);
if( rp->rp_src >= 25){

//last_reply_sequence != rp->rp_dst_seqno && rt_request->routeID == 0 && rp->path_id == 0
//trust_table.trust_change(rp->rp_src, -1);
 pass=false;
int hops = rp->rp_hop_count;
//fprintf(accuracy,"%d,droped,%d,test\n",rp->rp_src,hops);

//  if(rt1->rt_seqno != 0 && rt->rt_seqno != 0){
//     fprintf(passcomp,"%d,%d,%f,%f,%d,drop,0\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp,rt1->rt_seqno,rt->rt_updateRate,rp->rp_dst_seqno);
//    }
fprintf(passcomp,"%d,%d,%f,%f,%d,drop,0\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp,rt1->rt_seqno,rt->rt_updateRate,rp->rp_dst_seqno);

fprintf(accuracy,"%d,%f,drop\n",rp->rp_src,rt1->rt_requesterTimestamp);

}

else{



 pass=true;
   if(rt1->rt_seqno != 0 && rt->rt_seqno != 0){
    fprintf(passcomp,"%d,%d,%f,%f,%d,pass,0\n",rp->rp_src,rp->rp_timestamp - rt->rt_timestamp,rt1->rt_seqno,rt->rt_updateRate,rp->rp_dst_seqno);
   }

  }

// delete the recording about the testing request
trtable.tr_delete(sender_reciever_address2);
 }





       }
 
 

                      /**/


 if (  pass ) { // shorter or better route


//trust_table.trust_change(rp->rp_src, 1);

count = count +1;


    
	
 




      string r;
      stringstream R;

      R << index;
      R >> r;

      string s;
      stringstream S;

      S << rp->path_id;
      S >> s;

string paths;
      
paths = s + r;
    
      double pathID;
       std::istringstream(paths) >> pathID;
 
  rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
		rp->rp_src, CURRENT_TIME + rp->rp_lifetime,rp->replier_timestamp,0,pathID);


        
        fprintf(replier,"%d,%f\n",rp->rp_src,rt1->rt_requesterTimestamp); 



  if(rt1 != 0 && rp->rp_dst_seqno - rt1->rt_seqno > 0){
rt->rt_updateRateTempo = (rt1->rt_requesterTimestamp/(rp->rp_dst_seqno - rt1->rt_seqno));

double updateRate;

if(rt->rt_updateRate == 0){
  updateRate = rt->rt_updateRateTempo;

}else{
   updateRate = ((rt->rt_updateRate + rt->rt_updateRateTempo)/2);
}

  }  

  // reset the soft state
  rt->rt_req_cnt = 0;
  rt->rt_req_timeout = 0.0; 
  rt->rt_req_last_ttl = rp->rp_hop_count;
  
  if(rt_request != 0){
nsaddr_t to_whom = test_request_source(rt_request);
ih->daddr() = to_whom;
 }
//
if (ih->daddr() == index && rt_request == 0) { // If I am the original source
  // Update the route discovery latency statistics
  // rp->rp_timestamp is the time of request origination
		
    rt->rt_disc_latency[(unsigned char)rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
                                         / (double) rp->rp_hop_count;
    // increment indx for next time
    rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
  }	

  /*
   * Send all packets queued in the sendbuffer destined for
   * this destination. 
   * XXX - observe the "second" use of p.
   */
  Packet *buf_pkt;
  while((buf_pkt = rqueue.deque(rt->rt_dst))) {
    if(rt->rt_hops != INFINITY2) {
          assert (rt->rt_flags == RTF_UP);
    // Delay them a little to help ARP. Otherwise ARP 
    // may drop packets. -SRD 5/23/99
      forward(rt, buf_pkt, delay);
      delay += ARP_DELAY;
    }
  }
 }
 else {
  suppress_reply = 1;
 }

 /*
  * If reply is for me, discard it.
  */
//
if((ih->daddr() == index ) && rt_request == 0 || suppress_reply ) {

  //  if(rp->rp_hop_count == 1 && rp->rp_src != rp->rp_dst){
//fprintf(accuracy,"%d,droped,%d\n",rp->rp_src,-1);
  //  }
  //  else{
 
Packet::free(p);
  // }

   
 }
 /*
  * Otherwise, forward the Route Reply.
  */
 else {
 // Find the rt entry
 aodv_rt_entry *rt0;
if (rt_request != 0){
  nsaddr_t to_whom = test_request_source(rt_request);
 rt0 = rtable.rt_lookup(to_whom);
}
else{
rt0 = rtable.rt_lookup(ih->daddr());
}

//rt0 = rtable.rt_lookup(ih->daddr());

// if(rt_request !=0  && ih->daddr() != index ){
  
// }

// copy the sender of the reply to check at the source node

   // If the rt is up, forward
   if(rt0 && (rt0->rt_hops != INFINITY2)) {
        assert (rt0->rt_flags == RTF_UP);
     rp->rp_hop_count += 1;
     rp->rp_src = index;




      // nsaddr_t PATHID = pathID;
      // int c = rp->rp_hop_count;
      // std::cout<<rt->rt_path<<" "<<rp->rp_src<<" "<<index<<" "<<c<<"\n";
     
      
      

      

      
     
    

     forward(rt0, p, NO_DELAY);
     // Insert the nexthop towards the RREQ source to 
     // the precursor list of the RREQ destination
     rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
     
   }
   else {
   // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
     fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
     drop(p, DROP_RTR_NO_ROUTE);
   }
 }
}



void
AODV::recvError(Packet *p) {
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
aodv_rt_entry *rt;
u_int8_t i;
Packet *rerr = Packet::alloc();
struct hdr_aodv_error *nre = HDR_AODV_ERROR(rerr);

 nre->DestCount = 0;

 for (i=0; i<re->DestCount; i++) {
 // For each unreachable destination
   rt = rtable.rt_lookup(re->unreachable_dst[i]);
   if ( rt && (rt->rt_hops != INFINITY2) &&
	(rt->rt_nexthop == ih->saddr()) &&
     	(rt->rt_seqno <= re->unreachable_dst_seqno[i]) ) {
	assert(rt->rt_flags == RTF_UP);
	assert((rt->rt_seqno%2) == 0); // is the seqno even?
#ifdef DEBUG
     fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__,CURRENT_TIME,
		     index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
		     re->unreachable_dst[i],re->unreachable_dst_seqno[i],
	             ih->saddr());
#endif // DEBUG
     	rt->rt_seqno = re->unreachable_dst_seqno[i];
     	rt_down(rt);

   // Not sure whether this is the right thing to do
   Packet *pkt;
	while((pkt = ifqueue->filter(ih->saddr()))) {
        	drop(pkt, DROP_RTR_MAC_CALLBACK);
     	}

     // if precursor list non-empty add to RERR and delete the precursor list
     	if (!rt->pc_empty()) {
     		nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
     		nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
     		nre->DestCount += 1;
		rt->pc_delete();
     	}
   }
 } 

 if (nre->DestCount > 0) {
#ifdef DEBUG
   fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
   sendError(rerr);
 }
 else {
   Packet::free(rerr);
 }

 Packet::free(p);
}


/*
   Packet Transmission Routines
*/

void
AODV::forward(aodv_rt_entry *rt, Packet *p, double delay) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);

 if(ih->ttl_ == 0) {

#ifdef DEBUG
  fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG
 
  drop(p, DROP_RTR_TTL);
  return;
 }

 if ((( ch->ptype() != PT_AODV && ch->direction() == hdr_cmn::UP ) &&
	((u_int32_t)ih->daddr() == IP_BROADCAST))
		|| (ih->daddr() == here_.addr_)) {
	dmux_->recv(p,0);
	return;
 }

 if (rt) {
   assert(rt->rt_flags == RTF_UP);
   rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
   ch->next_hop_ = rt->rt_nexthop;
   ch->addr_type() = NS_AF_INET;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }
 else { // if it is a broadcast packet
   // assert(ch->ptype() == PT_AODV); // maybe a diff pkt type like gaf
   assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
   ch->addr_type() = NS_AF_NONE;
   ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction
 }

if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
 // If it is a broadcast packet
   assert(rt == 0);
   if (ch->ptype() == PT_AODV) {
     /*
      *  Jitter the sending of AODV broadcast packets by 10ms
      */
     Scheduler::instance().schedule(target_, p,
      				   0.01 * Random::uniform());
   } else {
     Scheduler::instance().schedule(target_, p, 0.);  // No jitter
   }
 }
 else { // Not a broadcast packet 
   if(delay > 0.0) {
     Scheduler::instance().schedule(target_, p, delay);
   }
   else {
   // Not a broadcast packet, no delay, send immediately
     Scheduler::instance().schedule(target_, p, 0.);
   }
 }

}


void
AODV::sendRequest(nsaddr_t dst,u_int32_t seq_number,bool correct) {

  
  
// Allocate a RREQ packet 
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_request *rq = HDR_AODV_REQUEST(p);
aodv_rt_entry *rt = rtable.rt_lookup(dst);

 assert(rt);

 /*
  *  Rate limit sending of Route Requests. We are very conservative
  *  about sending out route requests. 
  */

 if (rt->rt_flags == RTF_UP) {
   assert(rt->rt_hops != INFINITY2);
   Packet::free((Packet *)p);
   return;
 }

 if (rt->rt_req_timeout > CURRENT_TIME) {
   Packet::free((Packet *)p);
   return;
 }

 // rt_req_cnt is the no. of times we did network-wide broadcast
 // RREQ_RETRIES is the maximum number we will allow before 
 // going to a long timeout.

 if (rt->rt_req_cnt > RREQ_RETRIES) {
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
   rt->rt_req_cnt = 0;
 Packet *buf_pkt;
   while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
       drop(buf_pkt, DROP_RTR_NO_ROUTE);
   }
   Packet::free((Packet *)p);
   return;
 }

#ifdef DEBUG
   fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
                    ++route_request, index, rt->rt_dst);
#endif // DEBUG

 // Determine the TTL to be used this time. 
 // Dynamic TTL evaluation - SRD

 rt->rt_req_last_ttl = max(rt->rt_req_last_ttl,rt->rt_last_hop_count);


if(seq_number != 10000000){
rt->rt_req_last_ttl == 0;
}



 if (0 == rt->rt_req_last_ttl) {
 // first time query broadcast
   ih->ttl_ = TTL_START;
if(seq_number != 10000000){
   ih->ttl_ = 1;
}

 }
 else {
 // Expanding ring search.
   if (rt->rt_req_last_ttl < TTL_THRESHOLD)
     if(seq_number == 10000000){
ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
     }else{
      ih->ttl_ = 1;
     }
     
   else {
   // network-wide broadcast
   if(seq_number == 10000000){
     ih->ttl_ = NETWORK_DIAMETER;}
     else{
      ih->ttl_ = 1;
     }
     rt->rt_req_cnt += 1;
   }
 }

 //remember the TTL used  for the next time
 if(seq_number == 10000000){
rt->rt_req_last_ttl = ih->ttl_;
 }
 else{
  ih->ttl_ = 1;
  rt->rt_req_last_ttl = ih->ttl_; 
 }




 // PerHopTime is the roundtrip time per hop for route requests.
 // The factor 2.0 is just to be safe .. SRD 5/22/99
 // Also note that we are making timeouts to be larger if we have 
 // done network wide broadcast before. 

 rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt); 
 if (rt->rt_req_cnt > 0)
   rt->rt_req_timeout *= rt->rt_req_cnt;
 rt->rt_req_timeout += CURRENT_TIME;

 // Don't let the timeout to be too large, however .. SRD 6/8/99
 if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
   rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
 rt->rt_expire = 0;

#ifdef DEBUG
 fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
	         ++route_request, 
		 index, rt->rt_dst, 
		 rt->rt_req_timeout - CURRENT_TIME);
#endif	// DEBUG
	

 // Fill out the RREQ packet 
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rq->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;

 // Fill up some more fields. 
 rq->rq_type = AODVTYPE_RREQ;
 rq->rq_hop_count = 1;
 rq->rq_bcast_id = bid++;
 rq->rq_dst = dst;
 if(seq_number == 10000000){
rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
 }
 else{
  rq->rq_dst_seqno = seq_number;
 }
 
 rq->rq_src = index;
 seqno += 2;
 assert ((seqno%2) == 0);
 rq->rq_src_seqno = seqno;
 rq->rq_timestamp = CURRENT_TIME;
 rq->rq_requesterTimestamp = (rq->rq_dst_seqno != 0 && rt && rt->rt_timestamp != 0 ? CURRENT_TIME - rt->rt_timestamp :  0);
 rq->correct = correct;


//only needed when an actual sender sends request message
   string s_r;
      stringstream SR;

      SR << (int) rq->rq_src;
      SR >> s_r;

      string r_s;
      stringstream RS;

      RS << (int) rq->rq_dst;
      RS >> r_s;

      string sender_reciever = s_r +"00"+ r_s;
      int identification;
       std::istringstream(sender_reciever) >> identification;
      nsaddr_t sender_reciever_address = identification;

aodv_rt_entry *rtI;
     rtI = rtable.rt_lookup(sender_reciever_address);
   if(rtI == 0) { /* if not in the route table */
   // create an entry for the reverse route.
     rtI = rtable.rt_add(sender_reciever_address);
   } 

if(seq_number == 10000000){
sequenceInfoTable(rtI,rq->rq_requesterTimestamp,rq->rq_dst_seqno);
}
  

 

 Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
                u_int32_t rpseq, u_int32_t lifetime, double timestamp,nsaddr_t rep) {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
aodv_rt_entry *rt = rtable.rt_lookup(ipdst);


#ifdef DEBUG
fprintf(stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
 assert(rt);

aodv_rt_entry *rt_destination = rtable.rt_lookup(rpdst);;

double recordedTime = 0;
if(rt_destination != 0){
recordedTime = CURRENT_TIME - rt_destination->rt_timestamp;
}

 rp->rp_type = AODVTYPE_RREP;
 //rp->rp_flags = 0x00;
 rp->rp_hop_count = hop_count;
 rp->rp_dst = rpdst;
 rp->rp_dst_seqno = rpseq;
 rp->rp_src = index;
 rp->rp_lifetime = lifetime;
 rp->rp_timestamp = timestamp;
 rp->replier_timestamp = (rpdst == index ? 0 : recordedTime);
 rp->replierID = rep;

rp->path_id = (rpdst != index  ? (rt_destination != 0 ? rt_destination->rt_path : 0) : index);
 
   
 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rp->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_INET;
 ch->next_hop_ = rt->rt_nexthop;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;

 ih->saddr() = index;
 ih->daddr() = ipdst;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = NETWORK_DIAMETER;



 Scheduler::instance().schedule(target_, p, 0.);

}

void
AODV::sendError(Packet *p, bool jitter) {
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_error *re = HDR_AODV_ERROR(p);
    
#ifdef ERROR
fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 re->re_type = AODVTYPE_RERR;
 //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
 // DestCount and list of unreachable destinations are already filled

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + re->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->next_hop_ = 0;
 ch->prev_hop_ = index;          // AODV hack
 ch->direction() = hdr_cmn::DOWN;       //important: change the packet's direction

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 // Do we need any jitter? Yes
 if (jitter)
 	Scheduler::instance().schedule(target_, p, 0.01*Random::uniform());
 else
 	Scheduler::instance().schedule(target_, p, 0.0);

}


/*
   Neighbor Management Functions
*/

void
AODV::sendHello() {
Packet *p = Packet::alloc();
struct hdr_cmn *ch = HDR_CMN(p);
struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rh = HDR_AODV_REPLY(p);

#ifdef DEBUG
fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

 rh->rp_type = AODVTYPE_HELLO;
 //rh->rp_flags = 0x00;
 rh->rp_hop_count = 1;
 rh->rp_dst = index;
 rh->rp_dst_seqno = seqno;
 rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;

 // ch->uid() = 0;
 ch->ptype() = PT_AODV;
 ch->size() = IP_HDR_LEN + rh->size();
 ch->iface() = -2;
 ch->error() = 0;
 ch->addr_type() = NS_AF_NONE;
 ch->prev_hop_ = index;          // AODV hack

 ih->saddr() = index;
 ih->daddr() = IP_BROADCAST;
 ih->sport() = RT_PORT;
 ih->dport() = RT_PORT;
 ih->ttl_ = 1;

 Scheduler::instance().schedule(target_, p, 0.0);
}


void
AODV::recvHello(Packet *p) {
//struct hdr_ip *ih = HDR_IP(p);
struct hdr_aodv_reply *rp = HDR_AODV_REPLY(p);
AODV_Neighbor *nb;

 nb = nb_lookup(rp->rp_dst);
 if(nb == 0) {
   nb_insert(rp->rp_dst);
 }
 else {
   nb->nb_expire = CURRENT_TIME +
                   (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 }

 Packet::free(p);
}

void
AODV::nb_insert(nsaddr_t id) {
AODV_Neighbor *nb = new AODV_Neighbor(id);

 assert(nb);
 nb->nb_expire = CURRENT_TIME +
                (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
 LIST_INSERT_HEAD(&nbhead, nb, nb_link);
 seqno += 2;             // set of neighbors changed
 assert ((seqno%2) == 0);
}


AODV_Neighbor*
AODV::nb_lookup(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) break;
 }
 return nb;
}


/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
AODV::nb_delete(nsaddr_t id) {
AODV_Neighbor *nb = nbhead.lh_first;

 log_link_del(id);
 seqno += 2;     // Set of neighbors changed
 assert ((seqno%2) == 0);

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id) {
     LIST_REMOVE(nb,nb_link);
     delete nb;
     break;
   }
 }

 handle_link_failure(id);

}


/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
AODV::nb_purge() {
AODV_Neighbor *nb = nbhead.lh_first;
AODV_Neighbor *nbn;
double now = CURRENT_TIME;

 for(; nb; nb = nbn) {
   nbn = nb->nb_link.le_next;
   if(nb->nb_expire <= now) {
     nb_delete(nb->nb_addr);
   }
 }

}
