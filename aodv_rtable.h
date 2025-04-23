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

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems.
*/


#ifndef __aodv_rtable_h__
#define __aodv_rtable_h__

#include <assert.h>
#include <sys/types.h>
#include <config.h>
#include <lib/bsd-list.h>
#include <scheduler.h>
#include <iostream>
#include <map>
#include <list>

#define CURRENT_TIME    Scheduler::instance().clock()
#define INFINITY2        0xff



/*
   AODV malicious Neighbor Cache Entry edited by atnatiyos
*/

class aodv_malicious_nodes{
    friend class AODV;
    friend class aodv_mtable;
 public:
    aodv_malicious_nodes();
    
 protected:
    LIST_ENTRY(aodv_malicious_nodes) m_link;
    nsaddr_t        m_dst;

    

    map<nsaddr_t,double> coincidence;
    list<map<int,double> > coincidences;

    list<map<int,double> >::iterator list_it;
    map<int,double>::iterator map_it;
};


/*
   AODV test request Cache Entry edited by atnatiyos
*/

class aodv_test_request{
    friend class AODV;
    friend class aodv_trtable;
 public:
    aodv_test_request();
    
 protected:
    LIST_ENTRY(aodv_test_request) tr_link;
    nsaddr_t        tr_dst;

    nsaddr_t    requesterID;
    u_int32_t   replied_seq_num;
    nsaddr_t   rp_sender;
    u_int32_t    hop_count;
    u_int32_t    routeID;



    

//     map<nsaddr_t,u_int32_t> coincidence;
//     list<map<nsaddr_t,u_int32_t> > coincidences;

//     list<map<nsaddr_t,u_int32_t> >::iterator list_it;
//     map<nsaddr_t,u_int32_t>::iterator map_it;
};



/*
   AODV Neighbor Cache Entry
*/
class AODV_Neighbor {
        friend class AODV;
        friend class aodv_rt_entry;
 public:
        AODV_Neighbor(u_int32_t a) { nb_addr = a; }

 protected:
        LIST_ENTRY(AODV_Neighbor) nb_link;
        nsaddr_t        nb_addr;
        double          nb_expire;      // ALLOWED_HELLO_LOSS * HELLO_INTERVAL
};

LIST_HEAD(aodv_ncache, AODV_Neighbor);

/*
   AODV Precursor list data structure
*/
class AODV_Precursor {
        friend class AODV;
        friend class aodv_rt_entry;
 public:
        AODV_Precursor(u_int32_t a) { pc_addr = a; }

 protected:
        LIST_ENTRY(AODV_Precursor) pc_link;
        nsaddr_t        pc_addr;	// precursor address
};

LIST_HEAD(aodv_precursors, AODV_Precursor);



/*
  Trust Table Entry
*/

class aodv_trust_entry {
        friend class aodv_trust_table;
        friend class AODV;
	
 public:
        aodv_trust_entry();
        ~aodv_trust_entry();

 protected:
 LIST_ENTRY(aodv_trust_entry) trust_link;
          
         nsaddr_t node_id;
         int trust_level;


};

/*
  Route Table Entry
*/

class aodv_rt_entry {
        friend class aodv_rtable;
        friend class AODV;
	friend class LocalRepairTimer;
 public:
        aodv_rt_entry();
        ~aodv_rt_entry();

        void            nb_insert(nsaddr_t id);
        AODV_Neighbor*  nb_lookup(nsaddr_t id);

        void            pc_insert(nsaddr_t id);
        AODV_Precursor* pc_lookup(nsaddr_t id);
        void 		pc_delete(nsaddr_t id);
        void 		pc_delete(void);
        bool 		pc_empty(void);

        double          rt_req_timeout;         // when I can send another req
        u_int8_t        rt_req_cnt;             // number of route requests
	double          rt_timestamp, rt_requesterTimestamp;// editor atnatiyos added timestamp for data generation and requesterTimestamp for calculating the threshold
        u_int32_t       rt_path; //it show the exact path the reply comes used in test request       
        


 protected:
        LIST_ENTRY(aodv_rt_entry) rt_link;

        nsaddr_t        rt_dst;
        u_int32_t       rt_seqno;
	/* u_int8_t 	rt_interface; */
        u_int16_t       rt_hops;       		// hop count
	int 		rt_last_hop_count;	// last valid hop count
        nsaddr_t        rt_nexthop;    		// next hop IP address
	/* list of precursors */ 
        aodv_precursors rt_pclist;
        double          rt_expire;     		// when entry expires
        u_int8_t        rt_flags;

        double          rt_lastUpdate;
        double          rt_updateRate;
        double          rt_updateRateTempo;
        int             rt_broadcast;




#define RTF_DOWN 0
#define RTF_UP 1
#define RTF_IN_REPAIR 2

        /*
         *  Must receive 4 errors within 3 seconds in order to mark
         *  the route down.
        u_int8_t        rt_errors;      // error count
        double          rt_error_time;
#define MAX_RT_ERROR            4       // errors
#define MAX_RT_ERROR_TIME       3       // seconds
         */

#define MAX_HISTORY	3
	double 		rt_disc_latency[MAX_HISTORY];
	char 		hist_indx;
        int 		rt_req_last_ttl;        // last ttl value used
	// last few route discovery latencies
	// double 		rt_length [MAX_HISTORY];
	// last few route lengths

        /*
         * a list of neighbors that are using this route.
         */
        aodv_ncache          rt_nblist;
};


/*
  The Routing Table
*/

class aodv_rtable {
 public:
	aodv_rtable() { LIST_INIT(&rthead); }

        aodv_rt_entry*       head() { return rthead.lh_first; }

        aodv_rt_entry*       rt_add(nsaddr_t id);
        void                 rt_delete(nsaddr_t id);
        aodv_rt_entry*       rt_lookup(nsaddr_t id);

 private:
        LIST_HEAD(aodv_rthead, aodv_rt_entry) rthead;
};


//       edited by atnatiyos for malicious node list

class aodv_mtable {
 public:
	aodv_mtable() { LIST_INIT(&mthead); }

        aodv_malicious_nodes*       head() { return mthead.lh_first; }

        aodv_malicious_nodes*       m_add(nsaddr_t id);
        void                 m_delete(nsaddr_t id);
        aodv_malicious_nodes*       m_lookup(nsaddr_t id);

 private:
        LIST_HEAD(aodv_mthead, aodv_malicious_nodes) mthead;
};


//       edited by atnatiyos for test request message

class aodv_trtable {
 public:
	aodv_trtable() { LIST_INIT(&trthead); }

        aodv_test_request*       head() { return trthead.lh_first; }

        aodv_test_request*       tr_add(nsaddr_t id);
        void                 tr_delete(nsaddr_t id);
        aodv_test_request*       tr_lookup(nsaddr_t id);

 private:
        LIST_HEAD(aodv_trthead, aodv_test_request) trthead;
};

class aodv_trust_table {
 public:
	aodv_trust_table() { LIST_INIT(&trust_thead); }

        aodv_trust_entry*       head() { return trust_thead.lh_first; }

        aodv_trust_entry*       trust_add(nsaddr_t id,int trust_lvl);
        void                 trust_delete(nsaddr_t id);
        aodv_trust_entry*       trust_lookup(nsaddr_t id);
        void                  trust_change(nsaddr_t id,int ch_add_sub);
        int                   trust_value(nsaddr_t id);

 private:
        LIST_HEAD(aodv_trust_thead, aodv_trust_entry) trust_thead;
};


#endif /* _aodv__rtable_h__ */
