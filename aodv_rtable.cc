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


#include <aodv/aodv_rtable.h>
//#include <cmu/aodv/aodv.h>


/*
 aodv trust managment
*/

aodv_trust_entry::aodv_trust_entry(){
  trust_level = 5;
}
aodv_trust_entry::~aodv_trust_entry(){}


aodv_trust_entry*
aodv_trust_table::trust_lookup(nsaddr_t id)
{
aodv_trust_entry *rt = trust_thead.lh_first;

 for(; rt; rt = rt->trust_link.le_next) {
   if(rt->node_id == id)
     break;
 }
 return rt;

}

void
aodv_trust_table::trust_delete(nsaddr_t id)
{
aodv_trust_entry *rt = trust_lookup(id);

 if(rt) {
   LIST_REMOVE(rt, trust_link);
   delete rt;
 }

}

aodv_trust_entry*
aodv_trust_table::trust_add(nsaddr_t id,int trust_lvl)
{
aodv_trust_entry *rt;

 assert(trust_lookup(id) == 0);
 rt = new aodv_trust_entry;
 assert(rt);
 rt->node_id = id;
 rt->trust_level = trust_lvl;
 LIST_INSERT_HEAD(&trust_thead, rt, trust_link);
 return rt;
}

void
aodv_trust_table::trust_change(nsaddr_t id, int ch_add_sub){
aodv_trust_entry *rt;
for(; rt; rt = rt->trust_link.le_next) {
   if(rt->node_id == id)
   {
     rt->trust_level = rt->trust_level + ch_add_sub;
     std::cout<<"update "<<id<<" "<<rt->trust_level<<"\n";
   }
     
 }


}

int
aodv_trust_table::trust_value(nsaddr_t id){
aodv_trust_entry *rt;
for(; rt; rt = rt->trust_link.le_next) {
   if(rt->node_id == id)
     return rt->trust_level;
 }
 return 5;
}




/*
  The Routing Table
*/

aodv_rt_entry::aodv_rt_entry()
{
int i;

 rt_req_timeout = 0.0;
 rt_req_cnt = 0;

 rt_dst = 0;
 rt_seqno = 0;
 rt_hops = rt_last_hop_count = INFINITY2;
 rt_nexthop = 0;
 LIST_INIT(&rt_pclist);
 rt_expire = 0.0;
 rt_flags = RTF_DOWN;

 /*
 rt_errors = 0;
 rt_error_time = 0.0;
 */
double rt_timestamp = 0.0;
double rt_requesterTimestamp = 0.0;
double rt_requestTime = 0.0;

rt_timestamp = 0;
rt_requesterTimestamp = 0;
rt_lastUpdate = 0;
rt_updateRateTempo = 0;
rt_broadcast = 0;
rt_path = NULL;




 for (i=0; i < MAX_HISTORY; i++) {
   rt_disc_latency[i] = 0.0;
 }
 hist_indx = 0;
 rt_req_last_ttl = 0;

 LIST_INIT(&rt_nblist);

}


aodv_rt_entry::~aodv_rt_entry()
{
AODV_Neighbor *nb;

 while((nb = rt_nblist.lh_first)) {
   LIST_REMOVE(nb, nb_link);
   delete nb;
 }

AODV_Precursor *pc;

 while((pc = rt_pclist.lh_first)) {
   LIST_REMOVE(pc, pc_link);
   delete pc;
 }

}


void
aodv_rt_entry::nb_insert(nsaddr_t id)
{
AODV_Neighbor *nb = new AODV_Neighbor(id);
        
 assert(nb);
 nb->nb_expire = 0;
 LIST_INSERT_HEAD(&rt_nblist, nb, nb_link);

}


AODV_Neighbor*
aodv_rt_entry::nb_lookup(nsaddr_t id)
{
AODV_Neighbor *nb = rt_nblist.lh_first;

 for(; nb; nb = nb->nb_link.le_next) {
   if(nb->nb_addr == id)
     break;
 }
 return nb;

}


void
aodv_rt_entry::pc_insert(nsaddr_t id)
{
	if (pc_lookup(id) == NULL) {
	AODV_Precursor *pc = new AODV_Precursor(id);
        
 		assert(pc);
 		LIST_INSERT_HEAD(&rt_pclist, pc, pc_link);
	}
}


AODV_Precursor*
aodv_rt_entry::pc_lookup(nsaddr_t id)
{
AODV_Precursor *pc = rt_pclist.lh_first;

 for(; pc; pc = pc->pc_link.le_next) {
   if(pc->pc_addr == id)
   	return pc;
 }
 return NULL;

}

void
aodv_rt_entry::pc_delete(nsaddr_t id) {
AODV_Precursor *pc = rt_pclist.lh_first;

 for(; pc; pc = pc->pc_link.le_next) {
   if(pc->pc_addr == id) {
     LIST_REMOVE(pc,pc_link);
     delete pc;
     break;
   }
 }

}

void
aodv_rt_entry::pc_delete(void) {
AODV_Precursor *pc;

 while((pc = rt_pclist.lh_first)) {
   LIST_REMOVE(pc, pc_link);
   delete pc;
 }
}	

bool
aodv_rt_entry::pc_empty(void) {
AODV_Precursor *pc;

 if ((pc = rt_pclist.lh_first)) return false;
 else return true;
}	

/*
  The Routing Table
*/

aodv_rt_entry*
aodv_rtable::rt_lookup(nsaddr_t id)
{
aodv_rt_entry *rt = rthead.lh_first;

 for(; rt; rt = rt->rt_link.le_next) {
   if(rt->rt_dst == id)
     break;
 }
 return rt;

}

void
aodv_rtable::rt_delete(nsaddr_t id)
{
aodv_rt_entry *rt = rt_lookup(id);

 if(rt) {
   LIST_REMOVE(rt, rt_link);
   delete rt;
 }

}

aodv_rt_entry*
aodv_rtable::rt_add(nsaddr_t id)
{
aodv_rt_entry *rt;

 assert(rt_lookup(id) == 0);
 rt = new aodv_rt_entry;
 assert(rt);
 rt->rt_dst = id;
 LIST_INSERT_HEAD(&rthead, rt, rt_link);
 return rt;
}


///// edited by atnatiyos //////////////
// function for adding the malicious node}

aodv_malicious_nodes::aodv_malicious_nodes(){
  
}

aodv_malicious_nodes*
aodv_mtable::m_add(nsaddr_t id)
{
aodv_malicious_nodes *rt;

 assert(m_lookup(id) == 0);
 rt = new aodv_malicious_nodes;
 assert(rt);
 rt->m_dst = id;

 LIST_INSERT_HEAD(&mthead, rt, m_link);
 return rt;
}

aodv_malicious_nodes*
aodv_mtable::m_lookup(nsaddr_t id)
{
aodv_malicious_nodes *rt = mthead.lh_first;

 for(; rt; rt = rt->m_link.le_next) {
   if(rt->m_dst == id)
     break;
 }
 return rt;

}



//// edited by atnatiyos //////////////
// function for sending test request messages

aodv_test_request::aodv_test_request(){
  
}

aodv_test_request*
aodv_trtable::tr_add(nsaddr_t id)
{
aodv_test_request *rt;

 assert(tr_lookup(id) == 0);
 rt = new aodv_test_request;
 assert(rt);
 rt->tr_dst = id;

 LIST_INSERT_HEAD(&trthead, rt, tr_link);
 return rt;
}

aodv_test_request*
aodv_trtable::tr_lookup(nsaddr_t id)
{
aodv_test_request *rt = trthead.lh_first;

 for(; rt; rt = rt->tr_link.le_next) {
   if(rt->tr_dst == id)
     break;
 }
 return rt;

}

void
aodv_trtable::tr_delete(nsaddr_t id)
{
aodv_test_request *rt = tr_lookup(id);

// if(rt == 0){
// std::cout<<"not found\n";
// }
// else{
//   std::cout<<"found\n";
// }

 if(rt) {
   LIST_REMOVE(rt, tr_link);
   delete rt;
 }

}