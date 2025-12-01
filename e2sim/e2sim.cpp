/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>

#include "e2sim.hpp"
#include "e2sim_defs.h"
#include "e2sim_sctp.hpp"
#include "e2ap_message_handler.hpp"
#include "encode_e2apv2.hpp"
#include "n3iwf_data.hpp"
#include "n3iwf_utils.hpp"
#include <mutex>

std::mutex g_sctp_send_mutex;


using namespace std;

int client_fd = -1;

static inline void set_octet_string(OCTET_STRING_t* dst, const void* src, size_t len) {
  if (!dst) return;
  dst->buf  = (uint8_t*)calloc(1, len);
  dst->size = len;
  if (len && src) memcpy(dst->buf, src, len);
}

void E2Sim::register_subscription_callback(long func_id, SubscriptionCallback cb) {
  printf("%%%%about to register callback for subscription for func_id %ld\n", func_id);
  subscription_callbacks[func_id] = cb;
  
}

SubscriptionCallback E2Sim::get_subscription_callback(long func_id) {
  printf("%%%%we are getting the subscription callback for func id %ld\n", func_id);
  SubscriptionCallback cb = subscription_callbacks[func_id];
  return cb;

}

void E2Sim::register_control_callback(long func_id, ControlCallback cb) {
  printf("%%%%about to register callback for control for func_id %ld\n", func_id);
  control_callbacks[func_id] = cb;
}

ControlCallback E2Sim::get_control_callback(long func_id) {
  printf("%%%%we are getting the control callback for func id %ld\n", func_id);
  auto it = control_callbacks.find(func_id);
  if (it == control_callbacks.end()) {
    return nullptr;
  }
  return it->second;
}

void E2Sim::register_e2sm_oid(long func_id, PrintableString_t* oid) {
  //Error conditions:
  //If we already have an entry for func_id
  
  printf("%%%%about to register e2sm func oid for %ld\n", func_id);

  ran_function_oids[func_id] = oid;

}

PrintableString_t* E2Sim::get_e2sm_oid(long func_id) {
  return ran_function_oids[func_id];
}

void E2Sim::register_e2sm(long func_id, PrintableString_t *ostr) {

  //Error conditions:
  //If we already have an entry for func_id
  
  printf("%%%%about to register e2sm func desc for %ld\n", func_id);

  ran_functions_registered[func_id] = ostr;

}

std::unordered_map<long, OCTET_STRING_t *> E2Sim::get_registered_e2sm() {
  return ran_functions_registered;
}


void E2Sim::encode_and_send_sctp_data(E2AP_PDU_t* pdu)
{
  std::lock_guard<std::mutex> lock(g_sctp_send_mutex);
  sctp_buffer_t data;

  auto buffer_size = MAX_SCTP_BUFFER;
  unsigned char buffer[MAX_SCTP_BUFFER];

  auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu, buffer, buffer_size);
  if(er.encoded < 0) {
    logln("E2AP PDU encoding failed: %s\n", er.failed_type->name);
    return;
  }

  data.len = er.encoded;

  memcpy(data.buffer, buffer, er.encoded); 

  sctp_send_data(client_fd, data);
}



int E2Sim::run_loop(int argc, char* argv[]){

  logln("Start E2 Agent (E2 Simulator)");
  GlobalgNB_ID_t *gnb = getGNBStore();
  if (gnb == NULL) {
    logln( "GNB Store is NULL\n");
    return -1;
  }
  
  options_t ops = read_input_options(argc, argv);

  E2AP_PDU_t* pdu_setup = (E2AP_PDU_t*)calloc(1,sizeof(E2AP_PDU));
  
  std::vector<ran_func_info> all_funcs;

  //Loop through RAN function definitions that are registered

    //Loop through RAN function definitions that are registered
    for (std::pair<long, OCTET_STRING_t*> elem : ran_functions_registered) {    
      ran_func_info next_func;
      next_func.ranFunctionId = elem.first;
      next_func.ranFunctionDesc = elem.second;
      next_func.ranFunctionRev = (long)1;
      next_func.ranFunctionOId = get_e2sm_oid(elem.first);
      all_funcs.push_back(next_func);
    }
 
  //Generate E2AP PDU for E2 Setup Request
  logln("About to generate E2AP PDU for E2 Setup Request\n");
  logln("Number of RAN Functions: %zu\n", all_funcs.size());
  generate_e2apv2_setup_request_parameterized(pdu_setup, all_funcs, ops.gNB_CU_UP_ID, ops.gNB_DU_ID);

  logln("After generating e2setup req ----------------------------------------------------------\n");
  xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu_setup);
  logln("After XER (XML Encoding Rules) Encoding ------------------------------------------------\n");

  auto buffer_size = MAX_SCTP_BUFFER;
  unsigned char buffer[MAX_SCTP_BUFFER];
  
  sctp_buffer_t data;

  char *error_buf = (char*)calloc(300, sizeof(char));
  size_t errlen;

  int checkConstraintE2AP_PDU=asn_check_constraints(&asn_DEF_E2AP_PDU, pdu_setup, error_buf, &errlen);
  
  if (checkConstraintE2AP_PDU != 0) {
    logln("E2AP PDU constraints check failed: %s\n", error_buf);
    logln("error length %ld\n", errlen);
    logln("error buf %s\n", error_buf);
    return -1;
  }

  logln("ASN ENCODE TO BUFFER IN ATS_ALIGNED_BASIC_PER\n");
  auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu_setup, buffer, buffer_size);
  if(er.encoded < 0) {
    logln("E2AP PDU encoding failed: %s\n", er.failed_type->name);
    return -1;
  }

  data.len = er.encoded;

  logln("ASN_ENCODE_TO_BUFFER encoded is %ld length\n",er.encoded);

  memcpy(data.buffer, buffer, er.encoded); 
  client_fd = sctp_start_client(ops.server_ip, ops.server_port, ops.local_ip);

  if(client_fd == -1) {
    logln("[SCTP] Unable to start SCTP client\n");
    return -1;
  }
  logln("client_fd SCTP START CLIENT value is %d\n", client_fd);


  if(sctp_send_data(client_fd, data) > 0) {
    logln("[SCTP] Sent E2-SETUP-REQUEST\n");

  } else {
    logln("[SCTP] Unable to send E2-SETUP-REQUEST to peer\n");
  }

  sctp_buffer_t recv_buf;

  logln("[SCTP] Waiting for SCTP data");

  while(1) //constantly looking for data on SCTP interface
  {
    int r = sctp_receive_data(client_fd, recv_buf);
    if (r == SCTP_RECV_E2AP) {
        logln("[SCTP] Received E2AP len=%d", recv_buf.len);
        e2ap_handle_sctp_data(client_fd, recv_buf, this);
        // continua a leggere: potrebbero arrivare altri messaggi
    } else if (r == SCTP_RECV_SKIP) {
        // è solo una notifica o payload non E2AP → continua ad aspettare
        logln("[SCTP] Received SCTP_RECV_SKIP");
        continue;
    } else { // SCTP_RECV_ERR
        logln("[SCTP] Received SCTP_RECV_ERR");
        // errore o connessione chiusa
        break;
    }
  }

  return 0;
}
