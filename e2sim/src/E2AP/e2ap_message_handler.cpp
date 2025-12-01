

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
#include "e2ap_message_handler.hpp"

// #include <iostream>
// #include <vector>

#include "encode_e2apv2.hpp"
#include "kpm_callbacks.hpp"
#include "n3iwf_utils.hpp"

extern "C" {
#include "RICsubscriptionDeleteRequest.h"
}

#include <unistd.h>

void e2ap_handle_sctp_data(int &socket_fd, sctp_buffer_t &data, E2Sim *e2sim)
{
  // decode the data into E2AP-PDU
  E2AP_PDU_t *pdu = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU));

  logln("[E2AP HANDLE SCTP DATA] decoding...");

  logln("[E2AP HANDLE SCTP DATA] full buffer\n%s\n", data.buffer);
  auto rval = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, (void **)&pdu, data.buffer, data.len);

  switch (rval.code)
  {
  case RC_OK:
    logln("[E2AP HANDLE SCTP DATA] Decoding successful (APER)\n");
    break;
  case RC_WMORE:
    break;
  case RC_FAIL:
    logln("[E2AP HANDLE SCTP DATA] Decoding failed (APER)\n");
    return;
    break;
  default:
    break;
  }

  int index = (int)pdu->present;
  logln("length of decoded data %ld with result %d and index is %d\n", rval.consumed, rval.code, index);

  int procedureCode = e2ap_asn1c_get_procedureCode(pdu);
  index = (int)pdu->present;

  logln("[E2AP] Unpacked E2AP-PDU: index = %d, procedureCode = %d\n", index, procedureCode);

  switch (procedureCode)
  {

  case ProcedureCode_id_E2setup:
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage:
      logln("[E2AP] Received SETUP-REQUEST");
      break;

    case E2AP_PDU_PR_successfulOutcome:
      logln("[E2AP] Received SETUP-RESPONSE-SUCCESS");
      // ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu_update); // se non riusi
      break;

    case E2AP_PDU_PR_unsuccessfulOutcome:
      logln("[E2AP] Received SETUP-RESPONSE-FAILURE");
      break;

    default:
      logln("[E2AP] Invalid message index=%d in E2AP-PDU", index);
      break;
    }
    break;

  case ProcedureCode_id_Reset: // reset = 7
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage:
      logln("[E2AP] Received RESET-REQUEST");
      break;

    case E2AP_PDU_PR_successfulOutcome:
      break;

    case E2AP_PDU_PR_unsuccessfulOutcome:
      break;

    default:
      logln("[E2AP] Invalid message index=%d in E2AP-PDU", index);
      break;
    }
    break;

  case ProcedureCode_id_RICsubscription: // RIC SUBSCRIPTION = 8
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage:
    { // initiatingMessage
      LOG_I("[E2AP] Received RIC-SUBSCRIPTION-REQUEST");
      //          e2ap_handle_RICSubscriptionRequest(pdu, socket_fd);
      long func_id = get_function_id_from_subscription(pdu);
      SubscriptionCallback cb = e2sim->get_subscription_callback(func_id);
      cb(pdu);
      //	  callback_kpm_subscription_request(pdu, socket_fd);
    }
    break;

    case E2AP_PDU_PR_successfulOutcome:
      logln("[E2AP] Received RIC-SUBSCRIPTION-RESPONSE");
      break;

    case E2AP_PDU_PR_unsuccessfulOutcome:
      logln("[E2AP] Received RIC-SUBSCRIPTION-FAILURE");
      break;

    default:
      logln("[E2AP] Invalid message index=%d in E2AP-PDU", index);
      break;
    }
    break;

  case ProcedureCode_id_RICindication: // 205
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage: // initiatingMessage
      logln("[E2AP] Received RIC-INDICATION-REQUEST");
      // e2ap_handle_RICSubscriptionRequest(pdu, socket_fd);
      break;
    case E2AP_PDU_PR_successfulOutcome:
      logln("[E2AP] Received RIC-INDICATION-RESPONSE");
      break;

    case E2AP_PDU_PR_unsuccessfulOutcome:
      logln("[E2AP] Received RIC-INDICATION-FAILURE");
      break;

    default:
      logln("[E2AP] Invalid message index=%d in E2AP-PDU %d", index,
               (int)ProcedureCode_id_RICindication);
      break;
    }
    break;

  case ProcedureCode_id_RICcontrol:
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage:
    {
      logln("[E2AP] Received RIC-CONTROL-REQUEST");
      long func_id = get_function_id_from_control(pdu);
      if (func_id < 0)
      {
        logln("[E2AP] Unable to extract RANfunctionID from RIC-CONTROL-REQUEST");
        break;
      }
      ControlCallback ctrl_cb = e2sim ? e2sim->get_control_callback(func_id) : nullptr;
      if (ctrl_cb)
      {
        ctrl_cb(pdu);
      }
      else
      {
        logln("[E2AP] No control callback registered for RANfunctionID=%ld", func_id);
      }
      break;
    }
    case E2AP_PDU_PR_successfulOutcome:
      logln("[E2AP] Received RIC-CONTROL-ACKNOWLEDGE");
      break;
    case E2AP_PDU_PR_unsuccessfulOutcome:
      logln("[E2AP] Received RIC-CONTROL-FAILURE");
      break;
    default:
      logln("[E2AP] Invalid message index=%d in E2AP-PDU %d", index,
                (int)ProcedureCode_id_RICcontrol);
      break;
    }
    break;

  case ProcedureCode_id_RICsubscriptionDelete:
    switch (index)
    {
    case E2AP_PDU_PR_initiatingMessage:
    {
      logln("[E2AP] Received RIC-SUBSCRIPTION-DELETE-REQUEST");
      long reqRequestorId = -1;
      long reqInstanceId = -1;
      long ranFunctionId = -1;

      RICsubscriptionDeleteRequest_t &del_req =
          pdu->choice.initiatingMessage->value.choice.RICsubscriptionDeleteRequest;
      int count = del_req.protocolIEs.list.count;
      auto **ies = (RICsubscriptionDeleteRequest_IEs_t **)del_req.protocolIEs.list.array;
      for (int i = 0; i < count; ++i)
      {
        RICsubscriptionDeleteRequest_IEs_t *next_ie = ies[i];
        if (!next_ie)
          continue;
        switch (next_ie->value.present)
        {
        case RICsubscriptionDeleteRequest_IEs__value_PR_RICrequestID:
          reqRequestorId = next_ie->value.choice.RICrequestID.ricRequestorID;
          reqInstanceId = next_ie->value.choice.RICrequestID.ricInstanceID;
          break;
        case RICsubscriptionDeleteRequest_IEs__value_PR_RANfunctionID:
          ranFunctionId = next_ie->value.choice.RANfunctionID;
          break;
        default:
          break;
        }
      }

      logln("[E2AP] Delete request payload -> requestorId=%ld instanceId=%ld ranFunctionId=%ld",
            reqRequestorId, reqInstanceId, ranFunctionId);

      if (ranFunctionId == 2)
      {
        stop_kpm_subscription(reqRequestorId, reqInstanceId, ranFunctionId);
      }

      if (reqRequestorId >= 0 && reqInstanceId >= 0 && ranFunctionId >= 0 && e2sim)
      {
        E2AP_PDU *resp_pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
        if (resp_pdu)
        {
          generate_e2apv2_subscription_delete_response(
              resp_pdu, reqRequestorId, reqInstanceId, ranFunctionId);
          e2sim->encode_and_send_sctp_data(resp_pdu);
          ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, resp_pdu);
        }
        else
        {
          logln("[E2AP] Failed to allocate response PDU for delete request");
        }
      }
      else
      {
        logln("[E2AP] Missing identifiers for delete request, skipping response");
      }
      break;
    }
    case E2AP_PDU_PR_successfulOutcome:
      logln("[E2AP] Received RIC-SUBSCRIPTION-DELETE-RESPONSE");
      break;
    case E2AP_PDU_PR_unsuccessfulOutcome:
      logln("[E2AP] Received RIC-SUBSCRIPTION-DELETE-FAILURE");
      break;
    default:
      logln("[E2AP] Invalid message index=%d in RIC-SUBSCRIPTION-DELETE PDU", index);
      break;
    }
    break;

  default:

    logln("[E2AP] No available handler for procedureCode=%d", procedureCode);

    break;
  }
}

/* Commento perchè non la utilizzo ma allo stesso tempo potrebbe essere utile per il futuro
void e2ap_handle_RICSubscriptionRequest(E2AP_PDU_t *pdu, int &socket_fd)
{

  // Send back Subscription Success Response

  E2AP_PDU_t *pdu_resp = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU));

  generate_e2apv2_subscription_response(pdu_resp, pdu);

  logln( "Subscription Response\n");

  xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu_resp);

  auto buffer_size2 = MAX_SCTP_BUFFER;
  unsigned char buffer2[MAX_SCTP_BUFFER];

  sctp_buffer_t data2;

  auto er2 = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu_resp, buffer2, buffer_size2);
  data2.len = er2.encoded;

  logln( "er encded is %ld\n", er2.encoded);

  memcpy(data2.buffer, buffer2, er2.encoded);

  if (sctp_send_data(socket_fd, data2) > 0)
  {
    LOG_I("[SCTP] Sent RIC-SUBSCRIPTION-RESPONSE");
  }
  else
  {
    LOG_E("[SCTP] Unable to send RIC-SUBSCRIPTION-RESPONSE to peer");
  }

  // Send back an Indication

  E2AP_PDU_t *pdu_ind = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU));

  generate_e2apv2_indication_request(pdu_ind);

  xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu_ind);

  auto buffer_size = MAX_SCTP_BUFFER;
  unsigned char buffer[MAX_SCTP_BUFFER];

  sctp_buffer_t data;

  auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu_ind, buffer, buffer_size);
  data.len = er.encoded;

  logln( "er encoded is %ld\n", er.encoded);

  memcpy(data.buffer, buffer, er.encoded);

  if (sctp_send_data(socket_fd, data) > 0)
  {
    LOG_I("[SCTP] Sent RIC-INDICATION-REQUEST");
  }
  else
  {
    LOG_E("[SCTP] Unable to send RIC-INDICATION-REQUEST to peer");
  }
}*/

void send_ric_service_update(int &socket_fd, sctp_buffer_t &data, E2Sim *e2sim)
{
  // Subito dopo lo setup, manda il RICserviceUpdate
  auto all_funcs = e2sim->get_registered_e2sm();
  if (all_funcs.size() == 0)
  {
    logln("No RAN functions registered, cannot send RICserviceUpdate");
    return;
  }
  std::vector<ran_func_info> funcs;
  for (const auto &[func_id, ostr] : all_funcs)
  {
    ran_func_info next_func;
    next_func.ranFunctionId = func_id;
    next_func.ranFunctionDesc = ostr;
    funcs.push_back(next_func);
  }
  E2AP_PDU_t *pdu_update = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
  build_ric_service_update(pdu_update, funcs, /*txid*/ 2);

  // encoda e invia con PPID=70
  unsigned char buf[2048];
  auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER,
                                 &asn_DEF_E2AP_PDU, pdu_update, buf, sizeof(buf));
  if (er.encoded > 0)
  {
    sctp_buffer_t out{};
    out.len = er.encoded;
    memcpy(out.buffer, buf, er.encoded);
    // assicurati che sctp_send_data setti sinfo_ppid = htonl(70)
    sctp_send_data(socket_fd, out);
  }
  return;
}
