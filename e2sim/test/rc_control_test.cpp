#include <iostream>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>

extern "C" {
#include "asn_application.h"
#include "E2AP-PDU.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "RICcontrolRequest.h"
#include "RICcontrolHeader.h"
#include "RICcontrolMessage.h"

#include "UEID.h"
#include "UEID-GNB.h"
#include "UEID-GNB-DU.h"
#include "RANUEID.h"

#include "E2SM-RC-ControlHeader-Format1.h"
#include "E2SM-RC-ControlMessage.h"
#include "E2SM-RC-ControlMessage-Format1.h"
#include "E2SM-RC-ControlMessage-Format1-Item.h"
#include "RANParameter-ValueType-Choice-ElementTrue.h"
#include "RICcontrolAckRequest.h"

}

#include "../src/DEF/e2sim_defs.h"
#include "../rc_ids.hpp"
#include "../rc_callbacks.hpp"
#include "../n3iwf_data.hpp"

// Stub per soddisfare il link da e2ap_message_handler.cpp (non usato in questo test)
void stop_kpm_subscription(long, long, long) {}

// Simple helper: build a RANUEID (OCTET STRING) from a 64-bit integer, big-endian.
static bool build_ran_ueid_from_long(long id, RANUEID_t *&out)
{
  if (id < 0)
  {
    return false;
  }

  RANUEID_t *ran = (RANUEID_t *)calloc(1, sizeof(RANUEID_t));
  if (!ran)
  {
    return false;
  }

  ran->size = 8;
  ran->buf = (uint8_t *)calloc(1, ran->size);
  if (!ran->buf)
  {
    free(ran);
    return false;
  }

  uint64_t value = (uint64_t)id;
  for (int i = (int)ran->size - 1; i >= 0; --i)
  {
    ran->buf[i] = (uint8_t)(value & 0xFFu);
    value >>= 8;
  }

  out = ran;
  return true;
}

// Build a UEID partendo da uno snapshot RC (come per KPM).
static bool build_ueid_from_rc_assoc(const RcAssociationSnapshot &assoc, UEID_t &ueid)
{
  // Prova gNB_UEID (AMF_UE_NGAP_ID + GUAMI) se abbiamo amf_ue_ngap_id
  int64_t amf_id = assoc.ue.amf_ue_ngap_id;
  if (amf_id >= 0)
  {
    memset(&ueid, 0, sizeof(ueid));
    UEID_GNB_t *g = (UEID_GNB_t *)calloc(1, sizeof(UEID_GNB_t));
    if (!g)
    {
      return false;
    }

    if (asn_long2INTEGER(&g->amf_UE_NGAP_ID, amf_id) != 0)
    {
      free(g);
      return false;
    }

    GlobalgNB_ID_t *gnb_store = getGNBStore();
    PLMNIdentity_t plmn{};
    if (gnb_store && gnb_store->plmn_id.buf && gnb_store->plmn_id.size > 0)
    {
      OCTET_STRING_fromBuf(&plmn,
                           (const char *)gnb_store->plmn_id.buf,
                           (int)gnb_store->plmn_id.size);
    }
    else
    {
      uint8_t plmn_bytes[3] = {0, 0, 0};
      OCTET_STRING_fromBuf(&plmn, (const char *)plmn_bytes, 3);
    }
    g->guami.pLMNIdentity = plmn;

    g->guami.aMFRegionID.size = 1;
    g->guami.aMFRegionID.buf = (uint8_t *)calloc(1, g->guami.aMFRegionID.size);
    g->guami.aMFRegionID.bits_unused = 0;

    g->guami.aMFSetID.size = 2;
    g->guami.aMFSetID.buf = (uint8_t *)calloc(1, g->guami.aMFSetID.size);
    g->guami.aMFSetID.bits_unused = 6;

    g->guami.aMFPointer.size = 1;
    g->guami.aMFPointer.buf = (uint8_t *)calloc(1, g->guami.aMFPointer.size);
    g->guami.aMFPointer.bits_unused = 2;

    if (assoc.ue.ran_ue_ngap_id >= 0)
    {
      RANUEID_t *ran_oct = nullptr;
      if (build_ran_ueid_from_long(assoc.ue.ran_ue_ngap_id, ran_oct))
      {
        g->ran_UEID = ran_oct;
      }
    }

    ueid.present = UEID_PR_gNB_UEID;
    ueid.choice.gNB_UEID = g;
    return true;
  }

  // Fallback: usa gNB-DU-UEID con ran_ue_ngap_id
  int64_t ran_id = assoc.ue.ran_ue_ngap_id;
  if (ran_id < 0)
  {
    return false;
  }

  memset(&ueid, 0, sizeof(ueid));
  UEID_GNB_DU_t *du = (UEID_GNB_DU_t *)calloc(1, sizeof(UEID_GNB_DU_t));
  if (!du)
  {
    return false;
  }

  du->gNB_CU_UE_F1AP_ID = (GNB_CU_UE_F1AP_ID_t)ran_id;

  RANUEID_t *ran_oct = nullptr;
  if (!build_ran_ueid_from_long(ran_id, ran_oct))
  {
    free(du);
    return false;
  }
  du->ran_UEID = ran_oct;

  ueid.present = UEID_PR_gNB_DU_UEID;
  ueid.choice.gNB_DU_UEID = du;
  return true;
}

// Encode an E2SM-RC ControlHeader Format1 into a RICcontrolHeader (OCTET STRING).
static bool encode_control_header(const RcAssociationSnapshot &assoc, RICcontrolHeader_t &out_hdr)
{
  E2SM_RC_ControlHeader_Format1_t *hdr =
      (E2SM_RC_ControlHeader_Format1_t *)calloc(1, sizeof(E2SM_RC_ControlHeader_Format1_t));
  if (!hdr)
  {
    return false;
  }

  if (!build_ueid_from_rc_assoc(assoc, hdr->ueID))
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader_Format1, hdr);
    return false;
  }

  hdr->ric_Style_Type = kRcControlStyleTypeHandover;
  hdr->ric_ControlAction_ID = kRcControlActionIdHandover;

  hdr->ric_ControlDecision = (long *)calloc(1, sizeof(long));
  if (hdr->ric_ControlDecision)
  {
    *hdr->ric_ControlDecision = E2SM_RC_ControlHeader_Format1__ric_ControlDecision_accept;
  }

  uint8_t buf[MAX_SCTP_BUFFER];
  asn_enc_rval_t er = asn_encode_to_buffer(
      nullptr,
      ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_RC_ControlHeader_Format1,
      hdr,
      buf,
      sizeof(buf));

  if (er.encoded < 0)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader_Format1, hdr);
    return false;
  }

  memset(&out_hdr, 0, sizeof(out_hdr));
  OCTET_STRING_fromBuf(&out_hdr, (const char *)buf, (int)er.encoded);

  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader_Format1, hdr);
  return true;
}

// Encode a very simple E2SM-RC ControlMessage (Format1) with a fixed NR CGI parameter.
static bool encode_control_message(RICcontrolMessage_t &out_msg)
{
  E2SM_RC_ControlMessage_t *msg =
      (E2SM_RC_ControlMessage_t *)calloc(1, sizeof(E2SM_RC_ControlMessage_t));
  if (!msg)
  {
    return false;
  }

  msg->ric_controlMessage_formats.present =
      E2SM_RC_ControlMessage__ric_controlMessage_formats_PR_controlMessage_Format1;

  E2SM_RC_ControlMessage_Format1_t *fmt1 =
      (E2SM_RC_ControlMessage_Format1_t *)calloc(1, sizeof(E2SM_RC_ControlMessage_Format1_t));
  if (!fmt1)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, msg);
    return false;
  }
  msg->ric_controlMessage_formats.choice.controlMessage_Format1 = fmt1;

  // Single RAN parameter: NR CGI (kRcParamTargetNrCgi)
  auto *item =
      (E2SM_RC_ControlMessage_Format1_Item_t *)calloc(1, sizeof(E2SM_RC_ControlMessage_Format1_Item_t));
  if (!item)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, msg);
    return false;
  }

  item->ranParameter_ID = kRcParamTargetNrCgi;
  item->ranParameter_valueType.present = RANParameter_ValueType_PR_ranP_Choice_ElementTrue;
  item->ranParameter_valueType.choice.ranP_Choice_ElementTrue =
      (RANParameter_ValueType_Choice_ElementTrue_t *)calloc(
          1, sizeof(RANParameter_ValueType_Choice_ElementTrue_t));
  if (!item->ranParameter_valueType.choice.ranP_Choice_ElementTrue)
  {
    free(item);
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, msg);
    return false;
  }

  RANParameter_Value_t &val =
      item->ranParameter_valueType.choice.ranP_Choice_ElementTrue->ranParameter_value;
  val.present = RANParameter_Value_PR_valuePrintableString;
  // Identificatore di destinazione (es. PLMN 208-93 e N3IWF ID 136)
  const char *target_id = "208-93-136";
  OCTET_STRING_fromBuf(&val.choice.valuePrintableString,
                       target_id,
                       (int)strlen(target_id));

  ASN_SEQUENCE_ADD(&fmt1->ranP_List.list, item);

  uint8_t buf[MAX_SCTP_BUFFER];
  asn_enc_rval_t er = asn_encode_to_buffer(
      nullptr,
      ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_RC_ControlMessage,
      msg,
      buf,
      sizeof(buf));

  if (er.encoded < 0)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, msg);
    return false;
  }

  memset(&out_msg, 0, sizeof(out_msg));
  OCTET_STRING_fromBuf(&out_msg, (const char *)buf, (int)er.encoded);

  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, msg);
  return true;
}

// Build a complete E2AP RICcontrolRequest PDU with fixed content.
static bool build_ric_control_request_pdu(E2AP_PDU_t &pdu,
                                          long requestorId,
                                          long instanceId,
                                          long ranFunctionId,
                                          const RcAssociationSnapshot &assoc)
{
  memset(&pdu, 0, sizeof(pdu));

  pdu.present = E2AP_PDU_PR_initiatingMessage;
  InitiatingMessage_t *init = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  if (!init)
  {
    return false;
  }
  pdu.choice.initiatingMessage = init;
  init->procedureCode = ProcedureCode_id_RICcontrol;
  init->criticality = Criticality_reject;
  init->value.present = InitiatingMessage__value_PR_RICcontrolRequest;

  RICcontrolRequest_t *req = &init->value.choice.RICcontrolRequest;

  // IE: RICrequestID
  {
    RICcontrolRequest_IEs_t *ie =
        (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ie)
      return false;
    ie->id = ProtocolIE_ID_id_RICrequestID;
    ie->criticality = Criticality_reject;
    ie->value.present = RICcontrolRequest_IEs__value_PR_RICrequestID;
    ie->value.choice.RICrequestID.ricRequestorID = requestorId;
    ie->value.choice.RICrequestID.ricInstanceID = instanceId;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);
  }

  // IE: RANfunctionID
  {
    RICcontrolRequest_IEs_t *ie =
        (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ie)
      return false;
    ie->id = ProtocolIE_ID_id_RANfunctionID;
    ie->criticality = Criticality_reject;
    ie->value.present = RICcontrolRequest_IEs__value_PR_RANfunctionID;
    ie->value.choice.RANfunctionID = ranFunctionId;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);
  }

  // IE: RICcontrolHeader
  {
    RICcontrolHeader_t hdr_oct{};
    if (!encode_control_header(assoc, hdr_oct))
    {
      return false;
    }
    RICcontrolRequest_IEs_t *ie =
        (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ie)
      return false;
    ie->id = ProtocolIE_ID_id_RICcontrolHeader;
    ie->criticality = Criticality_reject;
    ie->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolHeader;
    ie->value.choice.RICcontrolHeader = hdr_oct;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);
  }

  // IE: RICcontrolMessage
  {
    RICcontrolMessage_t msg_oct{};
    if (!encode_control_message(msg_oct))
    {
      return false;
    }
    RICcontrolRequest_IEs_t *ie =
        (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ie)
      return false;
    ie->id = ProtocolIE_ID_id_RICcontrolMessage;
    ie->criticality = Criticality_reject;
    ie->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;
    ie->value.choice.RICcontrolMessage = msg_oct;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);
  }

  // IE: RICcontrolAckRequest (ask for ACK)
  {
    RICcontrolRequest_IEs_t *ie =
        (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ie)
      return false;
    ie->id = ProtocolIE_ID_id_RICcontrolAckRequest;
    ie->criticality = Criticality_reject;
    ie->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolAckRequest;
    ie->value.choice.RICcontrolAckRequest = RICcontrolAckRequest_ack;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);
  }

  return true;
}

int main(int argc, char *argv[])
{
  long ran_ue_id = -1;
  if (argc >= 2)
  {
    ran_ue_id = std::strtol(argv[1], nullptr, 0);
  }

  // Carica snapshot RC e seleziona una UE (come per KPM)
  std::vector<RcAssociationSnapshot> assocs = getRcAssociations();
  if (assocs.empty())
  {
    std::cerr << "[RC-TEST] Nessuna association nel RC snapshot" << std::endl;
    return 1;
  }

  const RcAssociationSnapshot *target_assoc = nullptr;
  if (ran_ue_id >= 0)
  {
    auto match = findRcAssociationByRanUeId(ran_ue_id);
    if (!match)
    {
      std::cerr << "[RC-TEST] Nessuna UE con ranUeNgapId=" << ran_ue_id << " nel RC snapshot" << std::endl;
      return 1;
    }
    target_assoc = &*match;
  }
  else
  {
    // default: prima UE con ran_ue_ngap_id valido
    for (const auto &a : assocs)
    {
      if (a.ue.ran_ue_ngap_id >= 0)
      {
        target_assoc = &a;
        break;
      }
    }
    if (!target_assoc)
    {
      std::cerr << "[RC-TEST] Nessuna UE con ran_ue_ngap_id valido nel RC snapshot" << std::endl;
      return 1;
    }
  }

  E2AP_PDU_t pdu{};
  long requestor_id = 1;
  long instance_id = 1;
  long ran_function_id = 3; // RC RAN function

  if (!build_ric_control_request_pdu(pdu, requestor_id, instance_id, ran_function_id, *target_assoc))
  {
    std::cerr << "[RC-TEST] Failed to build RICcontrolRequest PDU" << std::endl;
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, &pdu);
    return 1;
  }

  // Stampa opzionale del PDU costruito
  xer_fprint(stdout, &asn_DEF_E2AP_PDU, &pdu);

  // Chiama direttamente il callback RC come se il messaggio fosse arrivato via E2AP
  callback_rc_control_request(&pdu);

  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, &pdu);
  return 0;
}
