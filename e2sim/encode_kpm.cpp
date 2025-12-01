#include "encode_kpm.hpp"
#include "n3iwf_data.hpp"
#include <ctime>

// Utility helpers

static inline void add_meas_name(MeasurementInfoList_t *list,const char *name) {
  if (!list) return;  // oppure assert/alloca, ma non dereferenziare
  MeasurementInfoItem_t *it = (MeasurementInfoItem_t *)calloc(1, sizeof(MeasurementInfoItem_t));
  it->measType.present = MeasurementType_PR_measName;
  OCTET_STRING_fromBuf(&it->measType.choice.measName, name, (int)strlen(name));

  LabelInfoItem *li = (LabelInfoItem *)calloc(1, sizeof(LabelInfoItem));
  li->measLabel.noLabel = (long*)calloc(1, sizeof(long));
  *li->measLabel.noLabel = 0; 
  ASN_SEQUENCE_ADD(&it->labelInfoList.list, li);

  ASN_SEQUENCE_ADD(&list->list, it);
}

static inline void rec_add_double(MeasurementRecord_t *rec, double v)
{
  MeasurementRecordItem_t *item = (MeasurementRecordItem_t *)calloc(1, sizeof(*item));
  item->present = MeasurementRecordItem_PR_real;
  item->choice.real = v;
  ASN_SEQUENCE_ADD(&rec->list, item);
}

// Riempie una struttura E2SM_KPM_IndicationMessage_Format1_t con la lista di KPI.
// Ritorna true se almeno una misura è stata aggiunta, false in caso di errore o lista vuota.
static bool fill_ind_msg_format1_struct(E2SM_KPM_IndicationMessage_Format1_t &fmt1,
                                        const std::map<std::string, double> &kpi)
{
  memset(&fmt1, 0, sizeof(fmt1));

  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(MeasurementDataItem_t));
  if (!mdi)
  {
    return false;
  }

  MeasurementInfoList_t *measInfoList = (MeasurementInfoList_t *)calloc(1, sizeof(MeasurementInfoList_t));
  if (!measInfoList)
  {
    free(mdi);
    return false;
  }
  fmt1.measInfoList = measInfoList;

  for (const auto &kv : kpi)
  {
    const char *name = kv.first.c_str();
    double value = kv.second;
    if (value != -1)
    {
      add_meas_name(fmt1.measInfoList, name);
      rec_add_double(&mdi->measRecord, value);
    }
  }

  if (fmt1.measInfoList->list.count == 0 ||
      mdi->measRecord.list.count != fmt1.measInfoList->list.count)
  {
    logln("No measurements to send in KPM Indication Message or inconsistent measurement counts\n");
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_MeasurementRecord, &mdi->measRecord);
    free(mdi);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_MeasurementInfoList, fmt1.measInfoList);
    free(fmt1.measInfoList);
    fmt1.measInfoList = nullptr;
    return false;
  }

  ASN_SEQUENCE_ADD(&fmt1.measData.list, mdi);
  return true;
}

// Converte un intero (RAN UE NGAP ID) in RANUEID (OCTET STRING di 8 byte, big-endian)
static bool build_ran_ueid_from_long(int64_t id, RANUEID_t *&out)
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


// Costruisce un UEID di tipo gNB-UEID usando AMF_UE_NGAP_ID e GUAMI/global PLMN.
static bool fill_ueid_from_assoc_gnb(const RcAssociationSnapshot &assoc, UEID_t &ueid)
{
  int64_t amf_id = assoc.ue.amf_ue_ngap_id;
  if (amf_id < 0)
  {
    return false;
  }

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

  // Costruisci GUAMI con PLMN dall'ID gNB globale (se disponibile), altrimenti default zero.
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

  // AMFRegionID: BIT STRING (SIZE(8))
  g->guami.aMFRegionID.size = 1;
  g->guami.aMFRegionID.buf = (uint8_t *)calloc(1, g->guami.aMFRegionID.size);
  g->guami.aMFRegionID.bits_unused = 0;

  // AMFSetID: BIT STRING (SIZE(10))
  g->guami.aMFSetID.size = 2;
  g->guami.aMFSetID.buf = (uint8_t *)calloc(1, g->guami.aMFSetID.size);
  g->guami.aMFSetID.bits_unused = 6;

  // AMFPointer: BIT STRING (SIZE(6))
  g->guami.aMFPointer.size = 1;
  g->guami.aMFPointer.buf = (uint8_t *)calloc(1, g->guami.aMFPointer.size);
  g->guami.aMFPointer.bits_unused = 2;

  // RAN UE ID opzionale: riusa ran_ue_ngap_id se presente.
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

// RAN Function Description (v3)

void encode_kpm_function_description(E2SM_KPM_RANfunction_Description_t *desc)
{
  // RANfunction-Name / OID / Instance
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-KPM", strlen("ORAN-E2SM-KPM"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_Description, "KPM monitor", strlen("KPM monitor"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_E2SM_OID, "1.3.6.1.4.1.53148.1.1.2.2", strlen("1.3.6.1.4.1.53148.1.1.2.2"));
  desc->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *desc->ranFunction_Name.ranFunction_Instance = 2;

  desc->ric_EventTriggerStyle_List =
      (decltype(desc->ric_EventTriggerStyle_List))calloc(1, sizeof(*desc->ric_EventTriggerStyle_List));
  desc->ric_ReportStyle_List =
      (decltype(desc->ric_ReportStyle_List))calloc(1, sizeof(*desc->ric_ReportStyle_List));

  // EventTrigger style: Periodic (Format 1)
  RIC_EventTriggerStyle_Item_t *et = (RIC_EventTriggerStyle_Item_t *)calloc(1, sizeof(*et));
  et->ric_EventTriggerStyle_Type = 1;
  OCTET_STRING_fromBuf(&et->ric_EventTriggerStyle_Name, "Periodic report",strlen("Periodic report"));
  et->ric_EventTriggerFormat_Type = 1; // KPM EventTrigger Format 1
  ASN_SEQUENCE_ADD(&desc->ric_EventTriggerStyle_List->list, et);

  // Report style type 1:
  // - ActionDefinition: Format 4 (UE-conditional, con subscriptionInfo in Format1)
  // - IndicationHeader: Format 1
  // - IndicationMessage: Format 3 (UEMeasurementReportList wrapping Format1)
  RIC_ReportStyle_Item_t *rs = (RIC_ReportStyle_Item_t *)calloc(1, sizeof(*rs));
  rs->ric_ReportStyle_Type = 4; // usa 4 se il tuo xApp lo richiede
  OCTET_STRING_fromBuf(&rs->ric_ReportStyle_Name, "KPM v3 N3IWF",strlen("KPM v3 N3IWF"));
  rs->ric_ActionFormat_Type = E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4;
  rs->ric_IndicationHeaderFormat_Type = E2SM_KPM_IndicationHeader__indicationHeader_formats_PR_indicationHeader_Format1;
  rs->ric_IndicationMessageFormat_Type = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3;

  // measInfoActionList (almeno una misura)
  // helper per aggiungere 1 misura con noLabel
  auto add_meas = [&](const char *name)
  {
    MeasurementInfo_Action_Item_t *mi = (MeasurementInfo_Action_Item_t *)calloc(1, sizeof(*mi));
    OCTET_STRING_fromBuf(&mi->measName, name, strlen(name));
    ASN_SEQUENCE_ADD(&rs->measInfo_Action_List.list, mi);
  };

  std::vector<std::string> allowedKPI = getAllowedKPI();
  for (const auto &kpi : allowedKPI)
  {
    add_meas(kpi.c_str());
  }

  // chiudi lo style
  ASN_SEQUENCE_ADD(&desc->ric_ReportStyle_List->list, rs);
}

void get_current_timestamp(OCTET_STRING_t *os)
{
  uint8_t buf[8];
  uint64_t ts = (uint64_t)time(NULL); // secondi epoch

  // scrivi ts in big-endian
  for (int i = 0; i < 8; ++i)
    buf[7 - i] = (uint8_t)((ts >> (8 * i)) & 0xFF);

  // Copia profonda nel campo ASN effettuata con la funzione standard asn1c.
  OCTET_STRING_fromBuf(os, (const char *)buf, 8);
}

// Indication Header - Format 1
void encode_kpm_ind_hdr_fmt1(E2SM_KPM_IndicationHeader_t *hdr)
{
  memset(hdr, 0, sizeof(*hdr));
  hdr->indicationHeader_formats.present = E2SM_KPM_IndicationHeader__indicationHeader_formats_PR_indicationHeader_Format1;

  E2SM_KPM_IndicationHeader_Format1_t *h1 = (E2SM_KPM_IndicationHeader_Format1_t *)calloc(1, sizeof(*h1));

  // In KPM v3 il campo è (tipicamente) scritto "colletStartTime" (refuso nel naming)
  // È un OCTET STRING (4..8); qui inseriamo un timestamp semplice.
  get_current_timestamp(&h1->colletStartTime);
  h1->senderName = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(h1->senderName, "O-RAN N3IWF", strlen("O-RAN N3IWF"));
  h1->fileFormatversion = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(h1->fileFormatversion, "3.0", strlen("3.0"));

  hdr->indicationHeader_formats.choice.indicationHeader_Format1 = h1;
  
}

void kpm_fill_ue_rf_basic(E2SM_KPM_IndicationMessage_t *indMsg, std::map<std::string, double> kpi)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present =
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 =
      (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));
  if (!fmt1)
  {
    return;
  }

  if (!fill_ind_msg_format1_struct(*fmt1, kpi))
  {
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationMessage_Format1, fmt1);
    free(fmt1);
    return;
  }

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;
}

void kpm_fill_ind_msg_format3(E2SM_KPM_IndicationMessage_t *indMsg,
                              const std::vector<RcAssociationSnapshot> &assocs,
                              const std::map<std::string, double> &kpi)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present =
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3;

  E2SM_KPM_IndicationMessage_Format3_t *fmt3 =
      (E2SM_KPM_IndicationMessage_Format3_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_Format3_t));
  if (!fmt3)
  {
    return;
  }

  size_t added = 0;
  for (const auto &assoc : assocs)
  {
    // Considera solo UE con un ran_ue_ngap_id valido
    if (assoc.ue.ran_ue_ngap_id < 0)
    {
      continue;
    }

    UEMeasurementReportItem_t *item =
        (UEMeasurementReportItem_t *)calloc(1, sizeof(UEMeasurementReportItem_t));
    if (!item)
    {
      continue;
    }

    bool have_ueid = fill_ueid_from_assoc_gnb(assoc, item->ueID);
    if (!have_ueid)
    {
      ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_UEID, &item->ueID);
      free(item);
      continue;
    }

    if (!fill_ind_msg_format1_struct(item->measReport, kpi))
    {
      ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_UEID, &item->ueID);
      ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationMessage_Format3, &item->measReport);
      free(item);
      continue;
    }

    ASN_SEQUENCE_ADD(&fmt3->ueMeasReportList.list, item);
    ++added;
  }

  if (added == 0)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage_Format3, fmt3);
    return;
  }

  indMsg->indicationMessage_formats.choice.indicationMessage_Format3 = fmt3;
}
