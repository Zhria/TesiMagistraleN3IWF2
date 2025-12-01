#ifndef ENCODE_KPM_V3_HPP
#define ENCODE_KPM_V3_HPP

#include <cstring>
#include <cstdlib>
#include <cassert>
#include "n3iwf_utils.hpp"
#include <vector>
#include <map>

// Forward declaration to avoid heavy includes here
struct RcAssociationSnapshot;

extern "C" {
  #include "asn_application.h"
  #include "OCTET_STRING.h"
  #include "TimeStamp.h"

  // RAN function description (stili ET/Report esistono ancora)
  #include "E2SM-KPM-RANfunction-Description.h"
  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"
  #include "asn_SEQUENCE_OF.h"

  // Header/Message v3 (formati)
  #include "E2SM-KPM-IndicationHeader.h"
  #include "E2SM-KPM-IndicationHeader-Format1.h"
  #include "E2SM-KPM-IndicationMessage.h"
  #include "E2SM-KPM-IndicationMessage-Format1.h"
  #include "E2SM-KPM-IndicationMessage-Format2.h"
  #include "E2SM-KPM-IndicationMessage-Format3.h"

  #include "UEMeasurementReportList.h"
  #include "UEMeasurementReportItem.h"

  // Nuovo data model delle misure
  #include "MeasurementInfoList.h"
  #include "MeasurementInfoItem.h"
  #include "LabelInfoList.h"
  #include "LabelInfoItem.h"
  #include "MeasurementLabel.h"
  #include "MeasurementData.h"
  #include "MeasurementDataItem.h"
  #include "MeasurementRecord.h"
  #include "MeasurementRecordItem.h"

  #include "MeasurementInfo-Action-Item.h"

  #include "INTEGER.h"

  #include "E2SM-KPM-RANfunction-Description.h"
  #include "E2SM-KPM-ActionDefinition.h"

  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"

  #include "UEID.h"
  #include "UEID-GNB.h"
  #include "UEID-GNB-DU.h"
  #include "RANUEID.h"
  #include "GNB-CU-UE-F1AP-ID.h"
}
  
// RAN Function Description
void encode_kpm_function_description(E2SM_KPM_RANfunction_Description_t* ranfunc_desc);

// Indication Header/Message (formati v3)
void encode_kpm_ind_hdr_fmt1(E2SM_KPM_IndicationHeader_t* hdr);

void kpm_fill_ue_rf_basic(E2SM_KPM_IndicationMessage_t* indMsg,std::map<std::string, double> kpi);

// Build IndicationMessage Format3 (per-UE reports wrapping Format1 per UE)
void kpm_fill_ind_msg_format3(E2SM_KPM_IndicationMessage_t* indMsg,
                              const std::vector<RcAssociationSnapshot>& assocs,
                              const std::map<std::string, double>& kpi);


#endif // ENCODE_KPM_V3_HPP
