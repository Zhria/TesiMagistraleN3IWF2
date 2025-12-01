#ifndef ENCODE_RC_V3_HPP
#define ENCODE_RC_V3_HPP

#include <cstring>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <string> 
#include <map>
extern "C" {
  #include "asn_application.h"
  #include "OCTET_STRING.h"
  #include "TimeStamp.h"

  // RAN function description (stili ET/Report esistono ancora)
  #include "E2SM-RC-RANFunctionDefinition.h"
  #include "RANFunctionDefinition-EventTrigger.h"
  #include "RANFunctionDefinition-Report.h"
  #include "RANFunctionDefinition-Control.h"
  #include "RANFunctionDefinition-Policy.h"
  #include "RANFunctionDefinition-Control-Item.h"
  #include "RANFunctionDefinition-Control-Action-Item.h"
  #include "ControlAction-RANParameter-Item.h"
  #include "ControlOutcome-RANParameter-Item.h"
  #include "RANFunctionDefinition-Insert.h"
  #include "RANFunctionDefinition-Insert-Item.h"
  #include "UEIdentification-RANParameter-Item.h"
  #include "RANFunctionDefinition-Report-Item.h"
  #include "Report-RANParameter-Item.h"
  


  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"
  #include "asn_SEQUENCE_OF.h"

  // Header/Message v3 (formati)
  #include "E2SM-RC-IndicationHeader.h"
  #include "E2SM-RC-IndicationHeader-Format1.h"
  #include "E2SM-RC-IndicationMessage.h"
  #include "E2SM-RC-IndicationMessage-Format1.h"
  #include "E2SM-RC-IndicationMessage-Format2.h"
  
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

  #include "E2SM-RC-ActionDefinition.h"
  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"
  

}
  
// RAN Function Description
void encode_rc_function_definition(E2SM_RC_RANFunctionDefinition* ranfunc_desc);

// Potenziali estensioni per future Indication Header/Message (v3)
// void encode_rc_ind_hdr_fmt1(E2SM_RC_IndicationHeader_t* hdr);
// void rc_fill_ue_rf_basic(E2SM_RC_IndicationMessage_t* indMsg,std::map<std::string, double> kpi);


#endif // ENCODE_RC_V3_HPP
