#include <iostream>
#include <map>
#include <vector>

extern "C" {
#include "asn_application.h"
#include "E2SM-KPM-IndicationMessage.h"
}

#include "encode_kpm.hpp"
#include "n3iwf_data.hpp"

int main() {
  // Costruisci una finta associazione RC con ID UE validi
  RcAssociationSnapshot assoc;
  assoc.ue.ran_ue_ngap_id = 1;
  assoc.ue.amf_ue_ngap_id = 10;

  std::vector<RcAssociationSnapshot> assocs;
  assocs.push_back(assoc);

  // Costruisci un set di KPI non vuoto basato su getAllowedKPI()
  std::map<std::string, double> kpi;
  std::vector<std::string> allowed = getAllowedKPI();
  double value = 1.0;
  for (const auto &name : allowed) {
    kpi[name] = value;
    value += 1.0;
  }

  E2SM_KPM_IndicationMessage_t msg;
  memset(&msg, 0, sizeof(msg));

  kpm_fill_ind_msg_format3(&msg, assocs, kpi);
  if (!msg.indicationMessage_formats.choice.indicationMessage_Format3) {
    std::cerr << "kpm_fill_ind_msg_format3 did not populate Format3\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  char errbuf[512] = {0};
  size_t errlen = sizeof(errbuf);
  int rc = asn_check_constraints(&asn_DEF_E2SM_KPM_IndicationMessage, &msg, errbuf, &errlen);
  if (rc != 0) {
    std::cerr << "Constraint check FAILED for encoded message: "
              << (errbuf[0] ? errbuf : "no details") << "\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  uint8_t buf[8192];
  asn_enc_rval_t er = asn_encode_to_buffer(
      nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
      &msg, buf, sizeof(buf));
  if (er.encoded < 0) {
    std::cerr << "Encoding FAILED: "
              << (er.failed_type ? er.failed_type->name : "unknown") << "\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  size_t encoded_bytes = (er.encoded + 7) / 8;

  E2SM_KPM_IndicationMessage_t *decoded = nullptr;
  asn_dec_rval_t dr = asn_decode(
      nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
      reinterpret_cast<void **>(&decoded), buf, encoded_bytes);
  if (dr.code != RC_OK || !decoded) {
    std::cerr << "Decoding FAILED at byte " << dr.consumed << "\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  if (decoded->indicationMessage_formats.present !=
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3) {
    std::cerr << "Decoded message is not Format3\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  auto *fmt3 = decoded->indicationMessage_formats.choice.indicationMessage_Format3;
  if (!fmt3 || fmt3->ueMeasReportList.list.count == 0) {
    std::cerr << "Decoded Format3 has no UE measurement reports\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  auto *item = fmt3->ueMeasReportList.list.array[0];
  if (!item) {
    std::cerr << "First UEMeasurementReportItem is null\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  auto &measReport = item->measReport;
  size_t data_count = measReport.measData.list.count;
  if (data_count == 0) {
    std::cerr << "Decoded measData list is empty\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  MeasurementDataItem_t *mdi = measReport.measData.list.array[0];
  if (!mdi) {
    std::cerr << "Decoded MeasurementDataItem is null\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    return 1;
  }

  size_t rec_len = mdi->measRecord.list.count;
  size_t info_len = measReport.measInfoList ? measReport.measInfoList->list.count : 0;

  std::cout << "Decoded UE reports: " << fmt3->ueMeasReportList.list.count << "\n";
  std::cout << "Decoded MeasurementDataItem count: " << data_count << "\n";
  std::cout << "Decoded measRecord length: " << rec_len << "\n";
  std::cout << "Decoded measInfoList length: " << info_len << "\n";

  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
  return 0;
}

