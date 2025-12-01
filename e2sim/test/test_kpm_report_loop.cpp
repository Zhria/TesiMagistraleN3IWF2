#include <iostream>
#include <map>
#include <vector>
#include <array>
#include <ctime>
#include <string>

extern "C" {
#include "asn_application.h"
#include "E2SM-KPM-IndicationHeader.h"
#include "E2SM-KPM-IndicationMessage.h"
}

// Provide the global timestamp used by logln() in n3iwf_utils.cpp
extern struct timespec ts;

// Stub for link-time dependency pulled in from e2ap_message_handler.cpp
void stop_kpm_subscription(long, long, long) {}


#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_hdr.h"
#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_msg.h"
#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_msg_frm_3.h"
#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_info_frm_1_lst.h"
#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_data_lst.h"
#include "/home/zakaria/flexricFeraudo/flexric-sm/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_type.h"

// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_hdr.h"
// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_msg.h"
// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/kpm_ric_info/kpm_ric_ind_msg_frm_3.h"
// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_info_frm_1_lst.h"
// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_data_lst.h"
// #include "/home/zakaria/flexric/src/sm/kpm_sm/kpm_sm_v03.00/ie/kpm_data_ie/data/meas_type.h"


extern "C" {
  kpm_ind_hdr_t kpm_dec_ind_hdr_asn(size_t len, const uint8_t *ind_hdr);
  kpm_ind_msg_t kpm_dec_ind_msg_asn(size_t len, const uint8_t *ind_msg);
}


#include "encode_kpm.hpp"
#include "n3iwf_utils.hpp"
#include "n3iwf_data.hpp"

// Standalone test: mimics run_report_loop by encoding a header + Format3 message
// into local buffers instead of sending over SCTP.
int main() {
  constexpr size_t MAX_BUF = 8192;

  // Fake UE association so Format3 has something to wrap.
  RcAssociationSnapshot assoc{};
  assoc.ue.ran_ue_ngap_id = 1001;
  assoc.ue.amf_ue_ngap_id = 2002;

  std::vector<RcAssociationSnapshot> assocs;
  assocs.push_back(assoc);

  // Populate KPI map with allowed names (values are arbitrary > -1).
  std::map<std::string, double> kpi;
  double v = 1.0;
  for (const auto &name : getAllowedKPI()) {
    kpi[name] = v;
    v += 1.0;
  }

  // Encode Indication Header (Format1).
  E2SM_KPM_IndicationHeader_t hdr{};
  encode_kpm_ind_hdr_fmt1(&hdr);

  uint8_t hdr_buf[MAX_SCTP_BUFFER];
    asn_enc_rval_t ehr = asn_encode_to_buffer(
        NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,&hdr, hdr_buf, sizeof(hdr_buf));

  if (ehr.encoded < 0) {
    std::cerr << "Header encode failed: "
              << (ehr.failed_type ? ehr.failed_type->name : "unknown") << "\n";
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationHeader, &hdr);
    return 1;
  }

  // Encode Indication Message (Format3 with embedded Format1 per UE).
  E2SM_KPM_IndicationMessage_t msg{};
  msg.indicationMessage_formats.present =
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3;


  E2SM_KPM_IndicationMessage_Format3_t *fmt3 =
      (E2SM_KPM_IndicationMessage_Format3_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_Format3_t));
  UEMeasurementReportItem_t *UE_Data =
        (UEMeasurementReportItem_t *)calloc(1, sizeof(UEMeasurementReportItem_t));

  // UEID gNB popolato in linea
  UEID_t ueid{};
  UEID_GNB_t *gnb = (UEID_GNB_t *)calloc(1, sizeof(UEID_GNB_t));
  asn_long2INTEGER(&gnb->amf_UE_NGAP_ID, 2002);
  OCTET_STRING_fromBuf(&gnb->guami.pLMNIdentity, "\x00\x00\x00", 3);
  gnb->guami.aMFRegionID.size = 1; gnb->guami.aMFRegionID.buf = (uint8_t *)calloc(1, 1); gnb->guami.aMFRegionID.bits_unused = 0;
  gnb->guami.aMFSetID.size = 2;   gnb->guami.aMFSetID.buf   = (uint8_t *)calloc(1, 2); gnb->guami.aMFSetID.bits_unused = 6;
  gnb->guami.aMFPointer.size = 1; gnb->guami.aMFPointer.buf = (uint8_t *)calloc(1, 1); gnb->guami.aMFPointer.bits_unused = 2;
  gnb->ran_UEID = (RANUEID_t *)calloc(1, sizeof(RANUEID_t));
  gnb->ran_UEID->size = 8; gnb->ran_UEID->buf = (uint8_t *)calloc(1, gnb->ran_UEID->size);
  gnb->ran_UEID->buf[7] = 0xE9; // 1001 dec -> 0x3E9, ultimo byte
  ueid.present = UEID_PR_gNB_UEID;
  ueid.choice.gNB_UEID = gnb;
  UE_Data->ueID = ueid;

  // Misura minima: 1 voce info + 1 valore reale
  MeasurementInfoList_t *measInfoList = (MeasurementInfoList_t *)calloc(1, sizeof(MeasurementInfoList_t));
  MeasurementInfoItem_t *mi = (MeasurementInfoItem_t *)calloc(1, sizeof(MeasurementInfoItem_t));
  mi->measType.present = MeasurementType_PR_measName;
  OCTET_STRING_fromBuf(&mi->measType.choice.measName, "DRB.UEThpDl", strlen("DRB.UEThpDl"));
  LabelInfoItem *li = (LabelInfoItem *)calloc(1, sizeof(LabelInfoItem));
  li->measLabel.noLabel = (long *)calloc(1, sizeof(long)); *li->measLabel.noLabel = 0;
  ASN_SEQUENCE_ADD(&mi->labelInfoList.list, li);
  ASN_SEQUENCE_ADD(&measInfoList->list, mi);
  UE_Data->measReport.measInfoList = measInfoList;

  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(MeasurementDataItem_t));
  MeasurementRecordItem_t *mri = (MeasurementRecordItem_t *)calloc(1, sizeof(MeasurementRecordItem_t));
  mri->present = MeasurementRecordItem_PR_real;
  mri->choice.real = 123.45;
  ASN_SEQUENCE_ADD(&mdi->measRecord.list, mri);
  ASN_SEQUENCE_ADD(&UE_Data->measReport.measData.list, mdi);

  int const rc = ASN_SEQUENCE_ADD(&fmt3->ueMeasReportList.list, UE_Data);
  assert(rc == 0);

  msg.indicationMessage_formats.choice.indicationMessage_Format3 = fmt3;

  msg.indicationMessage_formats.present=
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3;

  uint8_t msg_buf[MAX_SCTP_BUFFER];
  asn_enc_rval_t emr = asn_encode_to_buffer(
      NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,&msg, msg_buf, sizeof(msg_buf));
  if (emr.encoded < 0) {
    std::cerr << "Message encode failed: "
              << (emr.failed_type ? emr.failed_type->name : "unknown") << "\n";
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, &msg);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationHeader, &hdr);
    return 1;
  }

  size_t hdr_len = static_cast<size_t>(ehr.encoded);
  size_t msg_len = static_cast<size_t>(emr.encoded);

  std::cout << "Header encoded bytes: " << hdr_len << "\n";
  std::cout << "Message encoded bytes: " << msg_len << "\n";

  // Decode with FlexRIC KPM v3 helpers (dispatches on present/style).
  kpm_ind_hdr_t h_dec = kpm_dec_ind_hdr_asn(hdr_len, hdr_buf);
  kpm_ind_msg_t m_dec = kpm_dec_ind_msg_asn(msg_len, msg_buf);
  //kpm_ind_msg_format_3_t fmt3=kpm_dec_ind_msg_frm_3_asn(msg.indicationMessage_formats.choice.indicationMessage_Format3);
  std::cout << "FlexRIC decode -> ind_hdr format=" << h_dec.type
            << " ind_msg format=" << m_dec.type
            << " (2 means Format3)\n";
  if (m_dec.type == FORMAT_3_INDICATION_MESSAGE) {
    std::cout << "UE meas reports: " << m_dec.frm_3.ue_meas_report_lst_len << "\n";
    auto &fmt3 = m_dec.frm_3;
    for (size_t ue_idx = 0; ue_idx < fmt3.ue_meas_report_lst_len; ++ue_idx) {
      const auto &ue = fmt3.meas_report_per_ue[ue_idx];
      std::cout << "  UE[" << ue_idx << "] type=" << ue.ue_meas_report_lst.type << "\n";

      const auto &f1 = ue.ind_msg_format_1;
      if (f1.meas_data_lst_len == 0 || f1.meas_data_lst == nullptr) {
        std::cout << "    meas_data empty\n";
        continue;
      }
      const meas_data_lst_t &data = f1.meas_data_lst[0];
      for (size_t j = 0; j < data.meas_record_len; ++j) {
        std::string name = "meas[" + std::to_string(j) + "]";
        if (f1.meas_info_lst && j < f1.meas_info_lst_len) {
          const auto &mi = f1.meas_info_lst[j];
          if (mi.meas_type.type == meas_type_t::NAME_MEAS_TYPE && mi.meas_type.name.buf) {
            name.assign(reinterpret_cast<char *>(mi.meas_type.name.buf), mi.meas_type.name.len);
          } else if (mi.meas_type.type == meas_type_t::ID_MEAS_TYPE) {
            name = "id=" + std::to_string(mi.meas_type.id);
          }
        }

        const auto &rec = data.meas_record_lst[j];
        std::string value_str;
        switch (rec.value) {
        case REAL_MEAS_VALUE:
          value_str = std::to_string(rec.real_val);
          break;
        case INTEGER_MEAS_VALUE:
          value_str = std::to_string(rec.int_val);
          break;
        case NO_VALUE_MEAS_VALUE:
          value_str = "no-value";
          break;
        default:
          value_str = "unknown";
          break;
        }
        std::cout << "    " << name << " = " << value_str << "\n";
      }
    }
  }

  // Optional self-check: decode the message from the local buffer.
  E2SM_KPM_IndicationMessage_t *decoded = nullptr;
  asn_dec_rval_t dr = asn_decode(
      nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
      reinterpret_cast<void **>(&decoded), msg_buf, msg_len);
  if (dr.code != RC_OK || !decoded) {
    std::cerr << "Decode failed at byte " << dr.consumed << "\n";
  } else {
    auto *fmt3 = decoded->indicationMessage_formats.choice.indicationMessage_Format3;
    int ue_count = fmt3 ? fmt3->ueMeasReportList.list.count : 0;
    std::cout << "Decoded UE reports: " << ue_count << "\n";
  }

  return 0;
}
