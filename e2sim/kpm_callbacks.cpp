#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <map>
#include <mutex>
#include <memory>
#include <atomic>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>   // shutdown()
#include <netinet/sctp.h> // SCTP

extern "C"
{
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "E2SM-KPM-IndicationMessage.h"
#include "E2SM-KPM-RANfunction-Description.h"
#include "E2AP-PDU.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "RICactionType.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-SingleContainer.h"
#include "InitiatingMessage.h"

#include "E2SM-RC-RANFunctionDefinition.h"
#include "E2SM-RC-IndicationMessage.h"
#include "E2SM-RC-EventTrigger.h"
#include "E2SM-RC-EventTrigger-Format1.h"
#include "E2SM-RC-EventTrigger-Format2.h"
#include "E2SM-RC-EventTrigger-Format3.h"
#include "E2SM-RC-EventTrigger-Format4.h"
#include "E2SM-RC-ActionDefinition-Format1-Item.h"
#include "E2SM-RC-ActionDefinition-Format1.h"

// KPM ActionDefinition Formats (per-UE conditional subscriptions, UEID-based, ecc.)
#include "E2SM-KPM-ActionDefinition-Format4.h"
#include "E2SM-KPM-ActionDefinition-Format2.h"
#include "E2SM-KPM-ActionDefinition-Format3.h"
#include "E2SM-KPM-ActionDefinition-Format5.h"
#include "E2SM-KPM-EventTriggerDefinition.h"
#include "E2SM-KPM-EventTriggerDefinition-Format1.h"
#include "E2SM-KPM-IndicationHeader-Format1.h"
#include "E2SM-KPM-IndicationMessage-Format3.h"
#include "MatchingUeCondPerSubItem.h"
#include "MatchingUeCondPerSubList.h"
}

#include "kpm_callbacks.hpp"
#include "encode_kpm.hpp"
#include "n3iwf_utils.hpp"
#include "rc_callbacks.hpp"
#include "encode_rc.hpp"
#include "subscription_key.hpp"
#include "app_state.hpp"

#include "encode_e2apv2.hpp"

#include <nlohmann/json.hpp>
#include "n3iwf_data.hpp"
#include <atomic>
#include <signal.h>

extern struct timespec ts;

using namespace std;
using json = nlohmann::json;
static E2Sim e2;
std::atomic_bool g_app_stop{false};
extern int client_fd;

// Verifica locale: decodifica il messaggio KPM appena encodato (PER aligned, emr.encoded = byte count)
// per assicurarsi che sia internamente consistente prima di inviarlo allo xApp.
static bool kpm_self_decode_check(const uint8_t *buf, size_t encoded_len_bytes)
{
  if (!buf || encoded_len_bytes == 0)
  {
    return false;
  }

  E2SM_KPM_IndicationMessage_t *decoded = nullptr;

  asn_dec_rval_t dr = asn_decode(
      nullptr, ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_KPM_IndicationMessage,
      (void **)&decoded, buf, encoded_len_bytes);

  if (dr.code != RC_OK || !decoded)
  {
    logln("KPM self-decode failed (code=%d, consumed=%zu)", dr.code, dr.consumed);
    if (decoded)
    {
      ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
    }
    return false;
  }

  bool ok = true;

  if (decoded->indicationMessage_formats.present ==
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format3)
  {
    auto *fmt3 = decoded->indicationMessage_formats.choice.indicationMessage_Format3;
    if (!fmt3 || fmt3->ueMeasReportList.list.count == 0)
    {
      logln("KPM self-decode: Format3 with empty ueMeasReportList");
      ok = false;
    }
    else
    {
      for (int i = 0; i < fmt3->ueMeasReportList.list.count; ++i)
      {
        UEMeasurementReportItem_t *item = fmt3->ueMeasReportList.list.array[i];
        if (!item)
        {
          ok = false;
          break;
        }
        E2SM_KPM_IndicationMessage_Format1_t &f1 = item->measReport;
        if (f1.measData.list.count == 0)
        {
          logln("KPM self-decode: UE[%d] has empty measData", i);
          ok = false;
          break;
        }
        MeasurementDataItem_t *mdi = f1.measData.list.array[0];
        if (!mdi || mdi->measRecord.list.count == 0)
        {
          logln("KPM self-decode: UE[%d] has empty measRecord", i);
          ok = false;
          break;
        }
      }
    }
  }

  logln("KPM IndicationMessage XER dump");
  xer_fprint(stdout, &asn_DEF_E2SM_KPM_IndicationMessage, decoded);

  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, decoded);
  return ok;
}

struct KpmWorkerCtx
{
  std::shared_ptr<std::atomic_bool> stop_flag;
  std::thread worker;

  KpmWorkerCtx() = default;
  KpmWorkerCtx(std::thread &&thr, std::shared_ptr<std::atomic_bool> flag)
      : stop_flag(std::move(flag)), worker(std::move(thr)) {}

  KpmWorkerCtx(const KpmWorkerCtx &) = delete;
  KpmWorkerCtx &operator=(const KpmWorkerCtx &) = delete;
  KpmWorkerCtx(KpmWorkerCtx &&) noexcept = default;
  KpmWorkerCtx &operator=(KpmWorkerCtx &&) noexcept = default;
};

static std::mutex g_kpm_workers_mutex;
static std::map<SubscriptionKey, KpmWorkerCtx> g_kpm_workers;

static void stop_kpm_worker(const SubscriptionKey &key)
{
  std::shared_ptr<std::atomic_bool> stop_flag;
  std::thread worker;

  {
    std::lock_guard<std::mutex> lock(g_kpm_workers_mutex);
    auto it = g_kpm_workers.find(key);
    if (it == g_kpm_workers.end())
    {
      return;
    }
    stop_flag = it->second.stop_flag;
    worker = std::move(it->second.worker);
    g_kpm_workers.erase(it);
  }

  if (stop_flag)
  {
    stop_flag->store(true);
  }
  if (worker.joinable())
  {
    worker.join();
  }
}

static void stop_all_kpm_workers()
{
  std::vector<std::thread> workers_to_join;

  {
    std::lock_guard<std::mutex> lock(g_kpm_workers_mutex);
    for (auto &entry : g_kpm_workers)
    {
      if (entry.second.stop_flag)
      {
        entry.second.stop_flag->store(true);
      }
      workers_to_join.emplace_back(std::move(entry.second.worker));
    }
    g_kpm_workers.clear();
  }

  for (auto &t : workers_to_join)
  {
    if (t.joinable())
    {
      t.join();
    }
  }
}

void stop_kpm_subscription(long requestorId, long instanceId, long ranFunctionId)
{
  std::vector<SubscriptionKey> keys_to_stop;
  {
    std::lock_guard<std::mutex> lock(g_kpm_workers_mutex);
    for (const auto &entry : g_kpm_workers)
    {
      const auto &key = entry.first;
      if (ranFunctionId >= 0 && key.ranFunctionId != ranFunctionId)
      {
        continue;
      }
      if (requestorId >= 0 && key.requestorId != requestorId)
      {
        continue;
      }
      if (instanceId >= 0 && key.instanceId != instanceId)
      {
        continue;
      }
      keys_to_stop.push_back(key);
    }
  }

  if (keys_to_stop.empty())
  {
    logln("KPM subscription delete: no active worker for req=%ld inst=%ld ranFunc=%ld",
          requestorId, instanceId, ranFunctionId);
    return;
  }

  for (const auto &key : keys_to_stop)
  {
    logln("KPM subscription delete: stopping worker req=%ld inst=%ld ranFunc=%ld action=%ld",
          key.requestorId, key.instanceId, key.ranFunctionId, key.actionId);
    stop_kpm_worker(key);
  }
}

static void graceful_sctp_close(int fd)
{
  // 1) annuncia fine scritture -> kernel invia SHUTDOWN all peer
  shutdown(fd, SHUT_WR);
  // 2) drena eventuali dati in arrivo finché peer chiude
  char buf[2048];
  while (true)
  {
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n == 0)
      break; // EOF -> SHUTDOWN-ACK/COMPLETE completato
    if (n < 0)
      break; // errore -> chiudi comunque
  }
  // 3) chiusura definitiva della socket
  close(fd);
}

static void on_term(int)
{
  g_app_stop.store(true, std::memory_order_relaxed);
  // (opzionale) manda un E2AP Reset verso il RIC
  // send_e2ap_reset_request(g_sctp_fd);

  // chiudi TUTTE le associazioni SCTP con teardown pulito
  graceful_sctp_close(client_fd);

  stop_all_kpm_workers();
  stop_all_rc_workers();

  // libera risorse (ASN.1, heap, thread join, ecc.)
  // cleanup_asn1();
  // join_threads();
  logln("E2 Simulator exiting cleanly\n");
  _exit(0); // uscita rapida dopo cleanup
}
/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[])
{
  // pausa per permettere al n3iwf di avviarsi e iniziare a loggare
  std::this_thread::sleep_for(std::chrono::seconds(5));
  logln("Starting E2 Simulator with KPM Callbacks (KPM v3)\n");
  clock_gettime(CLOCK_REALTIME, &ts); // Inizializza ts all'avvio

  struct sigaction sa{};
  sa.sa_handler = on_term;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGSEGV, &sa, nullptr);

  registerKPMfunctionDefinition();

  registerRCfunctionDefinition(e2);

  // Avvia loop del simulatore
  e2.run_loop(argc, argv);
  return 0;
}

static void log_kpm_parameters(const std::map<std::string, double> &kpi)
{
  if (kpi.empty())
  {
    return;
  }
  std::string line;
  line.reserve(kpi.size() * 16);
  bool first = true;
  for (const auto &entry : kpi)
  {
    if (!first)
    {
      line.append(", ");
    }
    first = false;
    line.append(entry.first);
    line.push_back('=');
    line.append(std::to_string(entry.second));
  }
  logln("KPM report parameters: %s", line.c_str());
}

/* ============================================================
 * REPORT LOOP (genera e invia Indication in base ai file JSON)
 * ============================================================ */
void run_report_loop(long requestorId, long instanceId, long ranFunctionId, long actionId, GranularityPeriod_t granularityPeriod, const std::shared_ptr<std::atomic_bool> &stop_token)
{
  long seqNum = 1;
  asn_codec_ctx_t *opt_cod = NULL; // usare NULL per il contesto (standard)

  for (;;)
  {
    if (g_app_stop.load(std::memory_order_relaxed))
    {
      break;
    }
    if (stop_token && stop_token->load(std::memory_order_relaxed))
    {
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(granularityPeriod));

    std::map<std::string, double> kpi = getMetricsKPM(granularityPeriod);
    if (kpi.empty())
    {
      logln("KPM report loop: no KPI metrics available, skipping seqNum %ld", seqNum);
      continue;
    }
    E2SM_KPM_IndicationHeader_t hdr;
    encode_kpm_ind_hdr_fmt1(&hdr);

    uint8_t hdr_buf[MAX_SCTP_BUFFER];
    asn_enc_rval_t ehr = asn_encode_to_buffer(
        opt_cod, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,
        &hdr, hdr_buf, sizeof(hdr_buf));
    if (ehr.encoded < 0)
    {
      logln("hdr enc failed\n"); /* handle */
      logln("Reason: %s\n", ehr.failed_type ? ehr.failed_type->name : "unknown");
      continue;
    }

    E2SM_KPM_IndicationMessage_t *ind_msg =
        (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));

    std::vector<RcAssociationSnapshot> assocs = getRcAssociations();
    kpm_fill_ind_msg_format3(ind_msg, assocs, kpi);
    if (!ind_msg->indicationMessage_formats.choice.indicationMessage_Format3)
    {
      logln("KPM indication message (Format3) was not populated, skipping seqNum %ld", seqNum);
      continue;
    }

    uint8_t msg_buf[MAX_SCTP_BUFFER];

    asn_enc_rval_t emr = asn_encode_to_buffer(opt_cod, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
                                              ind_msg, msg_buf, sizeof(msg_buf));
    if (emr.encoded < 0)
    {
      logln("msg enc failed\n"); /* handle */
      logln("Reason: %s\n", emr.failed_type ? emr.failed_type->name : "unknown");
      continue;
    }

    if (!kpm_self_decode_check(msg_buf, (size_t)emr.encoded))
    {
      logln("KPM self-decode check failed, skipping seqNum %ld", seqNum);
      ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, ind_msg);
      ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationHeader, &hdr);
      continue;
    }

    E2AP_PDU *pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
    if (pdu == NULL)
    {
      logln("calloc failed for pdu\n");
      continue;
    }

    // log_kpm_parameters(kpi);

    generate_e2apv2_indication_request_parameterized(pdu, requestorId, instanceId, ranFunctionId, actionId, seqNum,
                                                     hdr_buf, (int)ehr.encoded, msg_buf, (int)emr.encoded);

    e2.encode_and_send_sctp_data(pdu);
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, ind_msg);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationHeader, &hdr);
    logln("KPM Indication sent: reqId=%ld instId=%ld ranFuncId=%ld actionId=%ld seqNum=%ld", requestorId, instanceId, ranFunctionId, actionId, seqNum);

    seqNum++;
  }
}

static void start_kpm_worker(const SubscriptionKey &key,
                             long requestorId,
                             long instanceId,
                             long ranFunctionId,
                             long actionId,
                             GranularityPeriod_t granularityPeriod)
{
  stop_kpm_worker(key);

  auto stop_flag = std::make_shared<std::atomic_bool>(false);

  std::thread worker([requestorId, instanceId, ranFunctionId, actionId, granularityPeriod, stop_flag]()
                     { run_report_loop(requestorId, instanceId, ranFunctionId, actionId, granularityPeriod, stop_flag); });

  std::lock_guard<std::mutex> lock(g_kpm_workers_mutex);
  g_kpm_workers.emplace(key, KpmWorkerCtx{std::move(worker), stop_flag});
}

static bool extract_meas_names_from_kpm_actiondef(const OCTET_STRING_t *act_def,
                                                  std::vector<std::string> &out_meas,
                                                  GranularityPeriod_t *granularityPeriod)
{
  if (!act_def || !act_def->buf || act_def->size == 0)
  {
    logln("[KPM SUB] ActionDefinition missing or empty");
    return false;
  }

  logln("[KPM SUB] Decoding ActionDefinition, size=%ld bytes", (long)act_def->size);

  E2SM_KPM_ActionDefinition_t *ad = nullptr;
  asn_dec_rval_t dr = aper_decode(
      /*opt_ctx*/ nullptr,
      &asn_DEF_E2SM_KPM_ActionDefinition,
      (void **)&ad,
      act_def->buf, act_def->size,
      /*skip_bits*/ 0, /*unused_bits*/ 0);

  if (dr.code != RC_OK || !ad)
  {
    logln("[KPM SUB] ActionDefinition decode failed: code=%d consumed=%zu", dr.code, dr.consumed);
    return false;
  }

  logln("[KPM SUB] ActionDefinition decoded: present=%d", ad->actionDefinition_formats.present);

  E2SM_KPM_ActionDefinition_Format1_t *f1 = nullptr;
  GranularityPeriod_t gp = 0;
  MatchingUeCondPerSubList_t matchingConditions;
  E2SM_KPM_ActionDefinition_Format4_t *f4 = nullptr;
  if (ad->actionDefinition_formats.present ==
      E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format4)
  {
    f4 = ad->actionDefinition_formats.choice.actionDefinition_Format4;
    if (f4)
    {
      matchingConditions = f4->matchingUeCondList;
      f1 = &f4->subscriptionInfo;
      logln("[KPM SUB] Using subscriptionInfo (Format1) from ActionDefinition Format4");
      gp = f1->granulPeriod;
    }
  }
  else
  {
    E2SM_KPM_ActionDefinition_Format2_t *f2 = ad->actionDefinition_formats.choice.actionDefinition_Format2;
    if(f2){
      f1 = &f2->subscriptInfo;
      logln("[KPM SUB] Using subscriptionInfo (Format1) from ActionDefinition Format2");
      gp = f1->granulPeriod;
    }

    // logln("[KPM SUB] Unsupported ActionDefinition format: %d", ad->actionDefinition_formats.present);
    // ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, ad);
    // return false;
  }

  // Mi aspetto delle matching conditions riguardo a sst e sd.
  // for (int i = 0; i < matchingConditions.list.count; ++i)
  // {
  //   MatchingUeCondPerSubItem_t *item = matchingConditions.list.array[i];
  //   if (!item)
  //     continue;

  //   if (item->testCondInfo.testType.present == TestCond_Type_PR_sNSSAI)
  //   {
  //     logln("[KPM SUB] Found matching condition on sNSSAI");
  //   }
  // }

  *granularityPeriod = gp;

  if (f1)
  {
    int n = f1->measInfoList.list.count;
    if (n > 0)
    {
      MeasurementInfoItem_t **arr = (MeasurementInfoItem_t **)f1->measInfoList.list.array;

      for (int i = 0; i < n; ++i)
      {
        MeasurementInfoItem_t *mi = arr[i];
        if (!mi)
          continue;

        MeasurementType_t *mt = &mi->measType;
        if (mt->present == MeasurementType_PR_measName && mt->choice.measName.buf && mt->choice.measName.size > 0)
        {
          out_meas.emplace_back((char *)mt->choice.measName.buf,
                                mt->choice.measName.size);
        }
      }
    }
  }

  logln("[KPM SUB] Extracted %d measurement names, granularityPeriod=%ld",
        (int)out_meas.size(), (long)*granularityPeriod);
  return true;
}

/* ============================================================
 * SUBSCRIPTION CALLBACK
 * ============================================================ */
void callback_kpm_subscription_request(E2AP_PDU_t *sub_req_pdu)
{
  logln("[CALLBACK KPM SUBSCRIPTION REQUEST] Received Subscription Request\n");
  RICsubscriptionRequest_t orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  int count = orig_req.protocolIEs.list.count;
  xer_fprint((stdout), &asn_DEF_RICsubscriptionRequest, &orig_req);
  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;

  logln("Processing Subscription Request...count %d\n", count);

  RICsubscriptionRequest_IEs__value_PR pres;

  long reqRequestorId = -1;
  long reqInstanceId = -1;
  long reqActionId = -1;

  // std::vector<long> actionIdsAccept;
  // std::vector<long> actionIdsReject;
  std::vector<long> acceptedActions; // actionId
  std::vector<long> rejectedActions; // actionId
  bool any_metric_not_allowed = false;
  GranularityPeriod_t granularityPeriod = 0;
  long reportingPeriod = 0;

  for (int i = 0; i < count; i++)
  {
    RICsubscriptionRequest_IEs_t *next_ie = ies[i];
    pres = next_ie->value.present;

    switch (pres)
    {
    case RICsubscriptionRequest_IEs__value_PR_RICrequestID:
    {
      RICrequestID_t reqId = next_ie->value.choice.RICrequestID;
      long requestorId = reqId.ricRequestorID;
      long instanceId = reqId.ricInstanceID;
      reqRequestorId = requestorId;
      reqInstanceId = instanceId;
      break;
    }
    case RICsubscriptionRequest_IEs__value_PR_RANfunctionID:
    {
      long ranFuncId = next_ie->value.choice.RANfunctionID;
      if (ranFuncId != 2) // KPM
      {
        logln("Received Subscription Request for unsupported RANfunctionID %ld, ignoring\n", ranFuncId);
        return;
      }
      break;
    }
    case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails:
    {
      RICsubscriptionDetails_t subDetails = next_ie->value.choice.RICsubscriptionDetails;
      RICactions_ToBeSetup_List_t actionList = subDetails.ricAction_ToBeSetup_List;
      // Recupero event trigger definition
      RICeventTriggerDefinition_t eventTriggerDefinition = subDetails.ricEventTriggerDefinition;
      E2SM_KPM_EventTriggerDefinition_t *ad = nullptr;
      asn_dec_rval_t dr = aper_decode(nullptr,
                                      &asn_DEF_E2SM_KPM_EventTriggerDefinition, (void **)&ad, eventTriggerDefinition.buf, eventTriggerDefinition.size, 0, 0);

      if (dr.code != RC_OK || !ad)
      {
        logln("[KPM SUB] TriggerDefinition decode failed: code=%d consumed=%zu", dr.code, dr.consumed);
        return;
      }
      if (ad->eventDefinition_formats.present == E2SM_KPM_EventTriggerDefinition__eventDefinition_formats_PR_eventDefinition_Format1)
      {
        E2SM_KPM_EventTriggerDefinition_Format1_t *f1 = ad->eventDefinition_formats.choice.eventDefinition_Format1;
        if (f1)
        {
          reportingPeriod = f1->reportingPeriod;
          logln("[KPM SUB] Extracted reportingPeriod=%ld from EventTriggerDefinition Format1", (long)reportingPeriod);
        }
      }

      RICaction_ToBeSetup_ItemIEs_t **item_array =
          (RICaction_ToBeSetup_ItemIEs_t **)actionList.list.array;

      for (int j = 0; j < actionList.list.count; j++)
      {
        RICaction_ToBeSetup_ItemIEs_t *next_item = item_array[j];

        RICactionID_t actionId =
            next_item->value.choice.RICaction_ToBeSetup_Item.ricActionID;
        RICactionType_t actionType =
            next_item->value.choice.RICaction_ToBeSetup_Item.ricActionType;

        logln("[KPM SUB] Found RICaction: id=%ld type=%ld (0=report)", (long)actionId, (long)actionType);

        // Consideriamo solo REPORT (coerente con KPM)
        if (actionType != RICactionType_report)
        {
          logln("[KPM SUB] Action %ld rejected: type %ld is not REPORT", (long)actionId, (long)actionType);
          any_metric_not_allowed = true;
          rejectedActions.push_back(actionId);
          continue;
        }
        OCTET_STRING_t *act_def = next_item->value.choice.RICaction_ToBeSetup_Item.ricActionDefinition;
        std::vector<std::string> meas_names;
        if (!extract_meas_names_from_kpm_actiondef(act_def, meas_names, &granularityPeriod))
        {
          logln("[KPM SUB] Action %ld rejected: unable to extract measurement names from ActionDefinition", (long)actionId);
          any_metric_not_allowed = true;
          rejectedActions.push_back(actionId);
          continue;
        }

        logln("[KPM SUB] Action %ld has %d requested measurements", (long)actionId, (int)meas_names.size());

        for (auto &m : meas_names)
        {
          if (std::find(getAllowedKPI().begin(), getAllowedKPI().end(), m) == getAllowedKPI().end())
          {
            logln("[KPM SUB] Measurement '%s' not allowed by simulator, action %ld will be rejected", m.c_str(), (long)actionId);
            any_metric_not_allowed = true;
            rejectedActions.push_back(actionId);
          }
        }
        if (!any_metric_not_allowed)
        {
          logln("[KPM SUB] Action %ld accepted", (long)actionId);
          acceptedActions.push_back(actionId);
          reqActionId = actionId; // salva l'ultimo actionId accettato
        }
        else
        {
          logln("[KPM SUB] any_metric_not_allowed already true, action %ld considered rejected", (long)actionId);
        }
      }
      break;
    }
    default:
      break;
    }
  }

  logln("After Processing Subscription Request\n");
  logln("requestorId %ld\n", reqRequestorId);
  logln("instanceId %ld\n", reqInstanceId);

  // Costruisci e invia la Subscription Response (success)
  E2AP_PDU *e2ap_pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
  if (e2ap_pdu == NULL)
  {
    logln("calloc failed for e2ap_pdu\n");
    return;
  }

  long *accept_array = acceptedActions.empty() ? NULL : acceptedActions.data();
  long *reject_array = rejectedActions.empty() ? NULL : rejectedActions.data();
  int accept_size = (int)acceptedActions.size();
  int reject_size = (int)rejectedActions.size();

  // Se c'è almeno un azione rifiutata, rifiuto tutto
  if (any_metric_not_allowed)
  {
    logln("At least one action not allowed, rejecting subscription (accepted=%d, rejected=%d)\n", accept_size, reject_size);
    generate_e2apv2_subscription_failure(e2ap_pdu, reqRequestorId, reqInstanceId, 2, reject_array, reject_size);
    e2.encode_and_send_sctp_data(e2ap_pdu);
    return;
  }

  logln("All actions allowed, accepting subscription\n");
  generate_e2apv2_subscription_response_success(e2ap_pdu, accept_array, reject_array, accept_size, reject_size, reqRequestorId, reqInstanceId, 2);
  e2.encode_and_send_sctp_data(e2ap_pdu);

  long funcId = 2; // KPM
  if (accept_size > 0 && reqActionId >= 0)
  {
    SubscriptionKey key{reqRequestorId, reqInstanceId, funcId, reqActionId};
    start_kpm_worker(key, reqRequestorId, reqInstanceId, funcId, reqActionId, granularityPeriod);
  }
  else
  {
    logln("No valid action to start KPM worker (accepted=%d, actionId=%ld)\n", accept_size, reqActionId);
  }
}

void registerKPMfunctionDefinition()
{
  // RANfunction-Description KPM v3
  E2SM_KPM_RANfunction_Description_t *ranfunc_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  if (ranfunc_desc == NULL)
  {
    logln("calloc failed for ranfunc_desc\n");
    return;
  }

  // Deve riempire i campi secondo KPM v3
  encode_kpm_function_description(ranfunc_desc);
  logln("KPM RANfunction-Description XER dump:");
  xer_fprint(stdout, &asn_DEF_E2SM_KPM_RANfunction_Description, ranfunc_desc);
  // Codifica della RANfunction-Description
  const size_t e2smbuffer_size = 16384;
  uint8_t *e2smbuffer = (uint8_t *)calloc(1, e2smbuffer_size);
  if (e2smbuffer == NULL)
  {
    logln("calloc failed for e2smbuffer\n");
    return;
  }

  asn_enc_rval_t er = asn_encode_to_buffer(
      NULL, ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_KPM_RANfunction_Description,
      ranfunc_desc, e2smbuffer, e2smbuffer_size);

  if (er.encoded < 0)
  {
    logln("Encoding failed: %s\n", er.failed_type ? er.failed_type->name : "unknown");
    free(e2smbuffer);
    return;
  }

  // Crea OCTET_STRING per registrazione nel simulatore
  OCTET_STRING_t *ranfunc_ostr = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  if (ranfunc_ostr == NULL)
  {
    logln("calloc failed for ranfunc_ostr\n");
    free(e2smbuffer);
    return;
  }
  ranfunc_ostr->buf = (uint8_t *)calloc(1, (size_t)er.encoded);
  ranfunc_ostr->size = (er.encoded > 0) ? (size_t)er.encoded : 0;
  if (ranfunc_ostr->buf == NULL)
  {
    logln("calloc failed for ranfunc_ostr->buf\n");
    free(ranfunc_ostr);
    free(e2smbuffer);
    return;
  }
  memcpy(ranfunc_ostr->buf, e2smbuffer, ranfunc_ostr->size);

  // Registra la SM (FunctionID=2) e callback subscription
  e2.register_e2sm(2, ranfunc_ostr);
  e2.register_subscription_callback(2, &callback_kpm_subscription_request);
  const char *oid = "1.3.6.1.4.1.53148.1.1.2.2";
  PrintableString_t *ranFunctionOIDe = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(ranFunctionOIDe, oid, strlen(oid));
  e2.register_e2sm_oid(2, ranFunctionOIDe);

  // Self-test: decodifica della RANfunction-Description appena encodata
  E2SM_KPM_RANfunction_Description_t *check = NULL;
  asn_dec_rval_t dr = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_RANfunction_Description, (void **)&check, ranfunc_ostr->buf, ranfunc_ostr->size);
  if (dr.code != RC_OK)
  {
    logln("Self-test decode KPM FAILED (%d) at byte %zu\n", dr.code, dr.consumed);
  }
  else
  {
    logln("Self-test decode KPM OK (consumed=%zu)\n", dr.consumed);
  }

  // Non servono più questi buffer locali
  free(e2smbuffer);
}
