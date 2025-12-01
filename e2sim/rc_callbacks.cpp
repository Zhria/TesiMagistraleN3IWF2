
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>   // shutdown()
#include <netinet/sctp.h> // SCTP
#include <nlohmann/json.hpp>
#include <atomic>
#include <signal.h>
#include <unordered_set>
#include <algorithm>
#include <map>
#include <mutex>
#include <memory>
#include <chrono>
#include <string_view>
#include <cstdint>
#include <sstream>
#include <utility>
#include <unordered_map>
#include <cmath>
#include <limits>
#include <functional>
#include <cctype>
#include <optional>
#include <curl/curl.h>

#include "rc_callbacks.hpp"
#include "subscription_key.hpp"
#include "app_state.hpp"

extern "C"
{
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "E2AP-PDU.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "RICactionType.h"
#include "RICcontrolRequest.h"
#include "RICcontrolAcknowledge.h"
#include "RICcontrolFailure.h"
#include "RICcontrolAckRequest.h"
#include "RICcallProcessID.h"
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
#include "E2SM-RC-ActionDefinition.h"
#include "E2SM-RC-IndicationHeader.h"
#include "E2SM-RC-IndicationHeader-Format1.h"
#include "E2SM-RC-IndicationMessage.h"
#include "E2SM-RC-IndicationMessage-Format1.h"
#include "E2SM-RC-IndicationMessage-Format1-Item.h"
#include "E2SM-RC-ControlHeader.h"
#include "E2SM-RC-ControlHeader-Format1.h"
#include "UEID-GNB.h"
#include "UEID-GNB-DU.h"
#include "UEID-GNB-CU-UP.h"
#include "UEID-NG-ENB.h"
#include "E2SM-RC-ControlMessage.h"
#include "E2SM-RC-ControlMessage-Format1.h"
#include "E2SM-RC-ControlMessage-Format1-Item.h"
#include "E2SM-RC-ControlOutcome.h"
#include "E2SM-RC-ControlOutcome-Format1.h"
#include "E2SM-RC-ControlOutcome-Format1-Item.h"
#include "RANParameter-ValueType-Choice-ElementTrue.h"
#include "RANParameter-ValueType-Choice-ElementFalse.h"
#include "RANParameter-ValueType-Choice-List.h"
#include "RANParameter-ValueType-Choice-Structure.h"
#include "RANParameter-Value.h"
#include "RANParameter-STRUCTURE.h"
#include "RANParameter-STRUCTURE-Item.h"
#include "RANParameter-LIST.h"
#include "INTEGER.h"
#include "RIC-EventTriggerCondition-ID.h"
#include "Cause.h"
}

#include "n3iwf_utils.hpp"
#include "n3iwf_data.hpp"

#include "encode_rc.hpp"
#include "encode_e2apv2.hpp"
#include "e2sim_defs.h"
#include "rc_ids.hpp"

using namespace std;
using json = nlohmann::json;
static E2Sim e2;
E2SM_RC_RANFunctionDefinition_t *g_rc_ranfunc_def = nullptr;

struct RcWorkerCtx
{
    std::shared_ptr<std::atomic_bool> stop_flag;
    std::thread worker;

    RcWorkerCtx() = default;
    RcWorkerCtx(std::thread &&thr, std::shared_ptr<std::atomic_bool> flag)
        : stop_flag(std::move(flag)), worker(std::move(thr)) {}

    RcWorkerCtx(const RcWorkerCtx &) = delete;
    RcWorkerCtx &operator=(const RcWorkerCtx &) = delete;
    RcWorkerCtx(RcWorkerCtx &&) noexcept = default;
    RcWorkerCtx &operator=(RcWorkerCtx &&) noexcept = default;
};

static std::mutex g_rc_workers_mutex;
static std::map<SubscriptionKey, RcWorkerCtx> g_rc_workers;

namespace
{

    constexpr size_t kMaxReportedAssociations = 8;
    constexpr int64_t kSignalUnknown = std::numeric_limits<int64_t>::min();
    constexpr bool kRcSubscriptionsEnabled = false;
    constexpr int kDefaultRcEventTriggerFormat = 4;

    static const std::vector<long> &default_rc_report_param_ids()
    {
        static const std::vector<long> ids = []
        {
            std::vector<long> out;
            auto metrics = getAllowedReportMetricsRC();
            out.reserve(metrics.size());
            for (const auto &kv : metrics)
            {
                out.push_back(kv.first);
            }
            return out;
        }();
        return ids;
    }

    struct RcRateState
    {
        RcCountersSnapshot counters{};
        std::chrono::steady_clock::time_point timestamp{};
    };

    struct RcDerivedMetrics
    {
        double ul_volume_kbits{0.0};
        double dl_volume_kbits{0.0};
        double ul_throughput_bps{0.0};
        double dl_throughput_bps{0.0};
        int64_t signal_dbm{kSignalUnknown};
    };

    static std::string normalize_mac_string(const std::string &mac)
    {
        if (mac.empty())
        {
            return {};
        }
        std::string out;
        out.reserve(mac.size());
        for (char c : mac)
        {
            if (c == ':' || c == '-' || c == '.')
            {
                continue;
            }
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return out;
    }

    static std::string build_assoc_key(const RcAssociationSnapshot &assoc)
    {
        if (!assoc.mac.empty())
        {
            return normalize_mac_string(assoc.mac);
        }
        if (!assoc.ue_ip.empty())
        {
            return assoc.ue_ip;
        }
        if (!assoc.station.mac.empty())
        {
            return normalize_mac_string(assoc.station.mac);
        }
        if (!assoc.station.ip.empty())
        {
            return assoc.station.ip;
        }
        return {};
    }

    static uint64_t delta_or_zero(uint64_t current, uint64_t previous)
    {
        return (current >= previous) ? (current - previous) : 0;
    }

    static long clamp_double_to_long(double value)
    {
        if (!std::isfinite(value))
        {
            return 0;
        }
        if (value > static_cast<double>(std::numeric_limits<long>::max()))
        {
            return std::numeric_limits<long>::max();
        }
        if (value < static_cast<double>(std::numeric_limits<long>::min()))
        {
            return std::numeric_limits<long>::min();
        }
        return static_cast<long>(std::llround(value));
    }

    static bool parse_first_integer(const std::string &text, int64_t &out)
    {
        if (text.empty())
        {
            return false;
        }
        std::istringstream iss(text);
        long long value = 0;
        iss >> value;
        if (iss.fail())
        {
            return false;
        }
        out = static_cast<int64_t>(value);
        return true;
    }

    static bool extract_signal_from_map(const std::map<std::string, std::string> &source,
                                        std::initializer_list<const char *> keys,
                                        int64_t &out)
    {
        for (const char *key : keys)
        {
            auto it = source.find(key);
            if (it == source.end())
            {
                continue;
            }
            if (parse_first_integer(it->second, out))
            {
                return true;
            }
        }
        return false;
    }

    static int64_t extract_signal_dbm(const RcAssociationSnapshot &assoc)
    {
        int64_t value = 0;
        if (extract_signal_from_map(assoc.station.fields, {"iw.signal", "signal", "iw.signal_avg", "signal_avg"}, value))
        {
            return value;
        }
        if (extract_signal_from_map(assoc.station.hostapd, {"signal"}, value))
        {
            return value;
        }
        if (extract_signal_from_map(assoc.station.station_dump, {"signal", "signal_avg"}, value))
        {
            return value;
        }
        return kSignalUnknown;
    }

    static RcDerivedMetrics build_derived_metrics(
        const RcAssociationSnapshot &assoc,
        const std::chrono::steady_clock::time_point &now,
        std::unordered_map<std::string, RcRateState> &rate_state)
    {
        RcDerivedMetrics derived;
        derived.ul_volume_kbits = static_cast<double>(assoc.counters.incoming_octets) * 8.0 / 1000.0;
        derived.dl_volume_kbits = static_cast<double>(assoc.counters.transmit_octets) * 8.0 / 1000.0;
        derived.signal_dbm = extract_signal_dbm(assoc);

        const std::string key = build_assoc_key(assoc);
        if (!key.empty())
        {
            auto &entry = rate_state[key];
            if (entry.timestamp.time_since_epoch().count() != 0)
            {
                double elapsed = std::chrono::duration<double>(now - entry.timestamp).count();
                if (elapsed > 0.0)
                {
                    const auto delta_ul = delta_or_zero(assoc.counters.incoming_octets, entry.counters.incoming_octets);
                    derived.ul_throughput_bps = static_cast<double>(delta_ul) * 8.0 / elapsed;

                    const auto delta_dl = delta_or_zero(assoc.counters.transmit_octets, entry.counters.transmit_octets);
                    derived.dl_throughput_bps = static_cast<double>(delta_dl) * 8.0 / elapsed;
                }
            }
            entry.counters = assoc.counters;
            entry.timestamp = now;
        }

        return derived;
    }

    static bool map_param_to_value(long param_id,
                                   const RcAssociationSnapshot &assoc,
                                   const RcDerivedMetrics &metrics,
                                   long &out_value)
    {
        switch (param_id)
        {
        case 41001:
        {
            if (assoc.ue.ran_ue_ngap_id >= 0)
            {
                out_value = assoc.ue.ran_ue_ngap_id;
                return true;
            }
            if (assoc.ue.amf_ue_ngap_id >= 0)
            {
                out_value = assoc.ue.amf_ue_ngap_id;
                return true;
            }
            const std::string key = build_assoc_key(assoc);
            if (!key.empty())
            {
                out_value = static_cast<long>(std::hash<std::string>{}(key) & 0x7fffffff);
                return true;
            }
            return false;
        }
        case 41003:
            out_value = assoc.ue.rrc_establishment_cause;
            return true;
        case 42001:
            out_value = (metrics.signal_dbm != kSignalUnknown) ? metrics.signal_dbm : 0;
            return true;
        case 43001:
            out_value = clamp_double_to_long(metrics.ul_throughput_bps);
            return true;
        case 43002:
            out_value = clamp_double_to_long(metrics.dl_throughput_bps);
            return true;
        case 44001:
            out_value = clamp_double_to_long(metrics.ul_volume_kbits);
            return true;
        case 44002:
            out_value = clamp_double_to_long(metrics.dl_volume_kbits);
            return true;
        default:
            return false;
        }
    }

    static bool append_param_item(E2SM_RC_IndicationMessage_Format1_t *fmt1, long param_id, long value)
    {
        if (!fmt1)
        {
            return false;
        }
        auto *item = (E2SM_RC_IndicationMessage_Format1_Item *)calloc(
            1, sizeof(E2SM_RC_IndicationMessage_Format1_Item));
        if (!item)
        {
            return false;
        }
        item->ranParameter_ID = param_id;
        item->ranParameter_valueType.present = RANParameter_ValueType_PR_ranP_Choice_ElementTrue;
        item->ranParameter_valueType.choice.ranP_Choice_ElementTrue =
            (RANParameter_ValueType_Choice_ElementTrue *)calloc(
                1, sizeof(RANParameter_ValueType_Choice_ElementTrue));
        if (!item->ranParameter_valueType.choice.ranP_Choice_ElementTrue)
        {
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage_Format1_Item, item);
            return false;
        }
        auto *val =
            &item->ranParameter_valueType.choice.ranP_Choice_ElementTrue->ranParameter_value;
        val->present = RANParameter_Value_PR_valueInt;
        val->choice.valueInt = value;
        ASN_SEQUENCE_ADD(&fmt1->ranP_Reported_List.list, item);
        return true;
    }

    void stop_rc_worker_internal(const SubscriptionKey &key)
    {
        std::shared_ptr<std::atomic_bool> stop_flag;
        std::thread worker;

        {
            std::lock_guard<std::mutex> lock(g_rc_workers_mutex);
            auto it = g_rc_workers.find(key);
            if (it == g_rc_workers.end())
            {
                return;
            }
            stop_flag = it->second.stop_flag;
            worker = std::move(it->second.worker);
            g_rc_workers.erase(it);
        }

        if (stop_flag)
        {
            stop_flag->store(true, std::memory_order_relaxed);
        }
        if (worker.joinable())
        {
            worker.join();
        }
    }

    void stop_all_rc_workers_internal()
    {
        std::vector<std::thread> to_join;

        {
            std::lock_guard<std::mutex> lock(g_rc_workers_mutex);
            for (auto &entry : g_rc_workers)
            {
                if (entry.second.stop_flag)
                {
                    entry.second.stop_flag->store(true, std::memory_order_relaxed);
                }
                to_join.emplace_back(std::move(entry.second.worker));
            }
            g_rc_workers.clear();
        }

        for (auto &t : to_join)
        {
            if (t.joinable())
            {
                t.join();
            }
        }
    }

} // namespace

void stop_rc_worker(const SubscriptionKey &key)
{
    stop_rc_worker_internal(key);
}

void stop_all_rc_workers()
{
    stop_all_rc_workers_internal();
}

namespace
{

    struct ControlOutcomeField
    {
        long id;
        std::string_view value;
    };

    struct RcParamValue
    {
        long id{0};
        std::string name;
        RANParameter_ValueType_PR value_type{RANParameter_ValueType_PR_NOTHING};
        std::string printable_value;
        bool has_int{false};
        long int_value{0};
    };

    struct RcControlContext
    {
        long requestor_id{-1};
        long instance_id{-1};
        long ran_function_id{-1};
        long control_action_id{-1};
        long style_type{-1};
        bool ack_requested{false};
        OCTET_STRING_t call_process_id{0};
        bool call_process_id_present{false};
        std::string ue_identity;
        long header_ran_ue_id{-1};
        long header_amf_ue_id{-1};
        bool header_ran_ue_id_present{false};
        bool header_amf_ue_id_present{false};
        std::vector<RcParamValue> params;
    };

    struct RcControlExecutionResult
    {
        bool success{false};
        std::string status;
        std::vector<std::pair<long, std::string>> outcome_items;
        long cause_value{CauseRICrequest_action_not_supported};
    };

    struct N3iwfTriggerResponse
    {
        bool success{false};
        std::string description;
        long failure_cause{CauseRICrequest_control_failed_to_execute};
    };

    static std::string_view get_param_value(const RcControlContext &ctx, long id);

    static std::once_flag g_curl_init_flag;

    namespace
    {

        constexpr const char *kDefaultHandoverUrl = "http://127.0.0.1:9085/rc/handover";
        constexpr long kHttpTimeoutMs = 5000;

    } // namespace

    static void ensure_curl_initialized()
    {
        std::call_once(g_curl_init_flag, []
                       { curl_global_init(CURL_GLOBAL_DEFAULT); });
    }

    static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp)
    {
        size_t total = size * nmemb;
        auto *buffer = static_cast<std::string *>(userp);
        buffer->append(static_cast<const char *>(contents), total);
        return total;
    }

    static bool http_post_json(const std::string &url,
                               const std::string &payload,
                               long &http_code,
                               std::string &response_body,
                               std::string &error_message)
    {
        ensure_curl_initialized();
        CURL *curl = curl_easy_init();
        if (!curl)
        {
            error_message = "curl_easy_init failed";
            return false;
        }

        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        logln("[RC CTRL] HTTP POST %s", url.c_str());
        logln("[RC CTRL] Payload: %s", payload.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kHttpTimeoutMs);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "e2sim-rc");

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            error_message = curl_easy_strerror(res);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return false;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return true;
    }

    static int hex_value(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F')
            return 10 + (c - 'A');
        return -1;
    }

    static bool hex_to_bytes(std::string_view text, std::vector<uint8_t> &out)
    {
        std::string cleaned;
        cleaned.reserve(text.size());
        for (size_t i = 0; i < text.size(); ++i)
        {
            char c = text[i];
            if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-')
            {
                continue;
            }
            if (c == '0' && (i + 1) < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X'))
            {
                ++i; // skip the 'x'
                continue;
            }
            cleaned.push_back(c);
        }

        if (cleaned.empty() || (cleaned.size() % 2) != 0)
        {
            return false;
        }

        out.clear();
        out.reserve(cleaned.size() / 2);
        for (size_t i = 0; i < cleaned.size(); i += 2)
        {
            int hi = hex_value(cleaned[i]);
            int lo = hex_value(cleaned[i + 1]);
            if (hi < 0 || lo < 0)
            {
                out.clear();
                return false;
            }
            out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return !out.empty();
    }

    static std::string base64_encode(const uint8_t *data, size_t len)
    {
        static const char kBase64Alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((len + 2) / 3) * 4);
        size_t i = 0;
        while (i + 2 < len)
        {
            uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                              (static_cast<uint32_t>(data[i + 1]) << 8) |
                              static_cast<uint32_t>(data[i + 2]);
            out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
            out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
            out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
            out.push_back(kBase64Alphabet[triple & 0x3F]);
            i += 3;
        }
        if (i < len)
        {
            uint32_t triple = static_cast<uint32_t>(data[i]) << 16;
            if ((i + 1) < len)
            {
                triple |= static_cast<uint32_t>(data[i + 1]) << 8;
            }
            out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
            out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
            if ((i + 1) < len)
            {
                out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
            }
            else
            {
                out.push_back('=');
            }
            out.push_back('=');
        }
        return out;
    }

    static std::string bytes_to_base64(const std::vector<uint8_t> &bytes)
    {
        if (bytes.empty())
        {
            return {};
        }
        return base64_encode(bytes.data(), bytes.size());
    }

    static std::string string_to_base64(const std::string &value)
    {
        if (value.empty())
        {
            return {};
        }
        return base64_encode(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    }

    static std::string convert_hex_or_ascii_to_base64(const std::string &value)
    {
        std::vector<uint8_t> bytes;
        if (hex_to_bytes(value, bytes))
        {
            return bytes_to_base64(bytes);
        }
        return string_to_base64(value);
    }

    // Generic callback to accumulate ASN.1 print output into a std::string.
    static int asn_string_append_cb(const void *buffer, size_t size, void *app_key)
    {
        auto *out = static_cast<std::string *>(app_key);
        if (!out || !buffer || size == 0)
        {
            return 0;
        }
        out->append(static_cast<const char *>(buffer), size);
        return 0;
    }

    // Convert an OCTET STRING (e.g. RANUEID_t) to a human-readable string using ASN.1 printer.
    static std::string octet_string_to_string(const OCTET_STRING_t &oct)
    {
        std::string out;
        OCTET_STRING_print(&asn_DEF_OCTET_STRING, &oct, 0, asn_string_append_cb, &out);
        return out;
    }

    // Convert a BIT STRING to a human-readable string using ASN.1 printer.
    static std::string bit_string_to_string(const BIT_STRING_t &bs)
    {
        std::string out;
        BIT_STRING_print(&asn_DEF_BIT_STRING, &bs, 0, asn_string_append_cb, &out);
        return out;
    }

    static std::optional<int64_t> resolve_ran_ue_ngap_id(const RcControlContext &ctx)
    {
        if (ctx.header_ran_ue_id_present)
        {
            return ctx.header_ran_ue_id;
        }
        if (ctx.header_amf_ue_id_present)
        {
            auto assoc = findRcAssociationByAmfUeId(ctx.header_amf_ue_id);
            if (assoc && assoc->ue.ran_ue_ngap_id >= 0)
            {
                return assoc->ue.ran_ue_ngap_id;
            }
        }

        return std::nullopt;
    }

    static std::string handover_endpoint_url()
    {
        const char *env = std::getenv("RC_HANDOVER_TRIGGER_URL");
        if (env && *env)
        {
            return std::string(env);
        }
        return std::string(kDefaultHandoverUrl);
    }

    static void release_octet_string(OCTET_STRING_t &str)
    {
        if (str.buf)
        {
            free(str.buf);
            str.buf = nullptr;
        }
        str.size = 0;
    }

    static std::string rc_param_name(long id)
    {
        static const auto metrics = getAllowedControlMetricsRC();
        auto it = metrics.find(id);
        if (it != metrics.end())
        {
            return it->second;
        }
        return std::string("RAN Parameter ") + std::to_string(id);
    }

    static std::string describe_ueid(const UEID_t *ue)
    {
        if (!ue)
        {
            return "<unknown UE>";
        }
        switch (ue->present)
        {
        case UEID_PR_gNB_UEID:
            if (ue->choice.gNB_UEID && ue->choice.gNB_UEID->ran_UEID)
            {
                const auto *ran = ue->choice.gNB_UEID->ran_UEID;
                return std::string("gNB-UEID ran=") + octet_string_to_string(*ran);
            }
            return "gNB-UEID";
        case UEID_PR_gNB_DU_UEID:
            return "gNB-DU-UEID";
        case UEID_PR_gNB_CU_UP_UEID:
            return "gNB-CU-UP-UEID";
        case UEID_PR_ng_eNB_UEID:
            return "ng-eNB-UEID";
        default:
            return std::string("UEID type=") + std::to_string(ue->present);
        }
    }

    static const RcParamValue *find_param(const RcControlContext &ctx, long id)
    {
        for (const auto &p : ctx.params)
        {
            if (p.id == id)
            {
                return &p;
            }
        }
        return nullptr;
    }

    static std::string_view get_param_value(const RcControlContext &ctx, long id)
    {
        const RcParamValue *param = find_param(ctx, id);
        return param ? std::string_view(param->printable_value) : std::string_view{};
    }

    static std::optional<long> get_param_int_value(const RcControlContext &ctx, long id)
    {
        const RcParamValue *param = find_param(ctx, id);
        if (!param)
        {
            return std::nullopt;
        }
        if (param->has_int)
        {
            return param->int_value;
        }
        int64_t value = 0;
        if (parse_first_integer(param->printable_value, value))
        {
            return static_cast<long>(value);
        }
        return std::nullopt;
    }

    static std::string get_target_identifier_value(const RcControlContext &ctx)
    {
        std::string value = std::string(get_param_value(ctx, kRcParamTargetCellPci));
        if (!value.empty())
        {
            return value;
        }
        value = std::string(get_param_value(ctx, kRcLegacyParamTargetGNbId));
        return value;
    }

    static std::string ran_value_to_string(const RANParameter_Value_t &value)
    {
        switch (value.present)
        {
        case RANParameter_Value_PR_valueBoolean:
            return value.choice.valueBoolean ? "true" : "false";
        case RANParameter_Value_PR_valueInt:
            return std::to_string(value.choice.valueInt);
        case RANParameter_Value_PR_valueReal:
            return std::to_string(value.choice.valueReal);
        case RANParameter_Value_PR_valueBitS:
            return bit_string_to_string(value.choice.valueBitS);
        case RANParameter_Value_PR_valueOctS:
            return octet_string_to_string(value.choice.valueOctS);
        case RANParameter_Value_PR_valuePrintableString:
            if (value.choice.valuePrintableString.buf && value.choice.valuePrintableString.size > 0)
            {
                return std::string(reinterpret_cast<char *>(value.choice.valuePrintableString.buf),
                                   value.choice.valuePrintableString.size);
            }
            return "";
        default:
            return "<unsupported>";
        }
    }

    static const RANParameter_Value_t *get_element_value(const RANParameter_ValueType_t &valueType)
    {
        if (valueType.present == RANParameter_ValueType_PR_ranP_Choice_ElementTrue &&
            valueType.choice.ranP_Choice_ElementTrue)
        {
            return &valueType.choice.ranP_Choice_ElementTrue->ranParameter_value;
        }
        if (valueType.present == RANParameter_ValueType_PR_ranP_Choice_ElementFalse &&
            valueType.choice.ranP_Choice_ElementFalse)
        {
            return valueType.choice.ranP_Choice_ElementFalse->ranParameter_value;
        }
        return nullptr;
    }

    static std::string describe_ran_value_type(const RANParameter_ValueType_t &valueType)
    {
        switch (valueType.present)
        {
        case RANParameter_ValueType_PR_ranP_Choice_ElementTrue:
            if (const auto *val = get_element_value(valueType))
            {
                return ran_value_to_string(*val);
            }
            return "<element-null>";
        case RANParameter_ValueType_PR_ranP_Choice_ElementFalse:
            if (const auto *val = get_element_value(valueType))
            {
                return ran_value_to_string(*val);
            }
            return "<element-false>";
        case RANParameter_ValueType_PR_ranP_Choice_Structure:
            if (valueType.choice.ranP_Choice_Structure &&
                valueType.choice.ranP_Choice_Structure->ranParameter_Structure &&
                valueType.choice.ranP_Choice_Structure->ranParameter_Structure->sequence_of_ranParameters)
            {
                auto &seq = valueType.choice.ranP_Choice_Structure->ranParameter_Structure->sequence_of_ranParameters->list;
                return std::string("<structure items=") + std::to_string(seq.count) + ">";
            }
            return "<structure-null>";
        case RANParameter_ValueType_PR_ranP_Choice_List:
            if (valueType.choice.ranP_Choice_List && valueType.choice.ranP_Choice_List->ranParameter_List)
            {
                auto &structures = valueType.choice.ranP_Choice_List->ranParameter_List->list_of_ranParameter.list;
                return std::string("<list structures=") + std::to_string(structures.count) + ">";
            }
            return "<list-null>";
        default:
            return "<unsupported-value-type>";
        }
    }

    static bool octet_string_to_long(const OCTET_STRING_t *oct, long &out)
    {
        if (!oct || !oct->buf || oct->size <= 0 || oct->size > 8)
        {
            return false;
        }
        uint64_t value = 0;
        for (int i = 0; i < oct->size; ++i)
        {
            value = (value << 8) | static_cast<uint8_t>(oct->buf[i]);
        }
        out = static_cast<long>(value);
        return true;
    }

    static void update_ctx_ids_from_ueid(const UEID_t *ueid, RcControlContext &ctx)
    {
        if (!ueid)
        {
            return;
        }
        auto set_amf = [&](const AMF_UE_NGAP_ID_t &src)
        {
            long value = 0;
            if (asn_INTEGER2long(&src, &value) == 0)
            {
                ctx.header_amf_ue_id = value;
                ctx.header_amf_ue_id_present = true;
                logln("[RC CONTROL] Header AMF UE NGAP ID=%ld", value);
            }
        };
        auto set_ran = [&](const OCTET_STRING_t *oct)
        {
            long value = 0;
            if (octet_string_to_long(oct, value))
            {
                ctx.header_ran_ue_id = value;
                ctx.header_ran_ue_id_present = true;
                logln("[RC CONTROL] Header RAN UE ID=%ld", value);
            }
        };

        switch (ueid->present)
        {
        case UEID_PR_gNB_UEID:
            if (ueid->choice.gNB_UEID)
            {
                set_amf(ueid->choice.gNB_UEID->amf_UE_NGAP_ID);
                if (ueid->choice.gNB_UEID->ran_UEID)
                {
                    set_ran(ueid->choice.gNB_UEID->ran_UEID);
                }
            }
            break;
        case UEID_PR_gNB_DU_UEID:
            if (ueid->choice.gNB_DU_UEID && ueid->choice.gNB_DU_UEID->ran_UEID)
            {
                set_ran(ueid->choice.gNB_DU_UEID->ran_UEID);
            }
            break;
        case UEID_PR_gNB_CU_UP_UEID:
            if (ueid->choice.gNB_CU_UP_UEID && ueid->choice.gNB_CU_UP_UEID->ran_UEID)
            {
                set_ran(ueid->choice.gNB_CU_UP_UEID->ran_UEID);
            }
            break;
        case UEID_PR_ng_eNB_UEID:
            if (ueid->choice.ng_eNB_UEID)
            {
                set_amf(ueid->choice.ng_eNB_UEID->amf_UE_NGAP_ID);
            }
            break;
        default:
            break;
        }
    }

    static void append_param_entry(RcControlContext &ctx, long id, const RANParameter_ValueType_t &valueType)
    {
        RcParamValue entry;
        entry.id = id;
        entry.name = rc_param_name(id);
        entry.value_type = valueType.present;
        entry.printable_value = describe_ran_value_type(valueType);
        if (const auto *val = get_element_value(valueType))
        {
            if (val->present == RANParameter_Value_PR_valueInt)
            {
                entry.has_int = true;
                entry.int_value = val->choice.valueInt;
            }
        }
        ctx.params.push_back(std::move(entry));

        if (valueType.present == RANParameter_ValueType_PR_ranP_Choice_Structure)
        {
            auto *structure_choice = valueType.choice.ranP_Choice_Structure;
            if (structure_choice &&
                structure_choice->ranParameter_Structure &&
                structure_choice->ranParameter_Structure->sequence_of_ranParameters)
            {
                auto &seq = structure_choice->ranParameter_Structure->sequence_of_ranParameters->list;
                for (int i = 0; i < seq.count; ++i)
                {
                    auto *item = static_cast<RANParameter_STRUCTURE_Item_t *>(seq.array[i]);
                    if (!item || !item->ranParameter_valueType)
                    {
                        continue;
                    }
                    append_param_entry(ctx,
                                       item->ranParameter_ID,
                                       *item->ranParameter_valueType);
                }
            }
        }
        else if (valueType.present == RANParameter_ValueType_PR_ranP_Choice_List)
        {
            auto *list_choice = valueType.choice.ranP_Choice_List;
            if (list_choice && list_choice->ranParameter_List)
            {
                auto &structures = list_choice->ranParameter_List->list_of_ranParameter.list;
                for (int si = 0; si < structures.count; ++si)
                {
                    auto *structure = static_cast<RANParameter_STRUCTURE_t *>(structures.array[si]);
                    if (!structure || !structure->sequence_of_ranParameters)
                    {
                        continue;
                    }
                    auto &seq = structure->sequence_of_ranParameters->list;
                    for (int i = 0; i < seq.count; ++i)
                    {
                        auto *item = static_cast<RANParameter_STRUCTURE_Item_t *>(seq.array[i]);
                        if (!item || !item->ranParameter_valueType)
                        {
                            continue;
                        }
                        append_param_entry(ctx,
                                           item->ranParameter_ID,
                                           *item->ranParameter_valueType);
                    }
                }
            }
        }
    }

    static bool is_supported_control_param(long id)
    {
        static const std::unordered_set<long> kSupportedIds = []
        {
            std::unordered_set<long> ids;
            const auto metrics = getAllowedControlMetricsRC();
            for (const auto &kv : metrics)
            {
                if (kv.first == kRcOutcomeStatus || kv.first == kRcOutcomeNotes || kv.first == kRcParamUeId)
                {
                    continue; // outcome-only parameters are not part of control messages
                }
                ids.insert(kv.first);
            }
            return ids;
        }();
        return kSupportedIds.find(id) != kSupportedIds.end();
    }

    static bool decode_rc_control_header(const RICcontrolHeader_t &hdr, RcControlContext &ctx, std::string &err)
    {
        logln("[RC CONTROL] Decoding ControlHeader (size=%ld)", hdr.size);
        logln("Received ControlHeader PER dump:");

        // Alcuni xApp inviano il ControlHeader come CHOICE completo, altri solo come Format1:
        // proviamo più decodifiche (aligned/unaligned, CHOICE/Format1) finché troviamo uno stile valido.
        E2SM_RC_ControlHeader_Format1_t *fmt1 = nullptr;
        E2SM_RC_ControlHeader_t *choice_holder = nullptr;
        bool fmt1_from_choice = false;


        const asn_dec_rval_t ret = asn_decode(NULL,ATS_ALIGNED_BASIC_PER,&asn_DEF_E2SM_RC_ControlHeader,(void **)&choice_holder,hdr.buf,hdr.size);
        if (ret.code != RC_OK)
        {
            return false;
        }
        if (choice_holder->ric_controlHeader_formats.present != E2SM_RC_ControlHeader__ric_controlHeader_formats_PR_controlHeader_Format1)
        {
            return false;
        }
        fmt1 = choice_holder->ric_controlHeader_formats.choice.controlHeader_Format1;
        xer_fprint(stdout, &asn_DEF_E2SM_RC_ControlHeader, choice_holder);
        
        ctx.style_type = fmt1->ric_Style_Type;
        ctx.control_action_id = fmt1->ric_ControlAction_ID;
        ctx.ue_identity = describe_ueid(&fmt1->ueID);
        update_ctx_ids_from_ueid(&fmt1->ueID, ctx);

        logln("[RC CONTROL] Header OK style=%ld action=%ld ue=%s",
              ctx.style_type,ctx.control_action_id,ctx.ue_identity.c_str());

        return true;
    }

    static bool decode_rc_control_message(const OCTET_STRING_t &msg, RcControlContext &ctx, std::string &err)
    {
        E2SM_RC_ControlMessage_t *decoded = nullptr;
        auto fail = [&](const std::string &msg_text) -> bool
        {
            err = msg_text;
            if (decoded)
            {
                ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, decoded);
                decoded = nullptr;
            }
            return false;
        };
        asn_dec_rval_t dr = asn_decode(nullptr, ATS_ALIGNED_BASIC_PER,&asn_DEF_E2SM_RC_ControlMessage, (void **)&decoded, msg.buf, msg.size);
        if (dr.code != RC_OK || !decoded)
        {
            return fail("Unable to decode E2SM RC ControlMessage");
        }
        logln("[RC CONTROL] Raw ControlMessage PER dump:");
        xer_fprint(stdout, &asn_DEF_E2SM_RC_ControlMessage, decoded);
        logln("[RC CONTROL] ControlMessage decoded (size=%ld)", msg.size);
        if (decoded->ric_controlMessage_formats.present !=
            E2SM_RC_ControlMessage__ric_controlMessage_formats_PR_controlMessage_Format1)
        {
            return fail("Unsupported ControlMessage format");
        }
        auto *fmt1 = decoded->ric_controlMessage_formats.choice.controlMessage_Format1;
        if (!fmt1)
        {
            return fail("ControlMessage Format1 payload missing");
        }
        for (int i = 0; i < fmt1->ranP_List.list.count; ++i)
        {
            auto *item = (E2SM_RC_ControlMessage_Format1_Item *)fmt1->ranP_List.list.array[i];
            if (!item)
            {
                return fail("ControlMessage list contains null entry");
            }
            if (!is_supported_control_param(item->ranParameter_ID))
            {
                logln("[RC CONTROL] Skipping unsupported parameter ID %ld", item->ranParameter_ID);
                continue;
            }
            if (item->ranParameter_valueType.present == RANParameter_ValueType_PR_NOTHING)
            {
                logln("[RC CONTROL] Parameter ID %ld missing value", item->ranParameter_ID);
                continue;
            }
            append_param_entry(ctx, item->ranParameter_ID, item->ranParameter_valueType);
        }
        if (ctx.params.empty())
        {
            return fail("RC control message does not contain any RAN parameters");
        }
        const bool has_target_gnb = !get_target_identifier_value(ctx).empty();
        if (!has_target_gnb)
        {
            return fail("RC control message missing target gNB/NR CGI parameters");
        }
        logln("[RC CONTROL] Message OK params=%zu targetGNb=%d",
              ctx.params.size(),
              has_target_gnb ? 1 : 0);
        for (const auto &param : ctx.params)
        {
            logln("[RC CONTROL]   Param ID=%ld (%s) type=%d value=%s",
                  param.id,
                  param.name.c_str(),
                  static_cast<int>(param.value_type),
                  param.printable_value.c_str());
        }
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlMessage, decoded);
        return true;
    }

    static bool build_handover_request_payload(const RcControlContext &ctx,json &payload, std::string &error)
    {
        logln("[RC CONTROL] Preparing HO payload for UE=%s", ctx.ue_identity.c_str());
        auto ran_ue = resolve_ran_ue_ngap_id(ctx);
        if (!ran_ue)
        {
            error = "Unable to resolve ranUeNgapId for UE";
            logln("[RC CONTROL] %s", error.c_str());
            return false;
        }

        std::string target_gnb = get_target_identifier_value(ctx);
        if (target_gnb.empty())
        {
            error = "Missing target gNB/NR CGI identifier";
            logln("[RC CONTROL] %s", error.c_str());
            return false;
        }

        std::string target_id_b64 = convert_hex_or_ascii_to_base64(target_gnb);
        if (target_id_b64.empty())
        {
            error = "Unable to encode target identifier";
            logln("[RC CONTROL] %s", error.c_str());
            return false;
        }

        payload = json::object();
        payload["ranUeNgapId"] = *ran_ue;
        payload["directForwarding"] = false;
        payload["targetId"] = target_id_b64;

        std::string metadata_ue = ctx.ue_identity;
        std::string target_pci = std::string(get_param_value(ctx, kRcParamTargetCellPci));
        std::string ho_cause = std::string(get_param_value(ctx, kRcParamHoCause));
        auto target_pci_value = get_param_int_value(ctx, kRcParamTargetCellPci);
        auto ho_cause_value = get_param_int_value(ctx, kRcParamHoCause);

        json metadata_json = json::object();
        if (!metadata_ue.empty())
        {
            metadata_json["ueIdentity"] = metadata_ue;
        }
        metadata_json["targetGnbRaw"] = target_gnb;
        if (target_pci_value)
        {
            metadata_json["targetCellPci"] = *target_pci_value;
        }
        else if (!target_pci.empty())
        {
            metadata_json["targetCellPci"] = target_pci;
        }
        if (ho_cause_value)
        {
            metadata_json["hoCause"] = *ho_cause_value;
        }
        else if (!ho_cause.empty())
        {
            metadata_json["hoCause"] = ho_cause;
        }
        payload["metadata"] = metadata_json;
        logln("[RC CONTROL] HO payload ready: ranUe=%ld targetLen=%zu", *ran_ue, target_gnb.size());
        return true;
    }

    static N3iwfTriggerResponse trigger_n3iwf_handover(const RcControlContext &ctx,const std::string &command_desc)
    {
        logln("[RC CONTROL] Triggering HO via N3IWF: %s", command_desc.c_str());

        N3iwfTriggerResponse response;
        json payload;
        std::string payload_error;
        if (!build_handover_request_payload(ctx, payload, payload_error))
        {
            response.success = false;
            response.description = payload_error;
            response.failure_cause = CauseRICrequest_control_message_invalid;
            return response;
        }

        std::string url = handover_endpoint_url();
        std::string payload_str = payload.dump();
        long http_code = 0;
        std::string http_body;
        std::string curl_error;
        logln("[RC CONTROL] POST %s (%zu bytes)", url.c_str(), payload_str.size());
        if (!http_post_json(url, payload_str, http_code, http_body, curl_error))
        {
            response.success = false;
            response.description = "HTTP POST failed: " + curl_error;
            response.failure_cause = CauseRICrequest_control_failed_to_execute;
            return response;
        }

        if (http_code >= 200 && http_code < 300)
        {
            logln("[RC CONTROL] HO HTTP success code=%ld", http_code);
            response.success = true;
            if (!http_body.empty())
            {
                response.description = std::string("HTTP ") + std::to_string(http_code) + ": " + http_body;
            }
            else
            {
                response.description = "HTTP " + std::to_string(http_code) + " (no body)";
            }
            return response;
        }

        response.success = false;
        response.failure_cause = CauseRICrequest_control_failed_to_execute;
        response.description = "N3IWF HTTP " + std::to_string(http_code);
        logln("[RC CONTROL] HO HTTP failure code=%ld", http_code);
        if (!http_body.empty())
        {
            response.description += ": " + http_body;
        }
        return response;
    }

    static RcControlExecutionResult execute_rc_control_command(const RcControlContext &ctx)
    {
        RcControlExecutionResult result;
        if (ctx.control_action_id != kRcControlActionIdHandover)
        {
            result.status = "Unsupported control action ID " + std::to_string(ctx.control_action_id);
            result.outcome_items.emplace_back(kRcOutcomeStatus, result.status);
            result.cause_value = CauseRICrequest_action_not_supported;
            return result;
        }

        const std::string ue = ctx.ue_identity;
        const std::string target_pci = std::string(get_param_value(ctx, kRcParamTargetCellPci));
        const std::string target_gnb = get_target_identifier_value(ctx);
        const std::string ho_cause = std::string(get_param_value(ctx, kRcParamHoCause));

        std::ostringstream oss;
        oss << "HO command for UE=" << (ue.empty() ? "<unknown>" : ue);
        if (!target_gnb.empty())
        {
            oss << " target-gNB=" << target_gnb;
        }
        if (!target_pci.empty())
        {
            oss << " target-PCI=" << target_pci;
        }
        if (!ho_cause.empty())
        {
            oss << " cause=" << ho_cause;
        }
        const std::string command_desc = oss.str();
        auto ho_response = trigger_n3iwf_handover(ctx, command_desc);

        if (ho_response.success)
        {
            result.success = true;
            result.status = command_desc;
            result.outcome_items.emplace_back(kRcOutcomeStatus, "ACK: " + command_desc);
            if (!ho_cause.empty())
            {
                result.outcome_items.emplace_back(kRcOutcomeNotes, "Cause=" + ho_cause);
            }
            if (!ho_response.description.empty())
            {
                result.outcome_items.emplace_back(kRcOutcomeNotes, ho_response.description);
            }
            return result;
        }

        const std::string failure_detail = ho_response.description.empty()
                                               ? "N3IWF rejected the handover trigger"
                                               : ho_response.description;
        result.success = false;
        result.cause_value = ho_response.failure_cause;
        result.status = command_desc.empty() ? failure_detail : (command_desc + " - " + failure_detail);
        result.outcome_items.emplace_back(kRcOutcomeStatus, "FAIL: " + failure_detail);
        if (!ho_cause.empty())
        {
            result.outcome_items.emplace_back(kRcOutcomeNotes, "Cause=" + ho_cause);
        }
        return result;
    }

    static bool encode_rc_control_outcome_view(const ControlOutcomeField *fields,
                                               size_t count,
                                               std::vector<uint8_t> &buffer)
    {
        buffer.clear();
        if (count == 0)
        {
            return true;
        }

        E2SM_RC_ControlOutcome_t *outcome = (E2SM_RC_ControlOutcome_t *)calloc(1, sizeof(*outcome));
        if (!outcome)
        {
            return false;
        }
        outcome->ric_controlOutcome_formats.present =
            E2SM_RC_ControlOutcome__ric_controlOutcome_formats_PR_controlOutcome_Format1;
        auto *fmt1 = (E2SM_RC_ControlOutcome_Format1_t *)calloc(1, sizeof(E2SM_RC_ControlOutcome_Format1_t));
        if (!fmt1)
        {
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlOutcome, outcome);
            return false;
        }
        outcome->ric_controlOutcome_formats.choice.controlOutcome_Format1 = fmt1;

        for (size_t i = 0; i < count; ++i)
        {
            const auto &field = fields[i];
            auto *entry = (E2SM_RC_ControlOutcome_Format1_Item *)calloc(1, sizeof(E2SM_RC_ControlOutcome_Format1_Item));
            if (!entry)
                continue;
            entry->ranParameter_ID = field.id;
            entry->ranParameter_value.present = RANParameter_Value_PR_valuePrintableString;
            OCTET_STRING_fromBuf(&entry->ranParameter_value.choice.valuePrintableString,
                                 field.value.data(),
                                 field.value.size());
            ASN_SEQUENCE_ADD(&fmt1->ranP_List.list, entry);
        }

        buffer.resize(MAX_SCTP_BUFFER);
        asn_enc_rval_t er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER,
                                                 &asn_DEF_E2SM_RC_ControlOutcome,
                                                 outcome, buffer.data(), buffer.size());
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlOutcome, outcome);
        if (er.encoded < 0)
        {
            buffer.clear();
            return false;
        }
        buffer.resize(er.encoded);
        return true;
    }

    static bool encode_rc_control_outcome(const std::vector<std::pair<long, std::string>> &items,
                                          std::vector<uint8_t> &buffer)
    {
        if (items.empty())
        {
            buffer.clear();
            return true;
        }
        std::vector<ControlOutcomeField> fields;
        fields.reserve(items.size());
        for (const auto &item : items)
        {
            fields.push_back(ControlOutcomeField{item.first, item.second});
        }
        return encode_rc_control_outcome_view(fields.data(), fields.size(), buffer);
    }

    static bool encode_rc_control_outcome_single(long id,
                                                 std::string_view value,
                                                 std::vector<uint8_t> &buffer)
    {
        if (value.empty())
        {
            buffer.clear();
            return true;
        }
        const ControlOutcomeField field{id, value};
        return encode_rc_control_outcome_view(&field, 1, buffer);
    }

} // namespace

// Raccoglie gli ID dichiarati in RANFunctionDefinition-Report, opzionalmente
// filtrando per ric_ReportStyle_Type == report_style_type (se >0).
static void collect_declared_report_param_ids(const E2SM_RC_RANFunctionDefinition_t *def,
                                              int report_style_type, // 0 = qualunque style
                                              std::unordered_set<long> &out_ids)
{
    out_ids.clear();
    if (!def || !def->ranFunctionDefinition_Report)
        return;

    const RANFunctionDefinition_Report_t *rep = def->ranFunctionDefinition_Report;
    const auto &lst = rep->ric_ReportStyle_List.list;
    for (int i = 0; i < lst.count; ++i)
    {
        const RANFunctionDefinition_Report_Item_t *it =
            (const RANFunctionDefinition_Report_Item_t *)lst.array[i];
        if (!it)
            continue;

        // se richiesto, filtra per style specifico
        if (report_style_type > 0 && (int)it->ric_ReportStyle_Type != report_style_type)
        {
            continue;
        }

        // lista dei RAN params supportati per quello style
        const auto *rp_list = it->ran_ReportParameters_List;
        if (!rp_list)
            continue;

        const auto &rp = rp_list->list;
        for (int j = 0; j < rp.count; ++j)
        {
            const Report_RANParameter_Item_t *p =
                (const Report_RANParameter_Item_t *)rp.array[j];
            if (!p)
                continue;
            out_ids.insert((long)p->ranParameter_ID);
        }
    }
}

// Verifica che tutti gli ID richiesti compaiano tra quelli dichiarati.
// Se 'out_missing' non è nullptr, riporta quelli mancanti.
// report_style_type: 0 = qualunque style; >0 = filtra su uno specifico.
bool all_ids_declared_in_ranFunctionDefinition(const std::vector<long> &ids, int report_style_type, std::vector<long> *out_missing)
{
    if (out_missing)
        out_missing->clear();
    if (!g_rc_ranfunc_def)
        return false;

    std::unordered_set<long> declared;
    collect_declared_report_param_ids(g_rc_ranfunc_def, report_style_type, declared);

    bool ok = true;
    for (long id : ids)
    {
        if (declared.find(id) == declared.end())
        {
            ok = false;
            if (out_missing)
                out_missing->push_back(id);
        }
    }
    return ok;
}

bool decode_rc_event_trigger(RICeventTriggerDefinition_t *et, int *out_format)
{
    if (!et || !et->buf || et->size == 0 || !out_format)
        return false;

    // Decodifica PER non allineata (Packed Encoding Rules) come da E2AP
    asn_dec_rval_t rval;
    E2SM_RC_EventTrigger *decoded = NULL;

    rval = aper_decode_complete(
        NULL,                          // codec context
        &asn_DEF_E2SM_RC_EventTrigger, // descrittore ASN.1
        (void **)&decoded,
        et->buf,
        et->size);

    if (rval.code != RC_OK || decoded == NULL)
    {
        fprintf(stderr, "[decode_rc_event_trigger] Decode failed: %s (consumed %zu bytes)\n",
                rval.code == RC_FAIL ? "RC_FAIL" : "RC_WMORE",
                rval.consumed);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
        return false;
    }

    // Identifica quale formato è presente
    if (decoded->ric_eventTrigger_formats.present ==
        E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format1)
    {
        *out_format = 1;
    }
    else if (decoded->ric_eventTrigger_formats.present ==
             E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format2)
    {
        *out_format = 2;
    }
    else if (decoded->ric_eventTrigger_formats.present ==
             E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format3)
    {
        *out_format = 3;
    }
    else if (decoded->ric_eventTrigger_formats.present ==
             E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format4)
    {
        *out_format = 4;
    }
    else
    {
        fprintf(stderr, "[decode_rc_event_trigger] Unknown format in EventTrigger\n");
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
        return false;
    }

    xer_fprint(stdout, &asn_DEF_E2SM_RC_EventTrigger, decoded);

    // Cleanup
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
    return true;
}

/**
 * Decodifica E2SM-RC Action Definition e accetta solo il Format 1 (REPORT).
 * Estrae la lista di RAN Parameter ID richiesti dalla xApp.
 *
 * @param ad                 OCTET STRING (E2AP) con la Action Definition RC
 * @param out_ids            output: lista di RAN Parameter ID richiesti
 * @return true se decodifica ok e format==1, altrimenti false
 */
bool decode_rc_actiondef_format1(const OCTET_STRING_t *ad, std::vector<long> &out_ids)
{
    out_ids.clear();

    if (!ad || !ad->buf || ad->size == 0)
    {
        fprintf(stderr, "[decode_rc_actiondef_format1] invalid input\n");
        return false;
    }

    E2SM_RC_ActionDefinition_t *decoded = nullptr;
    asn_dec_rval_t rval = aper_decode_complete(
        /*opt_codec_ctx*/ nullptr,
        &asn_DEF_E2SM_RC_ActionDefinition,
        (void **)&decoded,
        ad->buf,
        ad->size);

    if (rval.code != RC_OK || !decoded)
    {
        fprintf(stderr, "[decode_rc_actiondef_format1] PER decode failed (%s), consumed=%zu\n",
                (rval.code == RC_WMORE ? "RC_WMORE" : "RC_FAIL"), rval.consumed);
        if (decoded)
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    // Verifica che il CHOICE sia il Format 1 (REPORT) come da 9.2.1.2.1. :contentReference[oaicite:3]{index=3}
    auto &fmt = decoded->ric_actionDefinition_formats;
    if (fmt.present != E2SM_RC_ActionDefinition__ric_actionDefinition_formats_PR_actionDefinition_Format1)
    {
        fprintf(stderr, "[decode_rc_actiondef_format1] not Format1 (present=%d)\n", fmt.present);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    // Estrai i RAN Parameter ID dalla lista "Parameters to be Reported"
    E2SM_RC_ActionDefinition_Format1 *f1 = fmt.choice.actionDefinition_Format1;
    if (!f1)
    {
        fprintf(stderr, "[decode_rc_actiondef_format1] NULL Format1 pointer\n");
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    auto lst = f1->ranP_ToBeReported_List.list;
    for (int i = 0; i < lst.count; ++i)
    {
        E2SM_RC_ActionDefinition_Format1_Item *item = (E2SM_RC_ActionDefinition_Format1_Item *)lst.array[i];
        if (!item)
            continue;

        // Ogni item ha: RAN Parameter ID (obbligatorio) + RAN Parameter Definition (opzionale).
        // "Solo ID dichiarati in RAN Function Definition" sono validi. :contentReference[oaicite:4]{index=4}
        long id = (long)item->ranParameter_ID;
        out_ids.push_back(id);

        // Se ti serve: l'item->ranParameter_Definition (opzionale) ti dice se il parametro è STRUCTURE/LIST
        // e, se non incluso per STRUCTURE/LIST, la spec assume "tutti i sub-parameters supportati". :contentReference[oaicite:5]{index=5}
    }

    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
    return true;
}

/*
static void run_rc_report_loop(const SubscriptionKey &key,
                               int et_format,
                               std::vector<long> param_ids,
                               const std::shared_ptr<std::atomic_bool> &stop_token)
{
    logln("RC report loop start: requestorId=%ld instanceId=%ld ranFunctionId=%ld actionId=%ld (ET format %d)",
             key.requestorId, key.instanceId, key.ranFunctionId, key.actionId, et_format);

    if (param_ids.empty()) {
        logln("RC report loop: no RAN Parameter IDs requested, will send heartbeat indications only");
    }

    std::unordered_map<std::string, RcRateState> rate_state;
    long seq_num = 1;
    const auto period = std::chrono::milliseconds(1000);

    while (true) {
        if (g_app_stop.load(std::memory_order_relaxed)) {
            break;
        }
        if (stop_token && stop_token->load(std::memory_order_relaxed)) {
            break;
        }

        auto *hdr = (E2SM_RC_IndicationHeader_t *)calloc(1, sizeof(E2SM_RC_IndicationHeader_t));
        auto *hdr_fmt1 = (E2SM_RC_IndicationHeader_Format1 *)calloc(1, sizeof(E2SM_RC_IndicationHeader_Format1));
        if (!hdr || !hdr_fmt1) {
            logln("RC report loop: calloc failed for IndicationHeader");
            free(hdr);
            free(hdr_fmt1);
            std::this_thread::sleep_for(period);
            continue;
        }

        hdr_fmt1->ric_eventTriggerCondition_ID =
            (RIC_EventTriggerCondition_ID_t *)calloc(1, sizeof(RIC_EventTriggerCondition_ID_t));
        if (hdr_fmt1->ric_eventTriggerCondition_ID) {
            *hdr_fmt1->ric_eventTriggerCondition_ID = et_format;
        }

        hdr->ric_indicationHeader_formats.present =
            E2SM_RC_IndicationHeader__ric_indicationHeader_formats_PR_indicationHeader_Format1;
        hdr->ric_indicationHeader_formats.choice.indicationHeader_Format1 = hdr_fmt1;

        uint8_t hdr_buf[MAX_SCTP_BUFFER];
        asn_enc_rval_t hdr_enc = asn_encode_to_buffer(
            nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_RC_IndicationHeader,
            hdr, hdr_buf, sizeof(hdr_buf));
        if (hdr_enc.encoded < 0) {
            logln("RC report loop: header encode failed (%s)",
                     hdr_enc.failed_type ? hdr_enc.failed_type->name : "unknown");
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationHeader, hdr);
            std::this_thread::sleep_for(period);
            continue;
        }

        E2SM_RC_IndicationMessage_t *msg =
            (E2SM_RC_IndicationMessage_t *)calloc(1, sizeof(E2SM_RC_IndicationMessage_t));
        auto *fmt1 = (E2SM_RC_IndicationMessage_Format1 *)calloc(1, sizeof(E2SM_RC_IndicationMessage_Format1));
        if (!msg || !fmt1) {
            logln("RC report loop: calloc failed for IndicationMessage");
            free(fmt1);
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationHeader, hdr);
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage, msg);
            std::this_thread::sleep_for(period);
            continue;
        }

        msg->ric_indicationMessage_formats.present =
            E2SM_RC_IndicationMessage__ric_indicationMessage_formats_PR_indicationMessage_Format1;
        msg->ric_indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;

        const auto now = std::chrono::steady_clock::now();

        if (!param_ids.empty()) {
            auto associations = getRcAssociations();
            size_t reported = 0;
            for (const auto &assoc : associations) {
                if (reported >= kMaxReportedAssociations) {
                    break;
                }
                RcDerivedMetrics metrics = build_derived_metrics(assoc, now, rate_state);
                bool added = false;
                for (long param_id : param_ids) {
                    long value = 0;
                    if (!map_param_to_value(param_id, assoc, metrics, value)) {
                        continue;
                    }
                    if (append_param_item(fmt1, param_id, value)) {
                        added = true;
                    }
                }
                if (added) {
                    ++reported;
                }
            }
        }

        if (fmt1->ranP_Reported_List.list.count == 0) {
            // At least add a heartbeat parameter with ID 0 if nothing else is available
            auto *item = (E2SM_RC_IndicationMessage_Format1_Item *)calloc(
                1, sizeof(E2SM_RC_IndicationMessage_Format1_Item));
            if (item) {
                item->ranParameter_ID = 0;
                item->ranParameter_valueType.present = RANParameter_ValueType_PR_ranP_Choice_ElementTrue;
                item->ranParameter_valueType.choice.ranP_Choice_ElementTrue =
                    (RANParameter_ValueType_Choice_ElementTrue *)calloc(
                        1, sizeof(RANParameter_ValueType_Choice_ElementTrue));
                if (item->ranParameter_valueType.choice.ranP_Choice_ElementTrue) {
                    auto *val = &item->ranParameter_valueType.choice.ranP_Choice_ElementTrue->ranParameter_value;
                    val->present = RANParameter_Value_PR_valueInt;
                    val->choice.valueInt = seq_num;
                    ASN_SEQUENCE_ADD(&fmt1->ranP_Reported_List.list, item);
                } else {
                    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage_Format1_Item, item);
                }
            }
        }

        uint8_t msg_buf[MAX_SCTP_BUFFER];
        asn_enc_rval_t msg_enc = asn_encode_to_buffer(
            nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_RC_IndicationMessage,
            msg, msg_buf, sizeof(msg_buf));
        if (msg_enc.encoded < 0) {
            logln("RC report loop: message encode failed (%s)",
                     msg_enc.failed_type ? msg_enc.failed_type->name : "unknown");
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationHeader, hdr);
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage, msg);
            std::this_thread::sleep_for(period);
            continue;
        }

        E2AP_PDU *pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
        if (!pdu) {
            logln("RC report loop: calloc failed for E2AP PDU");
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationHeader, hdr);
            ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage, msg);
            std::this_thread::sleep_for(period);
            continue;
        }

        generate_e2apv2_indication_request_parameterized(
            pdu,
            key.requestorId,
            key.instanceId,
            key.ranFunctionId,
            key.actionId,
            seq_num,
            hdr_buf,
            static_cast<int>(hdr_enc.encoded),
            msg_buf,
            static_cast<int>(msg_enc.encoded));

        e2.encode_and_send_sctp_data(pdu);

        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationMessage, msg);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_IndicationHeader, hdr);

        ++seq_num;
        std::this_thread::sleep_for(period);
    }

    logln("RC report loop stop: requestorId=%ld instanceId=%ld ranFunctionId=%ld actionId=%ld",
             key.requestorId, key.instanceId, key.ranFunctionId, key.actionId);
}*/
/*
static void start_rc_worker(const SubscriptionKey &key,
                            int et_format,
                            const std::vector<long> &param_ids)
{
    stop_rc_worker_internal(key);

    auto stop_flag = std::make_shared<std::atomic_bool>(false);
    std::thread worker([key, et_format, param_ids, stop_flag]() {
        run_rc_report_loop(key, et_format, param_ids, stop_flag);
    });

    std::lock_guard<std::mutex> lock(g_rc_workers_mutex);
    g_rc_workers.emplace(key, RcWorkerCtx{std::move(worker), stop_flag});
}*/

/*
void start_rc_report_pipeline(const SubscriptionKey &key,
                              int et_format,
                              const std::vector<long> &ad_param_ids)
{
    logln("Starting RC report pipeline for key[%ld:%ld:%ld:%ld] with %zu RAN Param IDs (ET format %d)",
             key.requestorId, key.instanceId, key.ranFunctionId, key.actionId,
             ad_param_ids.size(), et_format);

    start_rc_worker(key, et_format, ad_param_ids);
}*/
/*
static void reject_rc_subscription_request(const RICsubscriptionRequest_t &orig_req) {
    long reqRequestorId = -1;
    long reqInstanceId = -1;
    std::vector<long> requestedActions;

    auto **ies = (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;
    int count = orig_req.protocolIEs.list.count;

    for (int i = 0; i < count; ++i) {
        RICsubscriptionRequest_IEs_t *ie = ies ? ies[i] : nullptr;
        if (!ie) {
            continue;
        }
        switch (ie->value.present) {
            case RICsubscriptionRequest_IEs__value_PR_RICrequestID:
                reqRequestorId = ie->value.choice.RICrequestID.ricRequestorID;
                reqInstanceId = ie->value.choice.RICrequestID.ricInstanceID;
                break;
            case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
                auto &sd = ie->value.choice.RICsubscriptionDetails;
                auto **aitems =
                    (RICaction_ToBeSetup_ItemIEs_t **)sd.ricAction_ToBeSetup_List.list.array;
                for (int j = 0; j < sd.ricAction_ToBeSetup_List.list.count; ++j) {
                    auto *item = aitems ? aitems[j] : nullptr;
                    if (!item) {
                        continue;
                    }
                    requestedActions.push_back(
                        item->value.choice.RICaction_ToBeSetup_Item.ricActionID);
                }
                break;
            }
            default:
                break;
        }
    }

    if (reqRequestorId < 0 || reqInstanceId < 0) {
        logln("RC subscription reject: missing RICrequestID, dropping request");
        return;
    }

    E2AP_PDU_t *rsp = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if (!rsp) {
        logln("RC subscription reject: calloc failed for response PDU");
        return;
    }
    const long *reject_array = requestedActions.empty() ? nullptr : requestedActions.data();
    generate_e2apv2_subscription_failure(
        rsp,
        reqRequestorId,
        reqInstanceId,
        3,
        reject_array,
        (int)requestedActions.size());
    e2.encode_and_send_sctp_data(rsp);
}

static void ensure_rc_worker_from_control(const RcControlContext &ctx) {
    if (ctx.requestor_id < 0 || ctx.instance_id < 0 || ctx.ran_function_id < 0) {
        logln("RC control: missing identifiers, cannot start RC report pipeline");
        return;
    }
    long actionId = (ctx.control_action_id > 0) ? ctx.control_action_id : kRcControlActionIdHandover;
    const auto &params = default_rc_report_param_ids();
    if (params.empty()) {
        logln("RC control: no default RC report parameters configured, skipping report pipeline");
        return;
    }
    SubscriptionKey key{ctx.requestor_id, ctx.instance_id, ctx.ran_function_id, actionId};
    logln("RC control: starting RC report pipeline triggered by control request key[%ld:%ld:%ld:%ld]",
          key.requestorId, key.instanceId, key.ranFunctionId, key.actionId);
    start_rc_report_pipeline(key, kDefaultRcEventTriggerFormat, params);
}

*/
/* ============================================================
 * SUBSCRIPTION CALLBACK RC
 * ============================================================
void callback_rc_subscription_request(E2AP_PDU_t *sub_req_pdu)
{
  logln("[CALLBACK RC SUBSCRIPTION REQUEST] Received Subscription Request\n");
  RICsubscriptionRequest_t &orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  if (!kRcSubscriptionsEnabled) {
    logln("[CALLBACK RC SUBSCRIPTION REQUEST] RC reporting via subscription is disabled; returning failure");
    reject_rc_subscription_request(orig_req);
    return;
  }

  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;
  int count = orig_req.protocolIEs.list.count;

  long reqRequestorId = -1, reqInstanceId = -1;
  std::vector<long> acceptedActions, rejectedActions;
  bool reject_all = false;

  // Helper outputs
  int et_format_detected = 0;     // 1..4 per RC (noi vogliamo 4 per UE change)
  int report_style_hint = 0;      // opzionale: dedotto da AD (p.es. 4 per UE Info)
  std::map<long, std::vector<long>> action_param_map; // actionId -> RAN Parameter IDs richiesti dal RIC

  // Step 1: parse IEs
  for (int i = 0; i < count; ++i) {
    RICsubscriptionRequest_IEs_t *ie = ies[i];
    switch (ie->value.present) {
      case RICsubscriptionRequest_IEs__value_PR_RICrequestID: {
        reqRequestorId = ie->value.choice.RICrequestID.ricRequestorID;
        reqInstanceId  = ie->value.choice.RICrequestID.ricInstanceID;
        break;
      }
      case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
        RICsubscriptionDetails_t &sd = ie->value.choice.RICsubscriptionDetails;

        // Step 1a: decode RC Event Trigger Definition (expect Format 4 per UE change)
        if (!decode_rc_event_trigger(&sd.ricEventTriggerDefinition, &et_format_detected)) {
          logln("Invalid RC Event Trigger Definition\n");
          reject_all = true;
          break;
        }

        // Step 1b: iterate actions
        RICactions_ToBeSetup_List_t &alist = sd.ricAction_ToBeSetup_List;
        auto **aitems = (RICaction_ToBeSetup_ItemIEs_t **)alist.list.array;

        for (int j = 0; j < alist.list.count; ++j) {
          auto *it = aitems[j];
          long actionId   = it->value.choice.RICaction_ToBeSetup_Item.ricActionID;
          auto actionType = it->value.choice.RICaction_ToBeSetup_Item.ricActionType;

          // In RC qui gestiamo REPORT; altri tipi (INSERT/POLICY/CONTROL) se vuoi
          if (actionType != RICactionType_report) {
            rejectedActions.push_back(actionId);
            continue;
          }

          OCTET_STRING_t *ad_oct = it->value.choice.RICaction_ToBeSetup_Item.ricActionDefinition;
          std::vector<long> ids_req;

          if (!decode_rc_actiondef_format1(ad_oct, ids_req)) {
            logln("ActionDef not RC-Format1 or decode failed\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          // Step 1c: validate that each requested RAN parameter ID was declared
          if (!all_ids_declared_in_ranFunctionDefinition(ids_req,report_style_hint,nullptr)) {
            logln("Requested RAN Parameter not declared in RANFunctionDefinition\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          // (opz) vincoli incrociati ET/ReportStyle: per Style 4 ci aspettiamo IM=2 ecc.
          if (et_format_detected == 4 && report_style_hint != 4) {
            logln("ET=UE-Change but ActionDef does not target UE-Info style\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          action_param_map[actionId] = ids_req;
          acceptedActions.push_back(actionId);
        }
        break;
      }
      default:
        break;
    }
  }

  // Step 2: send the response
  E2AP_PDU *rsp = (E2AP_PDU *)calloc(1, sizeof(*rsp));

  if (reject_all || acceptedActions.empty()) {
    // E2AP cause tipiche: Event Trigger not supported / Action not supported / Invalid Info Request
    generate_e2apv2_subscription_failure(
        rsp, reqRequestorId, reqInstanceId,
        (int)rejectedActions.size(),
        rejectedActions.empty()? NULL : rejectedActions.data(),
        (int)rejectedActions.size());
    e2.encode_and_send_sctp_data(rsp);
    return;
  }

  generate_e2apv2_subscription_response_success(
      rsp,
      acceptedActions.data(),
      rejectedActions.empty()? NULL : rejectedActions.data(),
      (int)acceptedActions.size(),
      (int)rejectedActions.size(),
      reqRequestorId, reqInstanceId,3);
  e2.encode_and_send_sctp_data(rsp);

  // Step 3: start the REPORT producer
  long ranFunctionId = 3; // RC RAN Function
  for (long actionId : acceptedActions) {
    SubscriptionKey key{reqRequestorId, reqInstanceId, ranFunctionId, actionId};
    const auto it = action_param_map.find(actionId);
    const std::vector<long> empty_vec;
    const std::vector<long> &params = (it != action_param_map.end()) ? it->second : empty_vec;
    start_rc_report_pipeline(key, et_format_detected, params);
  }
}
*/

void callback_rc_control_request(E2AP_PDU_t *ctrl_req_pdu)
{
    RcControlContext ctx;
    bool header_ok = false;
    bool message_ok = false;
    std::string decode_error;

    struct OctetStringGuard
    {
        OCTET_STRING_t &ref;
        explicit OctetStringGuard(OCTET_STRING_t &r) : ref(r) {}
        ~OctetStringGuard() { release_octet_string(ref); }
    } guard{ctx.call_process_id};

    if (!ctrl_req_pdu || ctrl_req_pdu->present != E2AP_PDU_PR_initiatingMessage)
    {
        logln("[RC CONTROL] Invalid PDU received");
        return;
    }
    logln("[RC CONTROL] Received RICcontrolRequest");

    RICcontrolRequest_t &orig_req =
        ctrl_req_pdu->choice.initiatingMessage->value.choice.RICcontrolRequest;

    xer_fprint(stdout, &asn_DEF_RICcontrolRequest, &orig_req);

    auto **ies = (RICcontrolRequest_IEs_t **)orig_req.protocolIEs.list.array;
    int ie_count = orig_req.protocolIEs.list.count;

    for (int i = 0; i < ie_count; ++i)
    {
        RICcontrolRequest_IEs_t *ie = ies[i];
        switch (ie->value.present)
        {
        case RICcontrolRequest_IEs__value_PR_RICrequestID:
            ctx.requestor_id = ie->value.choice.RICrequestID.ricRequestorID;
            ctx.instance_id = ie->value.choice.RICrequestID.ricInstanceID;
            break;
        case RICcontrolRequest_IEs__value_PR_RANfunctionID:
            ctx.ran_function_id = ie->value.choice.RANfunctionID;
            break;
        case RICcontrolRequest_IEs__value_PR_RICcallProcessID:
            release_octet_string(ctx.call_process_id);
            OCTET_STRING_fromBuf(&ctx.call_process_id,
                                 (const char *)ie->value.choice.RICcallProcessID.buf,
                                 ie->value.choice.RICcallProcessID.size);
            ctx.call_process_id_present = ctx.call_process_id.buf && ctx.call_process_id.size > 0;
            break;
        case RICcontrolRequest_IEs__value_PR_RICcontrolHeader:
            header_ok = decode_rc_control_header(ie->value.choice.RICcontrolHeader, ctx, decode_error);
            break;
        case RICcontrolRequest_IEs__value_PR_RICcontrolMessage:
            message_ok = decode_rc_control_message(ie->value.choice.RICcontrolMessage, ctx, decode_error);
            break;
        case RICcontrolRequest_IEs__value_PR_RICcontrolAckRequest:
            ctx.ack_requested = (ie->value.choice.RICcontrolAckRequest == RICcontrolAckRequest_ack);
            break;
        default:
            break;
        }
    }

    if (!header_ok)
    {
        decode_error = decode_error.empty() ? "Missing/invalid RC control header" : decode_error;
    }
    if (!message_ok && decode_error.empty())
    {
        decode_error = "Missing/invalid RC control message";
    }

    auto send_failure = [&](long cause_value, const std::string &reason)
    {
        if (ctx.requestor_id < 0 || ctx.instance_id < 0 || ctx.ran_function_id < 0)
        {
            logln("[RC CONTROL] Cannot send failure (missing identifiers)");
            return;
        }
        std::vector<uint8_t> outcome_buf;
        if (!encode_rc_control_outcome_single(kRcOutcomeStatus, reason, outcome_buf) && !reason.empty())
        {
            logln("[RC CONTROL] Unable to encode failure outcome payload");
        }
        E2AP_PDU_t *rsp = (E2AP_PDU_t *)calloc(1, sizeof(*rsp));
        const uint8_t *buf_ptr = outcome_buf.empty() ? nullptr : outcome_buf.data();
        generate_e2apv2_control_failure(
            rsp,
            ctx.requestor_id,
            ctx.instance_id,
            ctx.ran_function_id,
            Cause_PR_ricRequest,
            cause_value,
            ctx.call_process_id_present ? &ctx.call_process_id : nullptr,
            buf_ptr,
            outcome_buf.size());
        e2.encode_and_send_sctp_data(rsp);
        logln("[RC CONTROL] Sent control FAILURE req=%ld/%ld cause=%ld reason=%s",
              ctx.requestor_id,
              ctx.instance_id,
              cause_value,
              reason.c_str());
    };

    if (!decode_error.empty())
    {
        logln("[RC CONTROL] Decode failure: %s", decode_error.c_str());
        send_failure(CauseRICrequest_control_message_invalid, decode_error);
        return;
    }

    if (ctx.requestor_id < 0 || ctx.instance_id < 0 || ctx.ran_function_id < 0)
    {
        logln("[RC CONTROL] Missing mandatory identifiers in RICcontrolRequest");
        return;
    }

    RcControlExecutionResult exec_result = execute_rc_control_command(ctx);
    logln("[RC CONTROL] req=%ld/%ld action=%ld ack=%d status=%s",
          ctx.requestor_id,
          ctx.instance_id,
          ctx.control_action_id,
          ctx.ack_requested ? 1 : 0,
          exec_result.status.c_str());

    auto send_ack = [&](const RcControlExecutionResult &result)
    {
        std::vector<uint8_t> outcome_buf;
        if (!encode_rc_control_outcome(result.outcome_items, outcome_buf))
        {
            logln("[RC CONTROL] Unable to encode control outcome for ACK");
            outcome_buf.clear();
        }
        E2AP_PDU_t *rsp = (E2AP_PDU_t *)calloc(1, sizeof(*rsp));
        const uint8_t *buf_ptr = outcome_buf.empty() ? nullptr : outcome_buf.data();
        generate_e2apv2_control_ack(
            rsp,
            ctx.requestor_id,
            ctx.instance_id,
            ctx.ran_function_id,
            ctx.call_process_id_present ? &ctx.call_process_id : nullptr,
            buf_ptr,
            outcome_buf.size());
        e2.encode_and_send_sctp_data(rsp);
        logln("[RC CONTROL] Sent control ACK req=%ld/%ld outcomeLen=%zu",
              ctx.requestor_id,
              ctx.instance_id,
              outcome_buf.size());
    };

    if (exec_result.success)
    {
        if (ctx.ack_requested)
        {
            send_ack(exec_result);
        }
        else
        {
            logln("[RC CONTROL] ACK not requested by RIC, action executed locally");
        }
    }
    else
    {
        if (exec_result.outcome_items.empty())
        {
            exec_result.outcome_items.emplace_back(kRcOutcomeStatus, exec_result.status);
        }
        send_failure(exec_result.cause_value, exec_result.status);
    }
}

void registerRCfunctionDefinition(E2Sim &e2)
{
    // Mi occupo di integrare il setup RC qui
    E2SM_RC_RANFunctionDefinition_t *rc_ranfunc_desc =
        (E2SM_RC_RANFunctionDefinition_t *)calloc(1, sizeof(E2SM_RC_RANFunctionDefinition_t));
    if (rc_ranfunc_desc == NULL)
    {
        logln("calloc failed for rc_ranfunc_desc\n");
        return;
    }

    // Deve riempire i campi secondo RC v1
    encode_rc_function_definition(rc_ranfunc_desc);

    // Codifica della RANfunction-Description
    const size_t e2smbuffer_size = 16384;
    uint8_t *e2smbuffer_rc = (uint8_t *)calloc(1, e2smbuffer_size);
    if (e2smbuffer_rc == NULL)
    {
        logln("calloc failed for e2smbuffer_rc\n");
        return;
    }

    asn_enc_rval_t er_rc = asn_encode_to_buffer(
        NULL, ATS_ALIGNED_BASIC_PER,
        &asn_DEF_E2SM_RC_RANFunctionDefinition,
        rc_ranfunc_desc, e2smbuffer_rc, e2smbuffer_size);

    if (er_rc.encoded < 0)
    {
        logln("Encoding failed: %s\n", er_rc.failed_type ? er_rc.failed_type->name : "unknown");
        free(e2smbuffer_rc);
        return;
    }

    // Crea OCTET_STRING per registrazione nel simulatore
    OCTET_STRING_t *ranfunc_ostr_rc = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
    if (ranfunc_ostr_rc == NULL)
    {
        logln("calloc failed for ranfunc_ostr_rc\n");
        free(e2smbuffer_rc);
        return;
    }
    ranfunc_ostr_rc->buf = (uint8_t *)calloc(1, (size_t)er_rc.encoded);
    ranfunc_ostr_rc->size = (er_rc.encoded > 0) ? (size_t)er_rc.encoded : 0;
    if (ranfunc_ostr_rc->buf == NULL)
    {
        logln("calloc failed for ranfunc_ostr_rc->buf\n");
        free(ranfunc_ostr_rc);
        free(e2smbuffer_rc);
        return;
    }
    memcpy(ranfunc_ostr_rc->buf, e2smbuffer_rc, ranfunc_ostr_rc->size);

    e2.register_e2sm(3, ranfunc_ostr_rc);
    // e2.register_subscription_callback(3, &callback_rc_subscription_request);
    e2.register_control_callback(3, &callback_rc_control_request);
    const char *oid = "1.3.6.1.4.1.53148.1.1.2.3";
    PrintableString_t *ranFunctionOIDe = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
    OCTET_STRING_fromBuf(ranFunctionOIDe, oid, strlen(oid));
    e2.register_e2sm_oid(3, ranFunctionOIDe);
    g_rc_ranfunc_def = rc_ranfunc_desc;

    E2SM_RC_RANFunctionDefinition *check = NULL;
    asn_dec_rval_t dr = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_RC_RANFunctionDefinition, (void **)&check, ranfunc_ostr_rc->buf, ranfunc_ostr_rc->size);
    if (dr.code != RC_OK)
    {
        logln("Self-test decode RC FAILED (%d) at byte %zu\n", dr.code, dr.consumed);
    }
    else
    {
        logln("Self-test decode RC OK (consumed=%zu)\n", dr.consumed);
    }

    return;
}
