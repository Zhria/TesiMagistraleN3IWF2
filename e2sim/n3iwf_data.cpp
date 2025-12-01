#include <cctype>
#include <cerrno>
#include <iostream>
#include <map>
#include <fstream>
#include <optional>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <cstdlib>
#include <nlohmann/json.hpp>

#include "encode_e2apv2.hpp"
#include "n3iwf_data.hpp"
#include "n3iwf_utils.hpp"

extern "C" {
#include "E2SM-KPM-RANfunction-Description.h"
#include "e2ap_asn1c_codec.h"
#include "GlobalE2node-ID.h"
#include "GlobalE2node-gNB-ID.h"
#include "GlobalgNB-ID.h"
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "GNB-ID-Choice.h"
#include "ProtocolIE-Field.h"
#include "E2setupRequest.h"
#include "RICaction-ToBeSetup-Item.h"
#include "RICactions-ToBeSetup-List.h"
#include "RICeventTriggerDefinition.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "ProtocolIE-SingleContainer.h"
#include "RANfunctions-List.h"
#include "RICindication.h"
#include "RICsubsequentActionType.h"
#include "RICsubsequentAction.h"
#include "RICtimeToWait.h"
}

using json = nlohmann::json;
namespace fs = std::filesystem;

// Configurazione (safe)
static std::string g_fileName = "n3iwf_e2.json";
static std::string g_rcFileName = "n3iwf_e2_rc.json";
static std::string g_basePath = []{
  if (const char* p = std::getenv("E2_LOG_BASE")) return std::string(p);
  return std::string("/home/e2sim/log/");  // default nel tuo container
}();

static std::mutex g_rc_snapshot_mutex;
static RcSnapshot g_cached_rc_snapshot;
static bool g_rc_snapshot_valid = false;
static fs::file_time_type g_rc_snapshot_mtime{};

void setBasePath(const std::string& path) {
  g_basePath = path;
  if (!g_basePath.empty() && g_basePath.back() != '/') g_basePath.push_back('/');
}
void setFileName(const std::string& name) {
  g_fileName = name;
}

void setRcLogFileName(const std::string& name) {
  if (!name.empty()) {
    g_rcFileName = name;
  }
}

// Utility helpers
static inline std::string joinPathFile(const std::string& dir, const std::string& file) {
  if (dir.empty()) return file;
  if (dir.back() == '/') return dir + file;
  return dir + "/" + file;
}

static std::optional<std::string> readWholeFile(const std::string& fullpath) {
  std::ifstream f(fullpath, std::ios::in | std::ios::binary);
  if (!f) return std::nullopt;
  std::string data;
  f.seekg(0, std::ios::end);
  data.resize(static_cast<size_t>(f.tellg()));
  f.seekg(0, std::ios::beg);
  f.read(&data[0], static_cast<std::streamsize>(data.size()));
  return data;
}

static std::string json_to_string(const json& value) {
  if (value.is_string()) return value.get<std::string>();
  if (value.is_boolean()) return value.get<bool>() ? "true" : "false";
  if (value.is_number_integer()) return std::to_string(value.get<int64_t>());
  if (value.is_number_unsigned()) return std::to_string(value.get<uint64_t>());
  if (value.is_number_float()) {
    std::ostringstream oss;
    oss << value.get<double>();
    return oss.str();
  }
  if (value.is_null()) return "";
  return value.dump();
}

static uint64_t json_to_u64(const json& value) {
  if (value.is_number_unsigned()) return value.get<uint64_t>();
  if (value.is_number_integer()) {
    auto v = value.get<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
  }
  if (value.is_number_float()) {
    double v = value.get<double>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
  }
  if (value.is_string()) {
    try {
      return std::stoull(value.get<std::string>(), nullptr, 0);
    } catch (...) {
      return 0;
    }
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? 1 : 0;
  }
  return 0;
}

static int64_t json_to_i64(const json& value) {
  if (value.is_number_integer()) return value.get<int64_t>();
  if (value.is_number_unsigned()) return static_cast<int64_t>(value.get<uint64_t>());
  if (value.is_number_float()) return static_cast<int64_t>(value.get<double>());
  if (value.is_string()) {
    try {
      return std::stoll(value.get<std::string>(), nullptr, 0);
    } catch (...) {
      return 0;
    }
  }
  if (value.is_boolean()) return value.get<bool>() ? 1 : 0;
  return 0;
}

static bool json_to_bool(const json& value) {
  if (value.is_boolean()) return value.get<bool>();
  if (value.is_number_integer()) return value.get<int64_t>() != 0;
  if (value.is_number_unsigned()) return value.get<uint64_t>() != 0;
  if (value.is_string()) {
    auto str = value.get<std::string>();
    std::string lower;
    lower.reserve(str.size());
    for (char c : str) {
      lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lower == "true" || lower == "1" || lower == "yes";
  }
  return false;
}

static std::vector<int64_t> json_to_int64_vector(const json& value) {
  std::vector<int64_t> out;
  if (!value.is_array()) return out;
  out.reserve(value.size());
  for (const auto& entry : value) {
    out.push_back(json_to_i64(entry));
  }
  return out;
}

static std::map<std::string, std::string> json_to_string_map(const json& value) {
  std::map<std::string, std::string> out;
  if (!value.is_object()) return out;
  for (const auto& [key, val] : value.items()) {
    out.emplace(key, json_to_string(val));
  }
  return out;
}

static std::string to_lower_copy(const std::string &value) {
  std::string lower;
  lower.reserve(value.size());
  for (char c : value) {
    lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return lower;
}

static bool parse_first_double(const std::string &text, double &out) {
  if (text.empty()) {
    return false;
  }
  const char *ptr = text.c_str();
  char *end = nullptr;
  errno = 0;
  double val = std::strtod(ptr, &end);
  if (ptr == end || errno == ERANGE) {
    return false;
  }
  out = val;
  return true;
}

static bool parse_first_int64(const std::string &text, int64_t &out) {
  if (text.empty()) {
    return false;
  }
  const char *ptr = text.c_str();
  char *end = nullptr;
  errno = 0;
  long long val = std::strtoll(ptr, &end, 0);
  if (ptr == end || errno == ERANGE) {
    return false;
  }
  out = static_cast<int64_t>(val);
  return true;
}

static bool parse_first_uint64(const std::string &text, uint64_t &out) {
  if (text.empty()) {
    return false;
  }
  const char *ptr = text.c_str();
  char *end = nullptr;
  errno = 0;
  unsigned long long val = std::strtoull(ptr, &end, 0);
  if (ptr == end || errno == ERANGE) {
    return false;
  }
  out = static_cast<uint64_t>(val);
  return true;
}

static bool parse_bitrate_bps(const std::string &text, double &bps) {
  double value = 0.0;
  if (!parse_first_double(text, value)) {
    return false;
  }
  std::string lower = to_lower_copy(text);
  double multiplier = 1.0;
  if (lower.find("gbit") != std::string::npos) {
    multiplier = 1e9;
  } else if (lower.find("mbit") != std::string::npos) {
    multiplier = 1e6;
  } else if (lower.find("kbit") != std::string::npos) {
    multiplier = 1e3;
  } else if (lower.find("bit") != std::string::npos) {
    multiplier = 1.0;
  }
  bps = value * multiplier;
  return true;
}

static bool parse_duration_seconds(const std::string &text, double &seconds) {
  double value = 0.0;
  if (!parse_first_double(text, value)) {
    return false;
  }
  std::string lower = to_lower_copy(text);
  if (lower.find("ms") != std::string::npos) {
    seconds = value / 1000.0;
  } else if (lower.find("us") != std::string::npos) {
    seconds = value / 1'000'000.0;
  } else {
    seconds = value;
  }
  return true;
}

static bool lookup_station_field(const RcStationSnapshot &station,
                                 std::initializer_list<const char *> keys,
                                 std::string &out) {
  const std::map<std::string, std::string> *sources[] = {
      &station.fields, &station.station_dump, &station.hostapd};
  for (const char *key : keys) {
    for (const auto *src : sources) {
      auto it = src->find(key);
      if (it != src->end()) {
        out = it->second;
        return true;
      }
    }
  }
  return false;
}

struct RcMetricAccumulator {
  size_t ue_count{0};
  double signal_sum{0.0};
  size_t signal_count{0};
  uint64_t total_rx_bytes{0};
  uint64_t total_tx_bytes{0};
  uint64_t total_rx_packets{0};
  uint64_t total_tx_packets{0};
  uint64_t total_tx_retries{0};
  double conn_time_sum{0.0};
  size_t conn_time_count{0};
  double inactive_time_sum{0.0};
  size_t inactive_time_count{0};
  double tx_bitrate_sum{0.0};
  size_t tx_bitrate_count{0};
  double rx_bitrate_sum{0.0};
  size_t rx_bitrate_count{0};
};

static void accumulate_rc_metrics(const RcAssociationSnapshot &assoc,
                                  RcMetricAccumulator &acc) {
  acc.ue_count++;
  const RcStationSnapshot &station = assoc.station;
  std::string field;

  if (lookup_station_field(station, {"signal", "iw.signal", "signal_avg"}, field)) {
    double dbm = 0.0;
    if (parse_first_double(field, dbm)) {
      acc.signal_sum += dbm;
      acc.signal_count++;
    }
  }

  bool rx_bytes_recorded = false;
  if (lookup_station_field(station, {"rx_bytes", "iw.rx_bytes"}, field)) {
    uint64_t value = 0;
    if (parse_first_uint64(field, value)) {
      acc.total_rx_bytes += value;
      rx_bytes_recorded = true;
    }
  }
  if (!rx_bytes_recorded && assoc.counters.incoming_octets > 0) {
    acc.total_rx_bytes += assoc.counters.incoming_octets;
  }

  bool tx_bytes_recorded = false;
  if (lookup_station_field(station, {"tx_bytes", "iw.tx_bytes"}, field)) {
    uint64_t value = 0;
    if (parse_first_uint64(field, value)) {
      acc.total_tx_bytes += value;
      tx_bytes_recorded = true;
    }
  }
  if (!tx_bytes_recorded && assoc.counters.transmit_octets > 0) {
    acc.total_tx_bytes += assoc.counters.transmit_octets;
  }

  if (lookup_station_field(station, {"rx_packets", "iw.rx_packets"}, field)) {
    uint64_t value = 0;
    if (parse_first_uint64(field, value)) {
      acc.total_rx_packets += value;
    }
  } else if (assoc.counters.incoming_pkts > 0) {
    acc.total_rx_packets += assoc.counters.incoming_pkts;
  }

  if (lookup_station_field(station, {"tx_packets", "iw.tx_packets"}, field)) {
    uint64_t value = 0;
    if (parse_first_uint64(field, value)) {
      acc.total_tx_packets += value;
    }
  } else if (assoc.counters.transmit_pkts > 0) {
    acc.total_tx_packets += assoc.counters.transmit_pkts;
  }

  if (lookup_station_field(station, {"tx_retries", "iw.tx_retries"}, field)) {
    uint64_t value = 0;
    if (parse_first_uint64(field, value)) {
      acc.total_tx_retries += value;
    }
  }

  bool conn_recorded = false;
  if (lookup_station_field(station,
                           {"connected_time", "iw.connected_time", "stationDump.connected_time"},
                           field)) {
    double seconds = 0.0;
    if (parse_duration_seconds(field, seconds)) {
      acc.conn_time_sum += seconds;
      acc.conn_time_count++;
      conn_recorded = true;
    }
  }
  if (!conn_recorded && lookup_station_field(station, {"connected_time"}, field)) {
    double seconds = 0.0;
    if (parse_first_double(field, seconds)) {
      acc.conn_time_sum += seconds;
      acc.conn_time_count++;
    }
  }

  bool inactive_recorded = false;
  if (lookup_station_field(station, {"inactive_time", "iw.inactive_time"}, field)) {
    double seconds = 0.0;
    if (parse_duration_seconds(field, seconds)) {
      acc.inactive_time_sum += seconds;
      acc.inactive_time_count++;
      inactive_recorded = true;
    }
  }
  if (!inactive_recorded && lookup_station_field(station, {"inactive_msec"}, field)) {
    double ms_value = 0.0;
    if (parse_first_double(field, ms_value)) {
      acc.inactive_time_sum += ms_value / 1000.0;
      acc.inactive_time_count++;
    }
  }

  if (lookup_station_field(station, {"tx_bitrate", "iw.tx_bitrate"}, field)) {
    double bps = 0.0;
    if (parse_bitrate_bps(field, bps)) {
      acc.tx_bitrate_sum += bps;
      acc.tx_bitrate_count++;
    }
  }

  if (lookup_station_field(station, {"rx_bitrate", "iw.rx_bitrate"}, field)) {
    double bps = 0.0;
    if (parse_bitrate_bps(field, bps)) {
      acc.rx_bitrate_sum += bps;
      acc.rx_bitrate_count++;
    }
  }
}

struct RcThroughputTotals {
  uint64_t dl_bytes{0};
  uint64_t ul_bytes{0};
  uint64_t dl_packets{0};
  uint64_t ul_packets{0};
  uint64_t dl_drop_packets{0};
  uint64_t ul_drop_packets{0};
};

static RcThroughputTotals g_prev_throughput_totals{};
static bool g_prev_throughput_valid = false;

static void accumulate_rc_throughput(const RcAssociationSnapshot &assoc,
                                     RcThroughputTotals &totals) {
  std::string field;
  uint64_t value = 0;

  if (lookup_station_field(assoc.station, {"tx_bytes", "iw.tx_bytes"}, field) &&
      parse_first_uint64(field, value)) {
    totals.dl_bytes += value;
  } else {
    totals.dl_bytes += assoc.counters.transmit_octets;
  }

  if (lookup_station_field(assoc.station, {"rx_bytes", "iw.rx_bytes"}, field) &&
      parse_first_uint64(field, value)) {
    totals.ul_bytes += value;
  } else {
    totals.ul_bytes += assoc.counters.incoming_octets;
  }

  if (lookup_station_field(assoc.station, {"tx_packets", "iw.tx_packets"}, field) &&
      parse_first_uint64(field, value)) {
    totals.dl_packets += value;
  } else {
    totals.dl_packets += assoc.counters.transmit_pkts;
  }

  if (lookup_station_field(assoc.station, {"rx_packets", "iw.rx_packets"}, field) &&
      parse_first_uint64(field, value)) {
    totals.ul_packets += value;
  } else {
    totals.ul_packets += assoc.counters.incoming_pkts;
  }

  if (lookup_station_field(assoc.station, {"tx_failed", "iw.tx_failed"}, field) &&
      parse_first_uint64(field, value)) {
    totals.dl_drop_packets += value;
  }
  if (lookup_station_field(assoc.station, {"tx_retries", "iw.tx_retries"}, field) &&
      parse_first_uint64(field, value)) {
    totals.dl_drop_packets += value;
  }
  if (lookup_station_field(assoc.station, {"rx_drop_misc", "iw.rx_drop_misc"}, field) &&
      parse_first_uint64(field, value)) {
    totals.ul_drop_packets += value;
  }
}

static RcThroughputTotals subtract_totals(const RcThroughputTotals &curr,
                                          const RcThroughputTotals &prev) {
  RcThroughputTotals delta;
  delta.dl_bytes = (curr.dl_bytes >= prev.dl_bytes) ? (curr.dl_bytes - prev.dl_bytes) : 0;
  delta.ul_bytes = (curr.ul_bytes >= prev.ul_bytes) ? (curr.ul_bytes - prev.ul_bytes) : 0;
  delta.dl_packets = (curr.dl_packets >= prev.dl_packets) ? (curr.dl_packets - prev.dl_packets) : 0;
  delta.ul_packets = (curr.ul_packets >= prev.ul_packets) ? (curr.ul_packets - prev.ul_packets) : 0;
  delta.dl_drop_packets =
      (curr.dl_drop_packets >= prev.dl_drop_packets)
          ? (curr.dl_drop_packets - prev.dl_drop_packets)
          : 0;
  delta.ul_drop_packets =
      (curr.ul_drop_packets >= prev.ul_drop_packets)
          ? (curr.ul_drop_packets - prev.ul_drop_packets)
          : 0;
  return delta;
}

static RcCountersSnapshot parse_rc_counters(const json& counters) {
  RcCountersSnapshot out;
  if (!counters.is_object()) return out;
  if (auto it = counters.find("incomingOctets"); it != counters.end()) out.incoming_octets = json_to_u64(*it);
  if (auto it = counters.find("transmitOctets"); it != counters.end()) out.transmit_octets = json_to_u64(*it);
  if (auto it = counters.find("incomingPkts"); it != counters.end()) out.incoming_pkts = json_to_u64(*it);
  if (auto it = counters.find("transmitPkts"); it != counters.end()) out.transmit_pkts = json_to_u64(*it);
  if (auto it = counters.find("droppedOctets"); it != counters.end()) out.dropped_octets = json_to_u64(*it);
  return out;
}

static RcChildSaInfoSnapshot parse_child_sa(const json& child) {
  RcChildSaInfoSnapshot out;
  if (!child.is_object()) return out;
  if (auto it = child.find("inboundSpi"); it != child.end()) out.inbound_spi = static_cast<uint32_t>(json_to_u64(*it));
  if (auto it = child.find("outboundSpi"); it != child.end()) out.outbound_spi = static_cast<uint32_t>(json_to_u64(*it));
  if (auto it = child.find("tunnelIface"); it != child.end()) out.tunnel_iface = json_to_string(*it);
  if (auto it = child.find("peerPublicIp"); it != child.end()) out.peer_public_ip = json_to_string(*it);
  if (auto it = child.find("localPublicIp"); it != child.end()) out.local_public_ip = json_to_string(*it);
  if (auto it = child.find("n3iwfPort"); it != child.end()) out.n3iwf_port = static_cast<int>(json_to_i64(*it));
  if (auto it = child.find("natPort"); it != child.end()) out.nat_port = static_cast<int>(json_to_i64(*it));
  if (auto it = child.find("enableEncapsulate"); it != child.end()) out.enable_encapsulate = json_to_bool(*it);
  if (auto it = child.find("selectedIpProto"); it != child.end()) out.selected_ip_proto = static_cast<uint8_t>(json_to_u64(*it));
  if (auto it = child.find("pduSessionIds"); it != child.end()) out.pdu_session_ids = json_to_int64_vector(*it);
  return out;
}

static RcMaskedImeisvSnapshot parse_masked_imeisv(const json& masked) {
  RcMaskedImeisvSnapshot out;
  if (!masked.is_object()) return out;
  if (auto it_val = masked.find("Value"); it_val != masked.end() && it_val->is_object()) {
    if (auto it_b = it_val->find("Bytes"); it_b != it_val->end()) {
      out.bytes_b64 = json_to_string(*it_b);
    }
    if (auto it_l = it_val->find("BitLength"); it_l != it_val->end()) {
      out.bit_length = static_cast<int>(json_to_i64(*it_l));
    }
  }
  return out;
}

static RcGuamiSnapshot parse_guami(const json& guami) {
  RcGuamiSnapshot out;
  if (!guami.is_object()) return out;
  if (auto it_plmn = guami.find("PLMNIdentity"); it_plmn != guami.end() && it_plmn->is_object()) {
    if (auto it_v = it_plmn->find("Value"); it_v != it_plmn->end()) {
      out.plmn_value = json_to_string(*it_v);
    }
  }
  auto parse_bitfield = [](const json& obj, std::string& bytes_out, int& bitlen_out) {
    if (!obj.is_object()) return;
    if (auto it_val = obj.find("Value"); it_val != obj.end() && it_val->is_object()) {
      if (auto it_b = it_val->find("Bytes"); it_b != it_val->end()) {
        bytes_out = json_to_string(*it_b);
      }
      if (auto it_l = it_val->find("BitLength"); it_l != it_val->end()) {
        bitlen_out = static_cast<int>(json_to_i64(*it_l));
      }
    }
  };

  if (auto it = guami.find("AMFRegionID"); it != guami.end()) {
    parse_bitfield(*it, out.amf_region_bytes, out.amf_region_bit_length);
  }
  if (auto it = guami.find("AMFSetID"); it != guami.end()) {
    parse_bitfield(*it, out.amf_set_bytes, out.amf_set_bit_length);
  }
  if (auto it = guami.find("AMFPointer"); it != guami.end()) {
    parse_bitfield(*it, out.amf_pointer_bytes, out.amf_pointer_bit_length);
  }
  return out;
}

static RcSnssaiSnapshot parse_snssai(const json& snssai) {
  RcSnssaiSnapshot out;
  if (!snssai.is_object()) return out;
  if (auto it_sst = snssai.find("SST"); it_sst != snssai.end() && it_sst->is_object()) {
    if (auto it_v = it_sst->find("Value"); it_v != it_sst->end()) {
      out.sst_value = json_to_string(*it_v);
    }
  }
  if (auto it_sd = snssai.find("SD"); it_sd != snssai.end() && it_sd->is_object()) {
    if (auto it_v = it_sd->find("Value"); it_v != it_sd->end()) {
      out.sd_value = json_to_string(*it_v);
    }
  }
  return out;
}

static RcPduSessionQosFlowSnapshot parse_qos_flow(const json& flow) {
  RcPduSessionQosFlowSnapshot out;
  if (!flow.is_object()) return out;
  if (auto it = flow.find("identifier"); it != flow.end()) {
    out.identifier = static_cast<int32_t>(json_to_i64(*it));
  }
  if (auto it_params = flow.find("parameters"); it_params != flow.end() && it_params->is_object()) {
    const auto& params = *it_params;
    if (auto it_qc = params.find("QosCharacteristics"); it_qc != params.end() && it_qc->is_object()) {
      const auto& qc = *it_qc;
      if (auto it_nd = qc.find("NonDynamic5QI"); it_nd != qc.end() && it_nd->is_object()) {
        const auto& nd = *it_nd;
        if (auto it_fiveqi = nd.find("FiveQI"); it_fiveqi != nd.end() && it_fiveqi->is_object()) {
          if (auto it_v = it_fiveqi->find("Value"); it_v != it_fiveqi->end()) {
            out.five_qi = static_cast<int32_t>(json_to_i64(*it_v));
          }
        }
      }
    }
    if (auto it_arp = params.find("AllocationAndRetentionPriority"); it_arp != params.end() && it_arp->is_object()) {
      const auto& arp = *it_arp;
      if (auto it_pl = arp.find("PriorityLevelARP"); it_pl != arp.end() && it_pl->is_object()) {
        if (auto it_v = it_pl->find("Value"); it_v != it_pl->end()) {
          out.arp_priority_level = static_cast<int32_t>(json_to_i64(*it_v));
        }
      }
      if (auto it_pc = arp.find("PreEmptionCapability"); it_pc != arp.end() && it_pc->is_object()) {
        if (auto it_v = it_pc->find("Value"); it_v != it_pc->end()) {
          out.arp_pre_emption_capability = static_cast<int32_t>(json_to_i64(*it_v));
        }
      }
      if (auto it_pv = arp.find("PreEmptionVulnerability"); it_pv != arp.end() && it_pv->is_object()) {
        if (auto it_v = it_pv->find("Value"); it_v != it_pv->end()) {
          out.arp_pre_emption_vulnerability = static_cast<int32_t>(json_to_i64(*it_v));
        }
      }
    }
  }
  return out;
}

static RcPduSessionSnapshot parse_pdu_session(const json& sess) {
  RcPduSessionSnapshot out;
  if (!sess.is_object()) return out;
  if (auto it = sess.find("id"); it != sess.end()) {
    out.id = static_cast<int32_t>(json_to_i64(*it));
  }
  if (auto it_type = sess.find("type"); it_type != sess.end() && it_type->is_object()) {
    if (auto it_v = it_type->find("Value"); it_v != it_type->end()) {
      out.type_value = static_cast<int32_t>(json_to_i64(*it_v));
    }
  }
  if (auto it_ambr = sess.find("ambr"); it_ambr != sess.end() && it_ambr->is_object()) {
    const auto& ambr = *it_ambr;
    if (auto it_dl = ambr.find("PDUSessionAggregateMaximumBitRateDL"); it_dl != ambr.end() && it_dl->is_object()) {
      if (auto it_v = it_dl->find("Value"); it_v != it_dl->end()) {
        out.ambr_dl = json_to_u64(*it_v);
      }
    }
    if (auto it_ul = ambr.find("PDUSessionAggregateMaximumBitRateUL"); it_ul != ambr.end() && it_ul->is_object()) {
      if (auto it_v = it_ul->find("Value"); it_v != it_ul->end()) {
        out.ambr_ul = json_to_u64(*it_v);
      }
    }
  }
  if (auto it_sn = sess.find("snssai"); it_sn != sess.end() && it_sn->is_object()) {
    out.snssai = parse_snssai(*it_sn);
  }
  if (auto it = sess.find("securityCipher"); it != sess.end()) {
    out.security_cipher = json_to_bool(*it);
  }
  if (auto it = sess.find("securityIntegrity"); it != sess.end()) {
    out.security_integrity = json_to_bool(*it);
  }
  if (auto it_gtp = sess.find("gtpConnInfo"); it_gtp != sess.end() && it_gtp->is_object()) {
    const auto& gtp = *it_gtp;
    if (auto it_ip = gtp.find("upfIpAddr"); it_ip != gtp.end()) {
      out.upf_ip_addr = json_to_string(*it_ip);
    }
    if (auto it_udp = gtp.find("upfUdpAddr"); it_udp != gtp.end() && it_udp->is_object()) {
      if (auto it_uip = it_udp->find("ip"); it_uip != it_udp->end()) {
        out.upf_udp_ip = json_to_string(*it_uip);
      }
      if (auto it_port = it_udp->find("port"); it_port != it_udp->end()) {
        out.upf_udp_port = static_cast<int32_t>(json_to_i64(*it_port));
      }
    }
    if (auto it = gtp.find("incomingTeid"); it != gtp.end()) {
      out.incoming_teid = json_to_u64(*it);
    }
    if (auto it = gtp.find("outgoingTeid"); it != gtp.end()) {
      out.outgoing_teid = json_to_u64(*it);
    }
  }
  if (auto it = sess.find("qfiList"); it != sess.end()) {
    out.qfi_list_b64 = json_to_string(*it);
  }
  if (auto it_qos = sess.find("qosFlows"); it_qos != sess.end() && it_qos->is_object()) {
    for (const auto& [key, val] : it_qos->items()) {
      (void)key;
      if (!val.is_object()) continue;
      out.qos_flows.push_back(parse_qos_flow(val));
    }
  }
  return out;
}

static RcStationSnapshot parse_station_snapshot(const json& station,
                                                const std::string& fallback_iface,
                                                const std::string& fallback_mac,
                                                const std::string& fallback_ip) {
  RcStationSnapshot out;
  out.interface_name = fallback_iface;
  out.mac = fallback_mac;
  out.ip = fallback_ip;
  if (!station.is_object()) return out;
  out.interface_name = station.value("interface", out.interface_name);
  out.mac = station.value("mac", out.mac);
  out.ip = station.value("ip", out.ip);
  if (auto it = station.find("fields"); it != station.end()) out.fields = json_to_string_map(*it);
  if (auto it = station.find("hostapd"); it != station.end()) out.hostapd = json_to_string_map(*it);
  if (auto it = station.find("stationDump"); it != station.end()) out.station_dump = json_to_string_map(*it);
  return out;
}

static RcUeInfoSnapshot parse_ue_snapshot(const json& ue) {
  RcUeInfoSnapshot out;
  if (!ue.is_object()) return out;
  if (auto it = ue.find("ranUeNgapId"); it != ue.end()) out.ran_ue_ngap_id = json_to_i64(*it);
  if (auto it = ue.find("amfUeNgapId"); it != ue.end()) out.amf_ue_ngap_id = json_to_i64(*it);
  if (auto it = ue.find("ipAddrV4"); it != ue.end()) out.ip_addr_v4 = json_to_string(*it);
  if (auto it = ue.find("ipAddrV6"); it != ue.end()) out.ip_addr_v6 = json_to_string(*it);
  if (auto it = ue.find("portNumber"); it != ue.end()) out.port_number = static_cast<int32_t>(json_to_i64(*it));
  if (auto it = ue.find("guti"); it != ue.end()) out.guti = json_to_string(*it);
  if (auto it = ue.find("n3iwfId"); it != ue.end()) out.n3iwf_id = json_to_string(*it);
  if (auto it = ue.find("amfName"); it != ue.end()) out.amf_name = json_to_string(*it);
  if (auto it = ue.find("amfSctp"); it != ue.end()) out.amf_sctp = json_to_string(*it);
  if (auto it = ue.find("rrcEstablishmentCause"); it != ue.end()) out.rrc_establishment_cause = static_cast<int16_t>(json_to_i64(*it));
  if (auto it = ue.find("ikeLocalSpi"); it != ue.end()) out.ike_local_spi = json_to_u64(*it);
  if (auto it = ue.find("ikeRemoteSpi"); it != ue.end()) out.ike_remote_spi = json_to_u64(*it);
  if (auto it = ue.find("ikeState"); it != ue.end()) out.ike_state = static_cast<uint8_t>(json_to_u64(*it));
  if (auto it = ue.find("ueBehindNat"); it != ue.end()) out.ue_behind_nat = json_to_bool(*it);
  if (auto it = ue.find("n3iwfBehindNat"); it != ue.end()) out.n3iwf_behind_nat = json_to_bool(*it);
  if (auto it = ue.find("childSa"); it != ue.end() && it->is_array()) {
    for (const auto& sa : *it) {
      out.child_sa.push_back(parse_child_sa(sa));
    }
  }
   if (auto it = ue.find("maskedImeisv"); it != ue.end()) {
     out.masked_imeisv = parse_masked_imeisv(*it);
   }
   if (auto it = ue.find("guami"); it != ue.end()) {
     out.guami = parse_guami(*it);
   }
   if (auto it = ue.find("allowedNssai"); it != ue.end() && it->is_object()) {
     if (auto it_list = it->find("List"); it_list != it->end() && it_list->is_array()) {
       for (const auto& entry : *it_list) {
         if (!entry.is_object()) continue;
         if (auto it_sn = entry.find("SNSSAI"); it_sn != entry.end() && it_sn->is_object()) {
           out.allowed_nssai.push_back(parse_snssai(*it_sn));
         }
       }
     }
   }
   if (auto it = ue.find("pduSessionReleaseList"); it != ue.end() && it->is_object()) {
     if (auto it_list = it->find("List"); it_list != it->end() && it_list->is_array()) {
       out.pdu_session_release_ids = json_to_int64_vector(*it_list);
     }
   }
   if (auto it = ue.find("pduSessionList"); it != ue.end() && it->is_object()) {
     for (const auto& [key, val] : it->items()) {
       (void)key;
       if (!val.is_object()) continue;
       out.pdu_sessions.push_back(parse_pdu_session(val));
     }
   }
  for (const auto& [key, val] : ue.items()) {
    out.extra_fields[key] = json_to_string(val);
  }
  return out;
}

static RcAssociationSnapshot parse_rc_association(const json& assoc) {
  RcAssociationSnapshot out;
  if (!assoc.is_object()) return out;
  out.interface_name = assoc.value("interface", std::string{});
  out.mac = assoc.value("mac", std::string{});
  out.ue_ip = assoc.value("ueIp", std::string{});
  if (auto it = assoc.find("station"); it != assoc.end()) {
    out.station = parse_station_snapshot(*it, out.interface_name, out.mac, out.ue_ip);
  } else {
    out.station = parse_station_snapshot(json{}, out.interface_name, out.mac, out.ue_ip);
  }
  if (auto it = assoc.find("counters"); it != assoc.end()) out.counters = parse_rc_counters(*it);
  if (auto it = assoc.find("ue"); it != assoc.end()) out.ue = parse_ue_snapshot(*it);
  if (auto it = assoc.find("mismatches"); it != assoc.end() && it->is_array()) {
    for (const auto& mismatch : *it) {
      if (mismatch.is_string()) {
        out.mismatches.push_back(mismatch.get<std::string>());
      }
    }
  }
  return out;
}

static std::string normalize_mac(const std::string& mac) {
  std::string out;
  out.reserve(mac.size());
  for (char c : mac) {
    if (c == ':' || c == '-' || c == '.') continue;
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

// JSON I/O
static std::optional<json> getFree5gcData() {
  const std::string full = joinPathFile(g_basePath, g_fileName);
  if (!fs::exists(full)) {
    std::cerr << "[n3iwf] JSON file non trovato: " << full << "\n";
    return std::nullopt;
  }
  auto buf = readWholeFile(full);
  if (!buf) {
    std::cerr << "[n3iwf] Impossibile leggere: " << full << "\n";
    return std::nullopt;
  }
  if (!json::accept(*buf)) {
    std::cerr << "[n3iwf] JSON non valido:\n" << *buf << "\n";
    return std::nullopt;
  }
  try {
    return json::parse(*buf);
  } catch (const std::exception& e) {
    std::cerr << "[n3iwf] Eccezione nel parse JSON: " << e.what() << "\n";
    return std::nullopt;
  }
}

// ASN.1 helpers
// Converte MCC/MNC (stringhe "001","01") in 3 byte PLMN
static bool buildPLMN(const std::string& mcc, const std::string& mnc, OCTET_STRING_t& out) {
  if (mcc.size() != 3 || (mnc.size() != 2 && mnc.size() != 3)) return false;
  uint8_t b0 = static_cast<uint8_t>(((mcc[1]-'0') << 4) | (mcc[0]-'0'));
  uint8_t b1 = static_cast<uint8_t>(((mnc.size()==2? 0xF : (mnc[2]-'0')) << 4) | (mcc[2]-'0'));
  uint8_t b2 = static_cast<uint8_t>(((mnc[1]-'0') << 4) | (mnc[0]-'0'));

  out.buf = (uint8_t*)calloc(1, 3);
  if (!out.buf) return false;
  out.size = 3;
  out.buf[0]=b0; out.buf[1]=b1; out.buf[2]=b2;
  return true;
}

// asn1c: BIT_STRING_t { uint8_t* buf; size_t size; int bits_unused; }
static bool buildBitStringFromUIntN(uint32_t value, BIT_STRING_t* out) {
  int width=22;  
  if (!out || width < 1 || width > 32) return false;

    // controllo che 'value' stia in 'width' bit
    if (width < 32 && (value >> width) != 0) return false;

    const int num_bytes   = (width + 7) / 8;
    const int bits_unused = num_bytes * 8 - width;

    uint8_t* buf = (uint8_t*)calloc(1, num_bytes);
    if (!buf) return false;

    // Allinea a sinistra in modo che i bit inutilizzati (a destra) restino a zero
    uint64_t shifted = ((uint64_t)value) << bits_unused;

    // MSB-first nel buffer ASN.1 (big-endian a livello di ottetti)
    for (int i = 0; i < num_bytes; ++i) {
        int shift = 8 * (num_bytes - 1 - i);
        buf[i] = (uint8_t)((shifted >> shift) & 0xFFu);
    }

    // Azzeriamo esplicitamente i bit di padding (destra dell’ultimo ottetto)
    if (bits_unused) {
        buf[num_bytes - 1] &= (uint8_t)(0xFFu << bits_unused);
    }

    // (opzionale) libera out->buf se stai riusando la struct
    // if (out->buf) free(out->buf);

    out->buf = buf;
    out->size = num_bytes;
    out->bits_unused = bits_unused;
    return true;
}


// Costruzione strutture
static bool getPLMNID_from_json(const json& j, OCTET_STRING_t& out) {
  try {
    const auto& plmn = j.at("data").at("config").at("Configuration")
                        .at("N3IWFInfo").at("GlobalN3IWFID").at("PLMNID");
    std::string mcc = plmn.at("Mcc").get<std::string>();
    std::string mnc = plmn.at("Mnc").get<std::string>();
    return buildPLMN(mcc, mnc, out);
  } catch (...) {
    std::cerr << "[n3iwf] campi PLMN mancanti nel JSON\n";
    return false;
  }
}

static bool getGNBIDChoice_from_json(const json& j, GNB_ID_Choice_t& out) {
  try {
    int n3iwfId = 0;
    j.at("data").at("config").at("Configuration")
     .at("N3IWFInfo").at("GlobalN3IWFID").at("N3IWFID").get_to(n3iwfId);
    if (n3iwfId < 0) n3iwfId = 0;

    out.present = GNB_ID_Choice_PR_gnb_ID;
    // alloca buffer interno del bitstring
    BIT_STRING_t bs;
    if (!buildBitStringFromUIntN(static_cast<uint32_t>(n3iwfId), &bs)) return false;
    out.choice.gnb_ID = bs; // copia shallow dei campi (puntatore incluso)
    return true;
  } catch (...) {
    std::cerr << "[n3iwf] campo N3IWFID mancante nel JSON\n";
    return false;
  }
}

// Alloc/Build GlobalgNB_ID (il chiamante lo rilascia con freeGlobalgNB_ID)
static GlobalgNB_ID_t* buildGlobalgNB_ID() {
  auto j = getFree5gcData();
  if (!j) return nullptr;

  auto* gnb = (GlobalgNB_ID_t*)calloc(1, sizeof(GlobalgNB_ID_t));
  if (!gnb) return nullptr;

  if (!getPLMNID_from_json(*j, gnb->plmn_id)) {
    free(gnb); return nullptr;
  }
  if (!getGNBIDChoice_from_json(*j, gnb->gnb_id)) {
    free(gnb->plmn_id.buf);
    free(gnb); return nullptr;
  }
  return gnb;
}

static void freeGlobalgNB_ID(GlobalgNB_ID_t* gnb) {
  if (!gnb) return;
  if (gnb->plmn_id.buf) free(gnb->plmn_id.buf);
  if (gnb->gnb_id.present == GNB_ID_Choice_PR_gnb_ID && gnb->gnb_id.choice.gnb_ID.buf)
    free(gnb->gnb_id.choice.gnb_ID.buf);
  free(gnb);
}

// API “pubblica” compatibile
// Manteniamo un singleton per semplicità
static GlobalgNB_ID_t* g_gnbStore = nullptr;

int init_n3iwf_data() {
  if (g_gnbStore) return 0;
  g_gnbStore = buildGlobalgNB_ID();
  if (!g_gnbStore) {
    std::cerr << "[n3iwf] init_n3iwf_data: buildGlobalgNB_ID fallita\n";
    return -1;
  }
  return 0;
}

GlobalgNB_ID_t* getGNBStore() {
  if (!g_gnbStore) {
    if (init_n3iwf_data() != 0) return nullptr;
  }
  BIT_STRING_t& gnb_id_bs = g_gnbStore->gnb_id.choice.gnb_ID;

  int ret = validate_or_fix_gnb_id_length(&gnb_id_bs, /*min=*/22, /*max=*/32, /*target_if_pad=*/22);
  if (ret != 0) {
    std::cerr << "gNB ID invalid length (must be 22..32 bits) and cannot be auto-fixed.\n";
    return nullptr;
  }

  int total_bits = gnb_id_bs.size * 8 - gnb_id_bs.bits_unused;
  std::cout << "gNB ID length: " << total_bits << " bits\n";

  return g_gnbStore;
}

// Se/Quando vuoi rilasciare risorse (es. a fine programma):
void deinit_n3iwf_data() {
  if (g_gnbStore) {
    freeGlobalgNB_ID(g_gnbStore);
    g_gnbStore = nullptr;
  }
}

static inline double safe_div(double num, double den) {
  if (den <= 0) return 0.0;
  // round half up: (num + den/2) / den
  return num/den;
};

static inline double percent_or_zero(int64_t num, int64_t den) {
  return (den > 0) ? (100.0 * (double)num / (double)den) : 0.0;
}


std::map<std::string, double> getMetricsKPM(GranularityPeriod_t granularityPeriod) {
  RcSnapshot rc_snapshot;
  if (!loadRcSnapshot(rc_snapshot)) {
    logln("[n3iwf] Unable to load RC snapshot, skipping metrics collection");
    return {};
  }
  if (rc_snapshot.associations.empty()) {
    logln("[n3iwf] RC snapshot has no associations, skipping metrics collection");
    return {};
  }

  RcThroughputTotals curr_totals;
  RcMetricAccumulator acc;
  for (const auto &assoc : rc_snapshot.associations) {
    accumulate_rc_throughput(assoc, curr_totals);
    accumulate_rc_metrics(assoc, acc);
  }

  if (!g_prev_throughput_valid) {
    g_prev_throughput_totals = curr_totals;
    g_prev_throughput_valid = true;
    logln("[n3iwf] Initialized throughput baseline from RC snapshot; waiting next interval");
    return {};
  }

  RcThroughputTotals delta = subtract_totals(curr_totals, g_prev_throughput_totals);
  g_prev_throughput_totals = curr_totals;

  double granularityPeriodSec = granularityPeriod / 1000.0;
  if (granularityPeriodSec <= 0.0) {
    granularityPeriodSec = 1.0;
  }

  std::vector<std::string> kpi = getAllowedKPI();
  std::map<std::string, double> result;

  for (const auto& metric : kpi) {
    if (metric == "DRB.UEThpDl") {
      result[metric] = safe_div(static_cast<double>(delta.dl_bytes) * 8.0, granularityPeriodSec);
    } else if (metric == "DRB.UEThpUl") {
      result[metric] = safe_div(static_cast<double>(delta.ul_bytes) * 8.0, granularityPeriodSec);
    } else if (metric == "DRB.RlcSduTransmittedVolumeDL") {
      result[metric] = static_cast<double>(delta.dl_bytes) * 8.0 / 1000.0;
    } else if (metric == "DRB.RlcSduTransmittedVolumeUL") {
      result[metric] = static_cast<double>(delta.ul_bytes) * 8.0 / 1000.0;
    } else if (metric == "DRB.RlcPacketDropRateDLDist") {
      uint64_t denom = delta.dl_packets + delta.dl_drop_packets;
      result[metric] = percent_or_zero(static_cast<int64_t>(delta.dl_drop_packets),
                                       static_cast<int64_t>(denom));
    } else if (metric == "DRB.RlcPacketLossRateULDist") {
      uint64_t denom = delta.ul_packets + delta.ul_drop_packets;
      result[metric] = percent_or_zero(static_cast<int64_t>(delta.ul_drop_packets),
                                       static_cast<int64_t>(denom));
    } else {
      // handled later (extended RC-derived KPIs)
      continue;
    }
  }
/*
  result["UE.ActiveUeCount"] = static_cast<double>(acc.ue_count);
  if (acc.signal_count > 0) {
    result["UE.SignalStrengthAvgDbm"] = acc.signal_sum / static_cast<double>(acc.signal_count);
  }
  result["UE.RxBytesWiFi"] = static_cast<double>(acc.total_rx_bytes);
  result["UE.TxBytesWiFi"] = static_cast<double>(acc.total_tx_bytes);
  result["UE.RxPacketsWiFi"] = static_cast<double>(acc.total_rx_packets);
  result["UE.TxPacketsWiFi"] = static_cast<double>(acc.total_tx_packets);
  if (acc.total_tx_packets > 0) {
    result["UE.TxRetryRatePercent"] =
        percent_or_zero(static_cast<int64_t>(acc.total_tx_retries),
                        static_cast<int64_t>(acc.total_tx_packets));
  }
  if (acc.conn_time_count > 0) {
    result["UE.ConnectionTimeAvgSec"] =
        acc.conn_time_sum / static_cast<double>(acc.conn_time_count);
  }
  if (acc.inactive_time_count > 0) {
    result["UE.InactiveTimeAvgSec"] =
        acc.inactive_time_sum / static_cast<double>(acc.inactive_time_count);
  }
  if (acc.tx_bitrate_count > 0) {
    result["UE.TxBitrateAvgMbps"] =
        (acc.tx_bitrate_sum / static_cast<double>(acc.tx_bitrate_count)) / 1'000'000.0;
  }
  if (acc.rx_bitrate_count > 0) {
    result["UE.RxBitrateAvgMbps"] =
        (acc.rx_bitrate_sum / static_cast<double>(acc.rx_bitrate_count)) / 1'000'000.0;
  }
*/
  return result;
}

bool loadRcSnapshot(RcSnapshot &out) {
  const std::string full = joinPathFile(g_basePath, g_rcFileName);
  if (!fs::exists(full)) {
    std::cerr << "[n3iwf] RC JSON file non trovato: " << full << "\n";
    return false;
  }
  auto buf = readWholeFile(full);
  if (!buf) {
    std::cerr << "[n3iwf] Impossibile leggere RC JSON: " << full << "\n";
    return false;
  }
  if (!json::accept(*buf)) {
    std::cerr << "[n3iwf] RC JSON non valido:\n" << *buf << "\n";
    return false;
  }
  json j;
  try {
    j = json::parse(*buf);
  } catch (const std::exception &e) {
    std::cerr << "[n3iwf] Eccezione nel parse RC JSON: " << e.what() << "\n";
    return false;
  }

  out.timestamp = j.value("timestamp", std::string{});
  out.associations.clear();
  if (auto it = j.find("associations"); it != j.end() && it->is_array()) {
    out.associations.reserve(it->size());
    for (const auto &entry : *it) {
      out.associations.emplace_back(parse_rc_association(entry));
    }
  }
  return true;
}

static bool loadRcSnapshotCached(RcSnapshot &out) {
  const std::string full = joinPathFile(g_basePath, g_rcFileName);
  std::error_code ec;
  const auto current_mtime = fs::last_write_time(full, ec);
  const bool have_mtime = !ec;

  {
    std::lock_guard<std::mutex> lock(g_rc_snapshot_mutex);
    if (g_rc_snapshot_valid && (!have_mtime || current_mtime == g_rc_snapshot_mtime)) {
      out = g_cached_rc_snapshot;
      return true;
    }
  }

  RcSnapshot fresh;
  if (!loadRcSnapshot(fresh)) {
    return false;
  }

  {
    std::lock_guard<std::mutex> lock(g_rc_snapshot_mutex);
    g_cached_rc_snapshot = fresh;
    g_rc_snapshot_valid = true;
    if (have_mtime) {
      g_rc_snapshot_mtime = current_mtime;
    }
    out = g_cached_rc_snapshot;
  }

  return true;
}

std::vector<RcAssociationSnapshot> getRcAssociations() {
  RcSnapshot snap;
  if (!loadRcSnapshotCached(snap)) {
    return {};
  }
  return snap.associations;
}

std::optional<RcAssociationSnapshot> findRcAssociationByRanUeId(int64_t ran_ue_ngap_id) {
  if (ran_ue_ngap_id < 0) {
    return std::nullopt;
  }
  RcSnapshot snap;
  if (!loadRcSnapshotCached(snap)) {
    return std::nullopt;
  }
  for (const auto &assoc : snap.associations) {
    if (assoc.ue.ran_ue_ngap_id == ran_ue_ngap_id) {
      return assoc;
    }
  }
  return std::nullopt;
}

std::optional<RcAssociationSnapshot> findRcAssociationByAmfUeId(int64_t amf_ue_ngap_id) {
  if (amf_ue_ngap_id < 0) {
    return std::nullopt;
  }
  RcSnapshot snap;
  if (!loadRcSnapshotCached(snap)) {
    return std::nullopt;
  }
  for (const auto &assoc : snap.associations) {
    if (assoc.ue.amf_ue_ngap_id == amf_ue_ngap_id) {
      return assoc;
    }
  }
  return std::nullopt;
}
