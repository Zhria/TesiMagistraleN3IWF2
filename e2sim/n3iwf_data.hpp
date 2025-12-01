
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

extern "C" {
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

int init_n3iwf_data();

GlobalgNB_ID_t* getGNBStore();

std::map<std::string, double> getMetricsKPM(GranularityPeriod_t granularityPeriod);

struct RcCountersSnapshot {
    uint64_t incoming_octets{0};
    uint64_t transmit_octets{0};
    uint64_t incoming_pkts{0};
    uint64_t transmit_pkts{0};
    uint64_t dropped_octets{0};
};

struct RcChildSaInfoSnapshot {
    uint32_t inbound_spi{0};
    uint32_t outbound_spi{0};
    std::string tunnel_iface;
    std::string peer_public_ip;
    std::string local_public_ip;
    int n3iwf_port{0};
    int nat_port{0};
    bool enable_encapsulate{false};
    uint8_t selected_ip_proto{0};
    std::vector<int64_t> pdu_session_ids;
};

struct RcMaskedImeisvSnapshot {
    std::string bytes_b64;
    int bit_length{0};
};

struct RcGuamiSnapshot {
    std::string plmn_value;
    std::string amf_region_bytes;
    int amf_region_bit_length{0};
    std::string amf_set_bytes;
    int amf_set_bit_length{0};
    std::string amf_pointer_bytes;
    int amf_pointer_bit_length{0};
};

struct RcSnssaiSnapshot {
    std::string sst_value;
    std::string sd_value;
};

struct RcPduSessionQosFlowSnapshot {
    int32_t identifier{0};
    int32_t five_qi{0};
    int32_t arp_priority_level{0};
    int32_t arp_pre_emption_capability{0};
    int32_t arp_pre_emption_vulnerability{0};
};

struct RcPduSessionSnapshot {
    int32_t id{0};
    int32_t type_value{0};
    uint64_t ambr_dl{0};
    uint64_t ambr_ul{0};
    RcSnssaiSnapshot snssai;
    bool security_cipher{false};
    bool security_integrity{false};
    std::string upf_ip_addr;
    std::string upf_udp_ip;
    int32_t upf_udp_port{0};
    uint64_t incoming_teid{0};
    uint64_t outgoing_teid{0};
    std::string qfi_list_b64;
    std::vector<RcPduSessionQosFlowSnapshot> qos_flows;
};

struct RcUeInfoSnapshot {
    int64_t ran_ue_ngap_id{-1};
    int64_t amf_ue_ngap_id{-1};
    std::string ip_addr_v4;
    std::string ip_addr_v6;
    int32_t port_number{0};
    std::string guti;
    std::string n3iwf_id;
    std::string amf_name;
    std::string amf_sctp;
    int16_t rrc_establishment_cause{0};
    uint64_t ike_local_spi{0};
    uint64_t ike_remote_spi{0};
    uint8_t ike_state{0};
    bool ue_behind_nat{false};
    bool n3iwf_behind_nat{false};
    std::vector<RcChildSaInfoSnapshot> child_sa;
    RcMaskedImeisvSnapshot masked_imeisv;
    RcGuamiSnapshot guami;
    std::vector<RcSnssaiSnapshot> allowed_nssai;
    std::vector<int64_t> pdu_session_release_ids;
    std::vector<RcPduSessionSnapshot> pdu_sessions;
    std::map<std::string, std::string> extra_fields;
};

struct RcStationSnapshot {
    std::string interface_name;
    std::string mac;
    std::string ip;
    std::map<std::string, std::string> fields;
    std::map<std::string, std::string> hostapd;
    std::map<std::string, std::string> station_dump;
};

struct RcAssociationSnapshot {
    std::string interface_name;
    std::string mac;
    std::string ue_ip;
    RcStationSnapshot station;
    RcCountersSnapshot counters;
    RcUeInfoSnapshot ue;
    std::vector<std::string> mismatches;
};

struct RcSnapshot {
    std::string timestamp;
    std::vector<RcAssociationSnapshot> associations;
};

bool loadRcSnapshot(RcSnapshot &out);
std::vector<RcAssociationSnapshot> getRcAssociations();
std::optional<RcAssociationSnapshot> findRcAssociationByRanUeId(int64_t ran_ue_ngap_id);
std::optional<RcAssociationSnapshot> findRcAssociationByAmfUeId(int64_t amf_ue_ngap_id);
std::optional<RcAssociationSnapshot> findRcAssociationByMac(const std::string &mac);
void setRcLogFileName(const std::string &name);
