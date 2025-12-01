#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>



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

extern struct timespec ts;
#include "n3iwf_utils.hpp"
#include <map>

//String ammettendo n variabili variabili
 void logln(const char* msg, ...) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    long seconds = now.tv_sec - ts.tv_sec;
    long nseconds = now.tv_nsec - ts.tv_nsec;
    if (nseconds < 0) {
        seconds -= 1;
        nseconds += 1000000000L;
    }
    printf("[%ld.%09ld] ", seconds, nseconds);
    va_list args;
    va_start(args, msg);
    vprintf(msg, args);
    va_end(args);
    printf("\n");
    fflush(stdout);
}
// Ritorna il numero di bit effettivi (size*8 - bits_unused)
static inline int bit_length(const BIT_STRING_t& bs) {
  if (!bs.buf || bs.size <= 0 || bs.bits_unused < 0 || bs.bits_unused > 7) return -1;
  return bs.size * 8 - bs.bits_unused;
}

// Copia di sicurezza per (ri)allocare il buffer
static bool realloc_and_zero(uint8_t** buf, int new_size) {
  uint8_t* nb = (uint8_t*)calloc(1, new_size);
  if (!nb) return false;
  free(*buf);
  *buf = nb;
  return true;
}

/**
 * Valida o corregge la lunghezza del gNB ID:
 * - Se 22 <= len <= 32: OK (nessuna modifica)
 * - Se len < 22: left-pad a 22 mantenendo il valore
 * - Se len > 32: errore
 *
 * Ritorna 0 se OK (o dopo fix), -1 se errore.
 */
int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits = 22,
                                  int max_bits = 32,
                                  int target_if_pad = 22) {
  if (!gnb_id_bs) return -1;
  if (min_bits < 1 || max_bits < min_bits) return -1;

  int total_bits = bit_length(*gnb_id_bs);
  if (total_bits < 0) return -1;

  if (total_bits > max_bits) {
    // Non tronchiamo: meglio segnalare errore
    logln("gNB ID too long: %d bits (max %d)\n", total_bits, max_bits);
    return -1;
  }

  if (total_bits >= min_bits && total_bits <= max_bits) {
    // Già valido: nessuna azione
    return 0;
  }

  // total_bits < min_bits -> left-pad a target_if_pad (tipicamente 22)
  const int target_bits = target_if_pad;
  if (target_bits < min_bits || target_bits > max_bits) return -1;

  // 1) Ricostruisci il valore intero corrente (big-endian), rimuovendo i bits_unused
  uint64_t value = 0;
  for (int i = 0; i < gnb_id_bs->size; ++i) {
    value = (value << 8) | gnb_id_bs->buf[i];
  }
  // Rimuove gli unused bit (in coda all'ultimo byte)
  if (gnb_id_bs->bits_unused > 0) {
    value >>= gnb_id_bs->bits_unused;
  }

  // A questo punto 'value' rappresenta i 'total_bits' effettivi del gNB ID.
  // 2) Prepara il nuovo contenitore con target_bits
  const int num_bytes = (target_bits + 7) / 8;
  const int bits_unused_new = num_bytes * 8 - target_bits;

  if (!realloc_and_zero(&gnb_id_bs->buf, num_bytes)) {
    return -1;
  }
  gnb_id_bs->size = num_bytes;
  gnb_id_bs->bits_unused = bits_unused_new;

  // 3) Inserisci il valore nei target_bits *senza* cambiarlo (vero left-pad)
  // Per codifica ASN.1 BIT STRING: i bit inutilizzati sono in coda ⇒ shiftiamo a sinistra di bits_unused_new
  uint64_t out = value;
  out <<= bits_unused_new;

  // 4) Scrivi in big-endian
  for (int i = num_bytes - 1; i >= 0; --i) {
    gnb_id_bs->buf[i] = static_cast<uint8_t>(out & 0xFF);
    out >>= 8;
  }

  return 0;
}


// List of KPIs that the simulator can populate in KPM indications.
std::vector<std::string> getAllowedKPI() {
    return {
        "DRB.UEThpDl",         // Throughput downlink per UE/DRB (classico CU-UP)
        "DRB.UEThpUl",         // Throughput uplink per UE/DRB
        "DRB.RlcSduTransmittedVolumeDL" , // RLC SDU Transmitted Volume DL per UE/DRB O-RAN metric
        "DRB.RlcSduTransmittedVolumeUL" , // RLC SDU Transmitted Volume UL per UE/DRB O-RAN metric
        "DRB.RlcPacketDropRateDLDist", // RLC Packet Drop Rate DL per UE/DRB
        "DRB.RlcPacketLossRateULDist", // RLC Packet Loss Rate UL per UE/DRB
        /*// Extended UE level KPIs derived from RC logger
        "UE.ActiveUeCount",
        "UE.SignalStrengthAvgDbm",
        "UE.TxBytesWiFi",
        "UE.RxBytesWiFi",
        "UE.TxPacketsWiFi",
        "UE.RxPacketsWiFi",
        "UE.TxRetryRatePercent",
        "UE.ConnectionTimeAvgSec",
        "UE.InactiveTimeAvgSec",
        "UE.TxBitrateAvgMbps",
        "UE.RxBitrateAvgMbps"*/
    };
}

std::vector<std::string> getJSONKeysKPM(){
  return {
    "incomingOctets",
    "transmitOctets",
    "droppedOctets"
  };
}

// RAN Parameters that are declared as part of the RC report style.
std::map<long,std::string> getAllowedReportMetricsRC(){
    return {
        // L3 / UE context
        {41001, "UE ID"},             // (IE referenziato in 9.3.10; qui come RAN param per AD/IM)
        {41002, "Old UE ID"},         // UE ID precedente (Style 4)
        {41003, "RRC State"},         // vedi 7.3.5 (RRC state change)

        // Messaggio che ha causato il cambio UE ID (context)
        {41010, "Triggering NI/RRC Message"},

        {42001, "UE RSRP"},

        // Variabili L2 UE (raggruppo esempi comuni: PDCP/RLC/MAC)
        {43001, "PDCP UL Throughput"},
        {43002, "PDCP DL Throughput"},


        // Traffico aggregato per-UE
        {44001, "UL Data Volume"},
        {44002, "DL Data Volume"}
    };
}

// RAN Parameters consumed/produced by RC control actions.
std::map<long,std::string> getAllowedControlMetricsRC(){
    return {
        {1, "Target Primary Cell ID"},
        {2, "CHOICE Target Cell"},
        {3, "NR Cell"},
        {4, "NR CGI"},
        {5, "E-UTRA Cell"},
        {6, "E-UTRA CGI"},
        {7, "List of PDU sessions for handover"},
        {8, "PDU session Item for handover"},
        {9, "PDU session ID"},
        {10, "List of QoS flows in the PDU session"},
        {11, "QoS flow Item"},
        {12, "QoS Flow Identifier"},
        {13, "List of DRBs for handover"},
        {14, "DRB item for handover"},
        {15, "DRB ID"},
        {16, "List of QoS flows to be modified in DRB"},
        {17, "QoS flow Item"},
        {18, "QoS flow Identifier"},
        {19, "List of Secondary cells to be setup"},
        {20, "Secondary cell Item to be setup"},
        {21, "Secondary Cell ID"},
    };
}


// UE identification parameters referenced in the RC event trigger definition.
std::map<long,std::string> getUEIdentifierRC(){
    return {
        {35010, "S-NSSAI"},     // STRUCTURE
        {35011, "SST"},        // ELEMENT (SST)
        {35012, "SD"},         // ELEMENT (SD)
        {35091, "UE ID"}       // ELEMENT (OCTET STRING) – vedi 9.3.10
    };
}
