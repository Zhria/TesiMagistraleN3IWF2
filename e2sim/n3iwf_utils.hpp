#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>


//Include std map
#include <map>


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

static inline int bit_length(const BIT_STRING_t& bs);
static bool realloc_and_zero(uint8_t** buf, int new_size);


int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits,
                                  int max_bits,
                                  int target_if_pad);
                                  
void logln(const char* msg, ...);

// Returns the list of KPI names supported by the KPM indication loop.
std::vector<std::string> getAllowedKPI();

// Returns the RAN Parameter IDs exposed by the RC REPORT style.
std::map<long,std::string> getAllowedReportMetricsRC();

// Returns the RC control action/outcome parameter IDs.
std::map<long,std::string> getAllowedControlMetricsRC();

// Returns the UE identification parameters advertised by the RC event trigger.
std::map<long,std::string> getUEIdentifierRC();
