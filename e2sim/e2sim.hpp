#ifndef E2SIM_HPP
#define E2SIM_HPP

#include <unordered_map>

extern "C" {
#include "E2AP-PDU.h"
#include "OCTET_STRING.h"
#include "E2SM-KPM-ActionDefinition-Format1.h"
#include "MeasurementType.h"
#include "MeasurementInfoItem.h"
#include "E2SM-KPM-ActionDefinition.h"
}

typedef void (*SubscriptionCallback)(E2AP_PDU_t*);
typedef void (*ControlCallback)(E2AP_PDU_t*);

class E2Sim;
class E2Sim {

private:

  std::unordered_map<long, OCTET_STRING_t*> ran_functions_registered;
  std::unordered_map<long, SubscriptionCallback> subscription_callbacks;
  std::unordered_map<long, PrintableString_t*> ran_function_oids;  
  std::unordered_map<long, ControlCallback> control_callbacks;
public:

  SubscriptionCallback get_subscription_callback(long func_id);
  ControlCallback get_control_callback(long func_id);
  
  void register_e2sm(long func_id, OCTET_STRING_t* ostr);

  void register_subscription_callback(long func_id, SubscriptionCallback cb);
  void register_control_callback(long func_id, ControlCallback cb);
  
  void encode_and_send_sctp_data(E2AP_PDU_t* pdu);

  int run_loop(int argc, char* argv[]);

  std::unordered_map<long, OCTET_STRING_t *> get_registered_e2sm();

  void register_e2sm_oid(long func_id, PrintableString_t* oid);

  PrintableString_t* get_e2sm_oid(long func_id);

};

#endif
