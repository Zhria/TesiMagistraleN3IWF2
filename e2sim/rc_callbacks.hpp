#ifndef E2SIM_RC_CALLBACKS_HPP
#define E2SIM_RC_CALLBACKS_HPP

#include <vector>

#include "subscription_key.hpp"
#include "e2sim.hpp"

extern "C" {
#include "E2AP-PDU.h"
}

void callback_rc_subscription_request(E2AP_PDU_t *pdu);
void callback_rc_control_request(E2AP_PDU_t *pdu);
void registerRCfunctionDefinition(E2Sim &e2);
void stop_rc_worker(const SubscriptionKey &key);
void stop_all_rc_workers();

#endif  // E2SIM_RC_CALLBACKS_HPP
