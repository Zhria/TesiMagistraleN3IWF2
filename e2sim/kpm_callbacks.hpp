#include <atomic>
#include <memory>

#include "GranularityPeriod.h"
#include "e2sim.hpp"

void callback_kpm_subscription_request(E2AP_PDU_t *pdu);

void run_report_loop(long requestorId, long instanceId, long ranFunctionId, long actionId, GranularityPeriod_t granularityPeriod, const std::shared_ptr<std::atomic_bool>& stop_token);

void registerKPMfunctionDefinition();

void stop_kpm_subscription(long requestorId, long instanceId, long ranFunctionId);
