#ifndef E2SIM_SUBSCRIPTION_KEY_HPP
#define E2SIM_SUBSCRIPTION_KEY_HPP

#include <tuple>

struct SubscriptionKey {
  long requestorId{};
  long instanceId{};
  long ranFunctionId{};
  long actionId{};

  bool operator<(const SubscriptionKey &other) const {
    return std::tie(requestorId, instanceId, ranFunctionId, actionId) <
           std::tie(other.requestorId, other.instanceId, other.ranFunctionId, other.actionId);
  }
};

#endif  // E2SIM_SUBSCRIPTION_KEY_HPP
