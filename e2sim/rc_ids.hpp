#ifndef E2SIM_RC_IDS_HPP
#define E2SIM_RC_IDS_HPP

#include <string_view>

#include "n3iwf_utils.hpp"

inline const long kRcControlStyleTypeHandover = 3;
inline const long kRcControlActionIdHandover = 1;

inline long lookup_rc_control_param_id(std::string_view name, long fallback) {
  const auto metrics = getAllowedControlMetricsRC();
  for (const auto &entry : metrics) {
    if (entry.second == name) {
      return entry.first;
    }
  }
  return fallback;
}

inline const long kRcParamTargetCellPci =
    lookup_rc_control_param_id("Target Primary Cell ID", 1);
inline const long kRcParamTargetNrCgi =
    lookup_rc_control_param_id("NR CGI", 4);
inline const long kRcLegacyParamTargetGNbId =
    lookup_rc_control_param_id("Target gNB ID", 45002);
inline const long kRcParamHoCause =
    lookup_rc_control_param_id("Handover Cause", 45010);
inline const long kRcParamUeId =
    lookup_rc_control_param_id("UE ID", 41001);

inline constexpr long kRcOutcomeStatus = 50001;
inline constexpr long kRcOutcomeNotes = 50002;

#endif  // E2SIM_RC_IDS_HPP
