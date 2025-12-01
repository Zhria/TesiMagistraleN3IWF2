/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/

#include "e2sim_defs.h"

#include <getopt.h>
#include <sys/time.h>
#include <time.h>

#include <algorithm>    // std::min, std::max
#include <cstring>      // strcmp, memcpy, strdup (POSIX)
#include <cstdlib>      // atoi, getenv, malloc, exit
#include <stdexcept>
#include <string>
#include <fstream>

#include <yaml-cpp/yaml.h>

// Se qualche header legacy ha definito macro min/max, disattivali qui
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

// Helper: duplica una std::string in un buffer C-allocato (evita use-after-free)
static inline char* dup_cstr(const std::string& s) {
  char* p = static_cast<char*>(std::malloc(s.size() + 1));
  if (!p) return nullptr;
  std::memcpy(p, s.c_str(), s.size() + 1);
  return p;
}

char* time_stamp(void)
{
  timeval curTime;
  gettimeofday(&curTime, NULL);
  int milli = curTime.tv_usec / 1000;

  char buffer[80];
  strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&curTime.tv_sec));

  const int time_buffer_len = 84;
  static char currentTime[time_buffer_len] = "";
  snprintf(currentTime, time_buffer_len, "%s:%03d", buffer, milli);

  return currentTime;
}

options_t read_input_options(int argc, char *argv[])
{
  options_t options;
  options.server_ip   = (char*)DEFAULT_SCTP_IP;
  options.server_port = X2AP_SCTP_PORT;
  options.local_ip = (char*)DEFAULT_LOCAL_IP;
 
  // Log workdir se definito (evita costruzione da NULL)
  {
    const char* wd = std::getenv(WORKDIR_ENV);
    if (wd) {
      LOG_I("Using workdir from environment variable %s=%s", WORKDIR_ENV, wd);
    } else {
      LOG_I("Using default workdir");
    }
  }

  // Parsing argomenti
  const char* config_path = nullptr;
  const char* positional_ip   = nullptr;
  const char* positional_port = nullptr;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "-c") == 0) {
      if (i + 1 >= argc) {
        LOG_E("Option -c requires a path argument.\n");
        std::exit(1);
      }
      config_path = argv[++i];
    } else if (!positional_ip) {
      positional_ip = argv[i];
    } else if (!positional_port) {
      positional_port = argv[i];
    } else {
      LOG_E("Unrecognized extra argument: %s\n", argv[i]);
      LOG_I("Usage: %s [-c <config.yaml>] [SERVER IP] [SERVER PORT]\n", argv[0]);
      std::exit(1);
    }
  }

  // Se c'è -c, usa YAML
  if (config_path) {
    // verifica esistenza file
    std::ifstream f(config_path);
    if (!f.good()) {
      LOG_E("Config file not found: %s\n", config_path);
      std::exit(1);
    }

    try {
      YAML::Node root = YAML::LoadFile(config_path);
      YAML::Node cfg  = root["configuration"];
      if (!cfg) {
        LOG_E("Missing 'configuration' section in %s\n", config_path);
        std::exit(1);
      }

      // ricAddress: lista; prendiamo il primo elemento
      std::string ricAddr;
      if (cfg["ricAddress"] && cfg["ricAddress"].IsSequence() && cfg["ricAddress"].size() > 0) {
        ricAddr = cfg["ricAddress"][0].as<std::string>("");
      } else if (cfg["ricAddress"] && cfg["ricAddress"].IsScalar()) {
        // fallback: se qualcuno ha messo direttamente una stringa
        ricAddr = cfg["ricAddress"].as<std::string>("");
      }

      std::string localAddr;
      if (cfg["localAddress"] && cfg["localAddress"].IsSequence() && cfg["localAddress"].size() > 0) {
        localAddr = cfg["localAddress"][0].as<std::string>("");
      } else if (cfg["localAddress"] && cfg["localAddress"].IsScalar()) {
        // fallback: se qualcuno ha messo direttamente una stringa
        localAddr = cfg["localAddress"].as<std::string>("");
      }

      // URL HTTP per il trigger dell'handover verso l'N3IWF (opzionale).
      // Se presente, viene propagata alla logica RC tramite variabile
      // d'ambiente RC_HANDOVER_TRIGGER_URL, evitando indirizzi hardcoded.
      std::string hoUrl;
      if (cfg["n3iwfHandoverUrl"] && cfg["n3iwfHandoverUrl"].IsScalar()) {
        hoUrl = cfg["n3iwfHandoverUrl"].as<std::string>("");
      }
      long gnbCuUpId = -1;
      if (cfg["gnbCuUpId"]) {
        gnbCuUpId = cfg["gnbCuUpId"].as<long>(-1);
      }
      long gnbDuId = -1;
      if (cfg["gnbDuId"]) {
        gnbDuId = cfg["gnbDuId"].as<long>(-1);
      }
      int ricPort = -1;
      if (cfg["ricPort"]) {
        ricPort = cfg["ricPort"].as<int>(-1);
      }

      if (ricAddr.empty() || ricPort <= 0 || ricPort > 65535) {
        LOG_E("Invalid or missing ricAddress/ricPort in %s\n", config_path);
        std::exit(1);
      }

      // assegna a options (duplichiamo la stringa per avere storage proprio)
      char* locAddr = dup_cstr(localAddr);
      if (!locAddr) {
        LOG_E("Out of memory while duplicating localAddress\n");
        std::exit(1);
      }

            // assegna a options (duplichiamo la stringa per avere storage proprio)
      char* ipdup = dup_cstr(ricAddr);
      if (!ipdup) {
        LOG_E("Out of memory while duplicating ricAddress\n");
        std::exit(1);
      }
      options.server_ip   = ipdup;
      options.server_port = ricPort;
      options.local_ip = locAddr;
      options.gNB_CU_UP_ID = gnbCuUpId;
      options.gNB_DU_ID = gnbDuId;

      LOG_I("Loaded RIC from config: %s:%d", options.server_ip, options.server_port);

      if (!hoUrl.empty()) {
        if (setenv("RC_HANDOVER_TRIGGER_URL", hoUrl.c_str(), 1) != 0) {
          LOG_E("Failed to set RC_HANDOVER_TRIGGER_URL from config (n3iwfHandoverUrl)\n");
        } else {
          LOG_I("Using N3IWF handover URL from config: %s", hoUrl.c_str());
        }
      }
    } catch (const std::exception& e) {
      LOG_E("Failed to parse YAML config %s: %s\n", config_path, e.what());
      std::exit(1);
    }
    return options;
  }

  // Altrimenti: IP/PORT posizionali o default (logica esistente)
  if (positional_ip && positional_port) {
    options.server_ip   = const_cast<char*>(positional_ip);
    options.server_port = std::atoi(positional_port);
    if (options.server_port < 1 || options.server_port > 65535) {
      LOG_E("Invalid port number (%d). Valid values are 1..65535.\n", options.server_port);
      std::exit(1);
    }
  } else if (positional_ip) {
    options.server_ip = const_cast<char*>(positional_ip);
  } else {
    options.server_ip = (char*)DEFAULT_SCTP_IP;
  }

  return options;
}
