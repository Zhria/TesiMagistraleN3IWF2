#/*****************************************************************************
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
#******************************************************************************/

cmake_minimum_required(VERSION 3.5.1)
set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 17)



project(e2sim)

set (E2SIM_ROOT ./)


include_directories("${E2SIM_ROOT}")
include_directories("${E2SIM_ROOT}/src")
include_directories("${E2SIM_ROOT}/src/DEF")
include_directories("${E2SIM_ROOT}/src/SCTP/")
include_directories("${E2SIM_ROOT}/src/E2AP")
include_directories("${E2SIM_ROOT}/src/E2AP/E2SM")
include_directories("${E2SIM_ROOT}/ASN1c")


#set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG ON)

find_library( SCTP_STD_LIB sctp )  #needed for sctp_sendmsgf
find_package( Threads REQUIRED )

find_package(CURL REQUIRED)
find_package(yaml-cpp REQUIRED)         # <— importa il target 'yaml-cpp'
find_package(nlohmann_json REQUIRED)     # se lo usi come target


#----------------------------------------------
file(GLOB E2SIM_SOURCES
  "${E2SIM_ROOT}/e2sim.cpp"
  "${E2SIM_ROOT}/encode_kpm.cpp"
  "${E2SIM_ROOT}/encode_rc.cpp"
  "${E2SIM_ROOT}/rc_callbacks.cpp"
  "${E2SIM_ROOT}/encode_e2apv2.cpp"
  "${E2SIM_ROOT}/n3iwf_data.cpp"
  "${E2SIM_ROOT}/n3iwf_utils.cpp"
  "${E2SIM_ROOT}/src/DEF/*.cpp"
  "${E2SIM_ROOT}/src/SCTP/*.cpp"
  "${E2SIM_ROOT}/src/E2AP/*.c"
  "${E2SIM_ROOT}/src/E2AP/*.cpp"
  "${E2SIM_ROOT}/ASN1c/*.c"
)

# asn_config.h disables BER/UPER/OER/JER support, so drop their helpers.
# Keep only the aligned-PER/XER bits we actually use.
list(FILTER E2SIM_SOURCES EXCLUDE REGEX ".*/ASN1c/(ber_|der_|jer_|oer_|uper_).*\\.c$")
list(FILTER E2SIM_SOURCES EXCLUDE REGEX ".*/ASN1c/.*_(ber|jer|oer|uper)\\.c$")

add_executable(kpm_callbacks
  "${E2SIM_ROOT}/kpm_callbacks.cpp"
  ${E2SIM_SOURCES}
)

target_link_libraries( kpm_callbacks ${SCTP_STD_LIB}
    CURL::libcurl
    yaml-cpp                      
    nlohmann_json::nlohmann_json 
    Threads::Threads
 )

# Test standalone per RICcontrolRequest che chiama direttamente callback_rc_control_request
add_executable(rc_control_test
  "${E2SIM_ROOT}/test/rc_control_test.cpp"
  ${E2SIM_SOURCES}
)

target_link_libraries( rc_control_test ${SCTP_STD_LIB}
    CURL::libcurl
    yaml-cpp
    nlohmann_json::nlohmann_json
    Threads::Threads
)

# Standalone KPM v3 encode/decode exercise (optional; disable by default)
option(BUILD_TEST_KPM_REPORT_LOOP "Build the test_kpm_report_loop target" OFF)
set(FLEXRIC_KPM_LIB "/home/zakaria/flexricFeraudo/flexric-sm/build/src/sm/kpm_sm/kpm_sm_v03.00/libkpm_sm.so"
    CACHE FILEPATH "Path to libkpm_sm.so from FlexRIC (KPM v3)")

if(BUILD_TEST_KPM_REPORT_LOOP)
  if(EXISTS "${FLEXRIC_KPM_LIB}")
    add_executable(test_kpm_report_loop
      "${E2SIM_ROOT}/test/test_kpm_report_loop.cpp"
      ${E2SIM_SOURCES}
    )
    target_link_libraries( test_kpm_report_loop ${SCTP_STD_LIB}
        CURL::libcurl
        yaml-cpp
        nlohmann_json::nlohmann_json
        Threads::Threads
        ${FLEXRIC_KPM_LIB}
    )
    # Keep rpath so the linker can find the FlexRIC .so at runtime
    get_filename_component(_flexric_dir "${FLEXRIC_KPM_LIB}" DIRECTORY)
    set_target_properties(test_kpm_report_loop PROPERTIES
      BUILD_RPATH "${_flexric_dir}"
      INSTALL_RPATH "${_flexric_dir}"
    )
  else()
    message(WARNING "BUILD_TEST_KPM_REPORT_LOOP=ON but FLEXRIC_KPM_LIB not found at ${FLEXRIC_KPM_LIB}, skipping target.")
  endif()
endif()

#----------------------------------------------
#file(GLOB RICSIM_SOURCES

#  "${E2SIM_ROOT}/ricsim.cpp"
#  "${E2SIM_ROOT}/encode_e2apv2.cpp"
#  "${E2SIM_ROOT}/src/DEF/*.cpp"
#  "${E2SIM_ROOT}/src/SCTP/*.cpp"
#  "${E2SIM_ROOT}/src/E2APr/*.c"
#  "${E2SIM_ROOT}/src/E2APr/*.cpp"
#  "${E2SIM_ROOT}/ASN1c/*.c"
#  )
#add_executable(ricsim ${RICSIM_SOURCES})
#target_link_libraries( ricsim ${SCTP_STD_LIB}  )
