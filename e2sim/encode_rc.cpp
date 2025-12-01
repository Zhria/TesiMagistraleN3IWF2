#include "encode_rc.hpp"
#include "n3iwf_utils.hpp"
#include "rc_ids.hpp"

// Utility helpers
static void add_event_trigger(RANFunctionDefinition_EventTrigger *ev){
    //ADD EVENT TRIGGER STYLE
    RIC_EventTriggerStyle_Item_t *et = (RIC_EventTriggerStyle_Item_t*)calloc(1, sizeof(RIC_EventTriggerStyle_Item_t));
    if(!et) return;
    et->ric_EventTriggerStyle_Type = 4;
    OCTET_STRING_fromBuf(&et->ric_EventTriggerStyle_Name,"UE Information Change", strlen("UE Information Change"));
    et->ric_EventTriggerFormat_Type = 4;
    ASN_SEQUENCE_ADD(&ev->ric_EventTriggerStyle_List.list, et);

/*
    //Periodic report also
    RIC_EventTriggerStyle_Item_t *et2 = (RIC_EventTriggerStyle_Item_t*)calloc(1, sizeof(RIC_EventTriggerStyle_Item_t));
    if(!et2) return -1;
    et2->ric_EventTriggerStyle_Type = 1;
    OCTET_STRING_fromBuf(&et2->ric_EventTriggerStyle_Name,"Periodic Report", strlen("Periodic Report"));
    et2->ric_EventTriggerFormat_Type = 1;
    ASN_SEQUENCE_ADD(&ev->ric_EventTriggerStyle_List.list, et2);
*/
    ev->ran_UEIdentificationParameters_List = (RANFunctionDefinition_EventTrigger::RANFunctionDefinition_EventTrigger__ran_UEIdentificationParameters_List *) calloc(1, sizeof(*ev->ran_UEIdentificationParameters_List));


    std::map<long,std::string> maps=getUEIdentifierRC();
    //UE IDENTIFICATION PARAMETERS LIST
    for(const auto &metric : maps){
        UEIdentification_RANParameter_Item_t *ue_param = (UEIdentification_RANParameter_Item_t*)calloc(1, sizeof(UEIdentification_RANParameter_Item_t));
        ue_param->ranParameter_ID = metric.first;
        OCTET_STRING_fromBuf(&ue_param->ranParameter_name, metric.second.c_str(), metric.second.length());
        ASN_SEQUENCE_ADD(&ev->ran_UEIdentificationParameters_List->list, ue_param);
    }
}


static void add_report_style(RANFunctionDefinition_Report *rep){

    RANFunctionDefinition_Report_Item *rs =(RANFunctionDefinition_Report_Item*)calloc(1, sizeof(RANFunctionDefinition_Report_Item));
    rs->ric_ReportStyle_Type = 4; //UE Info
    OCTET_STRING_fromBuf(&rs->ric_ReportStyle_Name,"UE Measurement Report", strlen("UE Measurement Report"));
    rs->ric_SupportedEventTriggerStyle_Type = 4; //UE Info
    rs->ric_ReportActionFormat_Type  = 1;
    rs->ric_IndicationHeaderFormat_Type  = 1;
    rs->ric_IndicationMessageFormat_Type = 2;

    rs->ran_ReportParameters_List = (RANFunctionDefinition_Report_Item::RANFunctionDefinition_Report_Item__ran_ReportParameters_List *) calloc(1, sizeof(*rs->ran_ReportParameters_List));

    std::map<long,std::string> list=getAllowedReportMetricsRC(); //See chapter 8.2.4
    for (const auto &kpi : list)
    {
        Report_RANParameter_Item *mi = (Report_RANParameter_Item *)calloc(1, sizeof(Report_RANParameter_Item));
        mi->ranParameter_ID = kpi.first;
        OCTET_STRING_fromBuf(&mi->ranParameter_name, kpi.second.c_str(), strlen(kpi.second.c_str()));
        ASN_SEQUENCE_ADD(&rs->ran_ReportParameters_List->list, mi);
    }

    ASN_SEQUENCE_ADD(&rep->ric_ReportStyle_List.list, rs);
    return;
}

// Adds a control style entry (can be invoked multiple times for different styles).
static void add_control_style(RANFunctionDefinition_Control *ctl,
                              long style_type,
                              const char *style_name){
    RANFunctionDefinition_Control_Item *ctrl = (RANFunctionDefinition_Control_Item*)calloc(1, sizeof(RANFunctionDefinition_Control_Item));
    ctrl->ric_ControlStyle_Type = style_type;
    OCTET_STRING_fromBuf(&ctrl->ric_ControlStyle_Name, style_name, strlen(style_name));
    ctrl->ric_ControlHeaderFormat_Type  = 1;  // header carries UE/Cell information
    ctrl->ric_ControlMessageFormat_Type = 1;  // payload describes the handover target
    ctrl->ric_ControlOutcomeFormat_Type = 1;  // outcome ACK/FAIL

    ctrl->ric_ControlAction_List = (decltype(ctrl->ric_ControlAction_List))calloc(1, sizeof(*ctrl->ric_ControlAction_List));
    if (ctrl->ric_ControlAction_List) {
        auto *action = (RANFunctionDefinition_Control_Action_Item*)calloc(1, sizeof(RANFunctionDefinition_Control_Action_Item));
        action->ric_ControlAction_ID = kRcControlActionIdHandover;
        OCTET_STRING_fromBuf(&action->ric_ControlAction_Name, "Handover Control", strlen("Handover Control"));

        action->ran_ControlActionParameters_List = (decltype(action->ran_ControlActionParameters_List))calloc(1, sizeof(*action->ran_ControlActionParameters_List));
        if (action->ran_ControlActionParameters_List) {
            const auto control_params = getAllowedControlMetricsRC();
            for (const auto &entry : control_params) {
                ControlAction_RANParameter_Item *param =
                    (ControlAction_RANParameter_Item*)calloc(1, sizeof(ControlAction_RANParameter_Item));
                if (!param) {
                    continue;
                }
                param->ranParameter_ID = entry.first;
                OCTET_STRING_fromBuf(&param->ranParameter_name,
                                     entry.second.c_str(),
                                     entry.second.size());
                ASN_SEQUENCE_ADD(&action->ran_ControlActionParameters_List->list, param);
            }
        }
        ASN_SEQUENCE_ADD(&ctrl->ric_ControlAction_List->list, action);
    }
    /* Not needed by the xApp
    ctrl->ran_ControlOutcomeParameters_List = (decltype(ctrl->ran_ControlOutcomeParameters_List))calloc(1, sizeof(*ctrl->ran_ControlOutcomeParameters_List));
    if (ctrl->ran_ControlOutcomeParameters_List) {
        auto add_out_param = [&](long id, const char *name) {
            ControlOutcome_RANParameter_Item *param = (ControlOutcome_RANParameter_Item*)calloc(1, sizeof(ControlOutcome_RANParameter_Item));
            if (!param) return;
            param->ranParameter_ID = id;
            OCTET_STRING_fromBuf(&param->ranParameter_name, name, strlen(name));
            ASN_SEQUENCE_ADD(&ctrl->ran_ControlOutcomeParameters_List->list, param);
        };
        add_out_param(kRcOutcomeStatus, "Execution Status");
        add_out_param(kRcOutcomeNotes, "Execution Notes");
    }
    */
    ASN_SEQUENCE_ADD(&ctl->ric_ControlStyle_List.list, ctrl);
    return;
}


static void add_insert_style(RANFunctionDefinition_Insert *insert){
    if (!insert) {
        return;
    }

    RANFunctionDefinition_Insert_Item *item =
        (RANFunctionDefinition_Insert_Item *)calloc(1, sizeof(RANFunctionDefinition_Insert_Item));
    if (!item) {
        return;
    }

    item->ric_InsertStyle_Type = 1;
    OCTET_STRING_fromBuf(&item->ric_InsertStyle_Name, "UE Context Insert", strlen("UE Context Insert"));
    item->ric_SupportedEventTriggerStyle_Type = 4;
    item->ric_ActionDefinitionFormat_Type = 4;
    item->ric_IndicationHeaderFormat_Type = 2;
    item->ric_IndicationMessageFormat_Type = 6;
    item->ric_CallProcessIDFormat_Type = 1;

    ASN_SEQUENCE_ADD(&insert->ric_InsertStyle_List.list, item);
}

static void add_policy_style(RANFunctionDefinition_Policy *policy){
//Estendibile in futuro
}

void encode_rc_function_definition(E2SM_RC_RANFunctionDefinition* desc){

  // RANfunction-Name / OID / Instance
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-RC", strlen("ORAN-E2SM-RC"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_Description, "RAN Control", strlen("RAN Control"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_E2SM_OID, "1.3.6.1.4.1.53148.1.1.2.3", strlen("1.3.6.1.4.1.53148.1.1.2.3"));
  desc->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *desc->ranFunction_Name.ranFunction_Instance = 3;

  desc->ranFunctionDefinition_EventTrigger=(RANFunctionDefinition_EventTrigger*)calloc(1,sizeof(RANFunctionDefinition_EventTrigger));
  add_event_trigger(desc->ranFunctionDefinition_EventTrigger);

  desc->ranFunctionDefinition_Report=(RANFunctionDefinition_Report*)calloc(1,sizeof(RANFunctionDefinition_Report));
  add_report_style(desc->ranFunctionDefinition_Report);

  desc->ranFunctionDefinition_Control = (RANFunctionDefinition_Control*)calloc(1, sizeof(RANFunctionDefinition_Control));
  add_control_style(desc->ranFunctionDefinition_Control,
                    kRcControlStyleTypeHandover,
                    "Connected mode mobility control");
/* 
  desc->ranFunctionDefinition_Insert=(RANFunctionDefinition_Insert*)calloc(1,sizeof(RANFunctionDefinition_Insert));
  add_insert_style(desc->ranFunctionDefinition_Insert);

  desc->ranFunctionDefinition_Policy=(RANFunctionDefinition_Policy*)calloc(1,sizeof(RANFunctionDefinition_Policy));
  add_policy_style(desc->ranFunctionDefinition_Policy);
*/

  return;

}
