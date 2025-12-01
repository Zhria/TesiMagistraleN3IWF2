package message

import (
	"encoding/binary"
	"fmt"

	"github.com/free5gc/aper"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

// BuildPathSwitchRequest builds an NGAP PathSwitchRequest PDU for the given UE.
func BuildPathSwitchRequest(ranUe n3iwf_context.RanUe, gtpBindAddr string) ([]byte, error) {
	if ranUe == nil {
		return nil, errNilRanUe
	}

	shared := ranUe.GetSharedCtx()
	if shared == nil {
		return nil, errNilSharedCtx
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiating := pdu.InitiatingMessage
	initiating.ProcedureCode.Value = ngapType.ProcedureCodePathSwitchRequest
	initiating.Criticality.Value = ngapType.CriticalityPresentReject
	initiating.Value.Present = ngapType.InitiatingMessagePresentPathSwitchRequest
	initiating.Value.PathSwitchRequest = new(ngapType.PathSwitchRequest)

	req := initiating.Value.PathSwitchRequest
	ies := &req.ProtocolIEs

	// RAN UE NGAP ID
	ie := ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: shared.RanUeNgapId}
	ies.List = append(ies.List, ie)

	// Source AMF UE NGAP ID
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDSourceAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentSourceAMFUENGAPID
	ie.Value.SourceAMFUENGAPID = &ngapType.AMFUENGAPID{Value: shared.AmfUeNgapId}
	ies.List = append(ies.List, ie)

	// User location information
	ie = ngapType.PathSwitchRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = ranUe.GetUserLocationInformation()
	ies.List = append(ies.List, ie)

	// UE Security Capabilities (if available)
	if shared.SecurityCapabilities != nil {
		ie = ngapType.PathSwitchRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDUESecurityCapabilities
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.PathSwitchRequestIEsPresentUESecurityCapabilities
		ie.Value.UESecurityCapabilities = shared.SecurityCapabilities
		ies.List = append(ies.List, ie)
	}

	// PDU Session Resource To Be Switched DL List
	if len(shared.PduSessionList) > 0 {
		ie = ngapType.PathSwitchRequestIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceToBeSwitchedDLList
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.PathSwitchRequestIEsPresentPDUSessionResourceToBeSwitchedDLList
		ie.Value.PDUSessionResourceToBeSwitchedDLList = &ngapType.PDUSessionResourceToBeSwitchedDLList{}

		for id, sess := range shared.PduSessionList {
			if sess == nil || sess.GTPConnInfo == nil {
				logger.NgapLog.Warnf("Skip PDU Session %d for PathSwitch (missing GTP info)", id)
				continue
			}

			transfer, err := BuildPathSwitchRequestTransfer(sess, gtpBindAddr)
			if err != nil {
				logger.NgapLog.Errorf("Build PathSwitchRequestTransfer for PDU Session[%d] failed: %v", id, err)
				continue
			}

			item := ngapType.PDUSessionResourceToBeSwitchedDLItem{
				PDUSessionID:              ngapType.PDUSessionID{Value: id},
				PathSwitchRequestTransfer: transfer,
			}
			ie.Value.PDUSessionResourceToBeSwitchedDLList.List = append(ie.Value.PDUSessionResourceToBeSwitchedDLList.List, item)
		}

		if len(ie.Value.PDUSessionResourceToBeSwitchedDLList.List) > 0 {
			ies.List = append(ies.List, ie)
		}
	}

	return ngap.Encoder(pdu)
}

// BuildPathSwitchRequestTransfer builds the PathSwitchRequestTransfer per PDU session.
func BuildPathSwitchRequestTransfer(pduSession *n3iwf_context.PDUSession, gtpBindAddr string) ([]byte, error) {
	if pduSession == nil || pduSession.GTPConnInfo == nil {
		return nil, errNilPDUSession
	}

	transfer := ngapType.PathSwitchRequestTransfer{}

	// DL NG-U UP TNL Information (target address/TEID for DL)
	transfer.DLNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	transfer.DLNGUUPTNLInformation.GTPTunnel = &ngapType.GTPTunnel{
		TransportLayerAddress: ngapConvert.IPAddressToNgap(gtpBindAddr, ""),
		GTPTEID:               ngapType.GTPTEID{Value: make(aper.OctetString, 4)},
	}
	binary.BigEndian.PutUint32(transfer.DLNGUUPTNLInformation.GTPTunnel.GTPTEID.Value, pduSession.GTPConnInfo.IncomingTEID)

	// Qos Flow Accepted List
	for _, qfi := range pduSession.QFIList {
		transfer.QosFlowAcceptedList.List = append(
			transfer.QosFlowAcceptedList.List,
			ngapType.QosFlowAcceptedItem{
				QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: int64(qfi)},
			},
		)
	}
	if len(transfer.QosFlowAcceptedList.List) == 0 {
		transfer.QosFlowAcceptedList.List = append(transfer.QosFlowAcceptedList.List, ngapType.QosFlowAcceptedItem{QosFlowIdentifier: ngapType.QosFlowIdentifier{Value: 1}})
	}

	data, err := aper.MarshalWithParams(transfer, "valueExt")
	if err != nil {
		return nil, err
	}
	return data, nil
}

var (
	errNilRanUe      = fmt.Errorf("nil RanUE")
	errNilSharedCtx  = fmt.Errorf("nil shared UE context")
	errNilPDUSession = fmt.Errorf("nil PDUSession")
)
