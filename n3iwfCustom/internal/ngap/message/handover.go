package message

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/free5gc/aper"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
)

func BuildHandoverRequired(
	ranUe n3iwf_context.RanUe,
	evt *n3iwf_context.TriggerHandoverEvt,
) ([]byte, error) {
	if ranUe == nil {
		return nil, errors.New("nil RanUE")
	}
	if evt == nil {
		return nil, errors.New("nil handover trigger event")
	}
	if evt.TargetID == nil {
		return nil, errors.New("nil TargetID in handover trigger")
	}

	sharedCtx := ranUe.GetSharedCtx()
	if sharedCtx == nil {
		return nil, errors.New("missing shared UE context")
	}
	if sharedCtx.AMF == nil {
		return nil, errors.New("RanUE is not attached to an AMF")
	}
	if sharedCtx.AmfUeNgapId == n3iwf_context.AmfUeNgapIdUnspecified {
		return nil, fmt.Errorf("AMF UE NGAP ID unspecified for RanUE %d", sharedCtx.RanUeNgapId)
	}

	pduItems := evt.PDUSessionResourceHORqd
	if len(pduItems) == 0 {
		var err error
		pduItems, err = buildPDUSessionResourceHORqd(sharedCtx, evt.DirectForwardingAvailable)
		if err != nil {
			return nil, fmt.Errorf("build pdu session resource list: %w", err)
		}
	}

	sourceToTarget := evt.SourceToTargetContainer
	if len(sourceToTarget) == 0 {
		var err error
		sourceToTarget, err = buildSourceToTargetTransparentContainer(sharedCtx, evt.TargetID)
		if err != nil {
			return nil, fmt.Errorf("build source to target transparent container: %w", err)
		}
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentHandoverRequired
	initiatingMessage.Value.HandoverRequired = new(ngapType.HandoverRequired)

	handoverRequired := initiatingMessage.Value.HandoverRequired
	handoverRequiredIEs := &handoverRequired.ProtocolIEs

	// AMF UE NGAP ID
	amfUeNgapIDIE := ngapType.HandoverRequiredIEs{}
	amfUeNgapIDIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfUeNgapIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	amfUeNgapIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	amfUeNgapIDIE.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{
		Value: sharedCtx.AmfUeNgapId,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, amfUeNgapIDIE)

	// RAN UE NGAP ID
	ranUeNgapIDIE := ngapType.HandoverRequiredIEs{}
	ranUeNgapIDIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranUeNgapIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	ranUeNgapIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentRANUENGAPID
	ranUeNgapIDIE.Value.RANUENGAPID = &ngapType.RANUENGAPID{
		Value: sharedCtx.RanUeNgapId,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ranUeNgapIDIE)

	// Handover Type (default to intra-5GS)
	handoverTypeIE := ngapType.HandoverRequiredIEs{}
	handoverTypeIE.Id.Value = ngapType.ProtocolIEIDHandoverType
	handoverTypeIE.Criticality.Value = ngapType.CriticalityPresentReject
	handoverTypeIE.Value.Present = ngapType.HandoverRequiredIEsPresentHandoverType
	handoverTypeIE.Value.HandoverType = &ngapType.HandoverType{
		Value: ngapType.HandoverTypePresentIntra5gs,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, handoverTypeIE)

	// Cause
	causeIE := ngapType.HandoverRequiredIEs{}
	causeIE.Id.Value = ngapType.ProtocolIEIDCause
	causeIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	causeIE.Value.Present = ngapType.HandoverRequiredIEsPresentCause
	causeCopy := evt.Cause
	causeIE.Value.Cause = &causeCopy
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, causeIE)

	// Target ID
	targetIDIE := ngapType.HandoverRequiredIEs{}
	targetIDIE.Id.Value = ngapType.ProtocolIEIDTargetID
	targetIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	targetIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentTargetID
	targetIDCopy := *evt.TargetID
	targetIDIE.Value.TargetID = &targetIDCopy
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, targetIDIE)

	// Direct Forwarding Path Availability (present if true)
	if evt.DirectForwardingAvailable {
		directForwardingIE := ngapType.HandoverRequiredIEs{}
		directForwardingIE.Id.Value = ngapType.ProtocolIEIDDirectForwardingPathAvailability
		directForwardingIE.Criticality.Value = ngapType.CriticalityPresentIgnore
		directForwardingIE.Value.Present = ngapType.HandoverRequiredIEsPresentDirectForwardingPathAvailability
		directForwardingIE.Value.DirectForwardingPathAvailability = &ngapType.DirectForwardingPathAvailability{
			Value: ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable,
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, directForwardingIE)
	}

	// PDU Session Resource List
	if len(pduItems) > 0 {
		pduListIE := ngapType.HandoverRequiredIEs{}
		pduListIE.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListHORqd
		pduListIE.Criticality.Value = ngapType.CriticalityPresentReject
		pduListIE.Value.Present = ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd
		pduListIE.Value.PDUSessionResourceListHORqd = new(ngapType.PDUSessionResourceListHORqd)

		for _, item := range pduItems {
			cloned := ngapType.PDUSessionResourceItemHORqd{
				PDUSessionID:             item.PDUSessionID,
				HandoverRequiredTransfer: append(aper.OctetString(nil), item.HandoverRequiredTransfer...),
				IEExtensions:             item.IEExtensions,
			}
			pduListIE.Value.PDUSessionResourceListHORqd.List = append(
				pduListIE.Value.PDUSessionResourceListHORqd.List,
				cloned,
			)
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, pduListIE)
	}

	// Source to Target Transparent Container
	if len(sourceToTarget) > 0 {
		containerIE := ngapType.HandoverRequiredIEs{}
		containerIE.Id.Value = ngapType.ProtocolIEIDSourceToTargetTransparentContainer
		containerIE.Criticality.Value = ngapType.CriticalityPresentReject
		containerIE.Value.Present = ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer
		containerIE.Value.SourceToTargetTransparentContainer = &ngapType.SourceToTargetTransparentContainer{
			Value: aper.OctetString(append([]byte(nil), sourceToTarget...)),
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, containerIE)
	}

	return ngap.Encoder(pdu)
}

func BuildHandoverPreparationFailure(
	amfUeNgapId int64,
	ranUeNgapId *int64,
	cause ngapType.Cause,
) ([]byte, error) {
	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)

	unsuccessful := pdu.UnsuccessfulOutcome
	unsuccessful.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	unsuccessful.Criticality.Value = ngapType.CriticalityPresentReject
	unsuccessful.Value.Present = ngapType.UnsuccessfulOutcomePresentHandoverPreparationFailure
	unsuccessful.Value.HandoverPreparationFailure = new(ngapType.HandoverPreparationFailure)

	handoverFailure := unsuccessful.Value.HandoverPreparationFailure
	handoverFailureIEs := &handoverFailure.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverPreparationFailureIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapId}
	handoverFailureIEs.List = append(handoverFailureIEs.List, ie)

	// RAN UE NGAP ID (optional)
	if ranUeNgapId != nil {
		ie = ngapType.HandoverPreparationFailureIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentRANUENGAPID
		ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: *ranUeNgapId}
		handoverFailureIEs.List = append(handoverFailureIEs.List, ie)
	}

	// Cause
	ie = ngapType.HandoverPreparationFailureIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentCause
	causeCopy := cause
	ie.Value.Cause = &causeCopy
	handoverFailureIEs.List = append(handoverFailureIEs.List, ie)

	return ngap.Encoder(pdu)
}

type HandoverAdmittedItem struct {
	PDUSessionID int64
	Transfer     []byte
}

type HandoverFailedItem struct {
	PDUSessionID int64
	Transfer     []byte
}

func BuildHandoverRequestAcknowledge(
	ranUe n3iwf_context.RanUe,
	admitted []HandoverAdmittedItem,
	failed []HandoverFailedItem,
	targetToSourceContainer []byte,
) ([]byte, error) {
	if ranUe == nil {
		return nil, errors.New("nil RanUE")
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
	pdu.SuccessfulOutcome = new(ngapType.SuccessfulOutcome)

	successful := pdu.SuccessfulOutcome
	successful.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
	successful.Criticality.Value = ngapType.CriticalityPresentReject
	successful.Value.Present = ngapType.SuccessfulOutcomePresentHandoverRequestAcknowledge
	successful.Value.HandoverRequestAcknowledge = new(ngapType.HandoverRequestAcknowledge)

	handoverAck := successful.Value.HandoverRequestAcknowledge
	ackIEs := &handoverAck.ProtocolIEs

	sharedCtx := ranUe.GetSharedCtx()

	// AMF UE NGAP ID
	ie := ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: sharedCtx.AmfUeNgapId}
	ackIEs.List = append(ackIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: sharedCtx.RanUeNgapId}
	ackIEs.List = append(ackIEs.List, ie)

	if len(admitted) > 0 {
		pduSessionAdmittedList := ngapType.PDUSessionResourceAdmittedList{}
		for _, item := range admitted {
			admittedItem := ngapType.PDUSessionResourceAdmittedItem{
				PDUSessionID: ngapType.PDUSessionID{
					Value: item.PDUSessionID,
				},
				HandoverRequestAcknowledgeTransfer: item.Transfer,
			}
			pduSessionAdmittedList.List = append(pduSessionAdmittedList.List, admittedItem)
		}
		ie = ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceAdmittedList
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList
		ie.Value.PDUSessionResourceAdmittedList = &pduSessionAdmittedList
		ackIEs.List = append(ackIEs.List, ie)
	}

	if len(failed) > 0 {
		pduSessionFailedList := ngapType.PDUSessionResourceFailedToSetupListHOAck{}
		for _, item := range failed {
			failedItem := ngapType.PDUSessionResourceFailedToSetupItemHOAck{
				PDUSessionID: ngapType.PDUSessionID{
					Value: item.PDUSessionID,
				},
				HandoverResourceAllocationUnsuccessfulTransfer: item.Transfer,
			}
			pduSessionFailedList.List = append(pduSessionFailedList.List, failedItem)
		}
		ie = ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListHOAck
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceFailedToSetupListHOAck
		ie.Value.PDUSessionResourceFailedToSetupListHOAck = &pduSessionFailedList
		ackIEs.List = append(ackIEs.List, ie)
	}

	ie = ngapType.HandoverRequestAcknowledgeIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDTargetToSourceTransparentContainer
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer
	ie.Value.TargetToSourceTransparentContainer = &ngapType.TargetToSourceTransparentContainer{
		Value: targetToSourceContainer,
	}
	ackIEs.List = append(ackIEs.List, ie)

	return ngap.Encoder(pdu)
}

func BuildHandoverRequestAcknowledgeTransfer(pduSession *n3iwf_context.PDUSession, gtpIPv4 string) ([]byte, error) {
	if pduSession == nil {
		return nil, errors.New("nil pdu session")
	}
	if pduSession.GTPConnInfo == nil {
		return nil, errors.New("GTP tunnel not ready")
	}

	transfer := ngapType.HandoverRequestAcknowledgeTransfer{}

	transfer.DLNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	transfer.DLNGUUPTNLInformation.GTPTunnel = new(ngapType.GTPTunnel)
	gtpTunnel := transfer.DLNGUUPTNLInformation.GTPTunnel

	teid := make([]byte, 4)
	binary.BigEndian.PutUint32(teid, pduSession.GTPConnInfo.IncomingTEID)
	gtpTunnel.GTPTEID.Value = teid
	gtpTunnel.TransportLayerAddress = ngapConvert.IPAddressToNgap(gtpIPv4, "")

	for _, qfi := range pduSession.QFIList {
		item := ngapType.QosFlowItemWithDataForwarding{
			QosFlowIdentifier: ngapType.QosFlowIdentifier{
				Value: int64(qfi),
			},
		}
		transfer.QosFlowSetupResponseList.List = append(
			transfer.QosFlowSetupResponseList.List, item)
	}

	return aper.MarshalWithParams(transfer, "valueExt")
}

func BuildHandoverResourceAllocationUnsuccessfulTransfer(
	cause ngapType.Cause,
) ([]byte, error) {
	transfer := ngapType.HandoverResourceAllocationUnsuccessfulTransfer{
		Cause: cause,
	}
	return aper.MarshalWithParams(transfer, "valueExt")
}

func buildPDUSessionResourceHORqd(
	sharedCtx *n3iwf_context.RanUeSharedCtx,
	directForwarding bool,
) ([]ngapType.PDUSessionResourceItemHORqd, error) {
	if sharedCtx == nil {
		return nil, errors.New("nil shared UE context")
	}
	if len(sharedCtx.PduSessionList) == 0 {
		return nil, errors.New("no active PDU sessions available for handover")
	}

	var sessionIDs []int64
	for id := range sharedCtx.PduSessionList {
		sessionIDs = append(sessionIDs, id)
	}
	sort.Slice(sessionIDs, func(i, j int) bool { return sessionIDs[i] < sessionIDs[j] })

	var items []ngapType.PDUSessionResourceItemHORqd
	for _, id := range sessionIDs {
		pduSession := sharedCtx.PduSessionList[id]
		if pduSession == nil {
			return nil, fmt.Errorf("missing context for PDU session %d", id)
		}

		transfer, err := buildHandoverRequiredTransferOctets(directForwarding)
		if err != nil {
			return nil, fmt.Errorf("pdu session %d: %w", id, err)
		}

		item := ngapType.PDUSessionResourceItemHORqd{
			PDUSessionID: ngapType.PDUSessionID{
				Value: pduSession.Id,
			},
			HandoverRequiredTransfer: transfer,
		}
		items = append(items, item)
	}
	return items, nil
}

func buildHandoverRequiredTransferOctets(directForwarding bool) ([]byte, error) {
	transfer := ngapType.HandoverRequiredTransfer{}
	if directForwarding {
		transfer.DirectForwardingPathAvailability = &ngapType.DirectForwardingPathAvailability{
			Value: ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable,
		}
	}
	return aper.MarshalWithParams(transfer, "valueExt")
}

func buildSourceToTargetTransparentContainer(sharedCtx *n3iwf_context.RanUeSharedCtx, targetID *ngapType.TargetID) ([]byte, error) {
	if sharedCtx == nil {
		return nil, errors.New("nil shared UE context")
	}
	if targetID == nil {
		return nil, errors.New("nil target ID")
	}

	plmn, err := deriveTargetPLMN(sharedCtx, targetID)
	if err != nil {
		return nil, err
	}

	nrCellID := deriveNRCellIdentity(targetID, sharedCtx.RanUeNgapId)

	container := ngapType.SourceNGRANNodeToTargetNGRANNodeTransparentContainer{
		RRCContainer: ngapType.RRCContainer{
			Value: []byte{0x00},
		},
		TargetCellID: ngapType.NGRANCGI{
			Present: ngapType.NGRANCGIPresentNRCGI,
			NRCGI: &ngapType.NRCGI{
				PLMNIdentity: plmn,
				NRCellIdentity: ngapType.NRCellIdentity{
					Value: nrCellID,
				},
			},
		},
	}

	if infoList := buildPDUSessionResourceInformationList(sharedCtx); infoList != nil {
		container.PDUSessionResourceInformationList = infoList
	}

	historyItem := ngapType.LastVisitedCellItem{
		LastVisitedCellInformation: ngapType.LastVisitedCellInformation{
			Present: ngapType.LastVisitedCellInformationPresentNGRANCell,
			NGRANCell: &ngapType.LastVisitedNGRANCellInformation{
				GlobalCellID: container.TargetCellID,
				CellType: ngapType.CellType{
					CellSize: ngapType.CellSize{Value: ngapType.CellSizePresentSmall},
				},
				TimeUEStayedInCell: ngapType.TimeUEStayedInCell{Value: 1},
			},
		},
	}
	container.UEHistoryInformation.List = append(container.UEHistoryInformation.List, historyItem)

	if sharedCtx.IndexToRfsp != 0 {
		container.IndexToRFSP = &ngapType.IndexToRFSP{Value: sharedCtx.IndexToRfsp}
	}

	return aper.MarshalWithParams(container, "valueExt")
}

func buildPDUSessionResourceInformationList(sharedCtx *n3iwf_context.RanUeSharedCtx) *ngapType.PDUSessionResourceInformationList {
	if sharedCtx == nil || len(sharedCtx.PduSessionList) == 0 {
		return nil
	}

	var sessionIDs []int64
	for id := range sharedCtx.PduSessionList {
		sessionIDs = append(sessionIDs, id)
	}
	slices.Sort(sessionIDs)

	infoList := ngapType.PDUSessionResourceInformationList{}
	for _, id := range sessionIDs {
		sess := sharedCtx.PduSessionList[id]
		if sess == nil {
			continue
		}

		info := ngapType.PDUSessionResourceInformationItem{
			PDUSessionID: ngapType.PDUSessionID{Value: sess.Id},
		}

		qfis := collectQFIs(sess)
		if len(qfis) == 0 {
			qfis = []uint8{1}
		}
		slices.Sort(qfis)

		for _, qfi := range qfis {
			info.QosFlowInformationList.List = append(
				info.QosFlowInformationList.List,
				ngapType.QosFlowInformationItem{
					QosFlowIdentifier: ngapType.QosFlowIdentifier{
						Value: int64(qfi),
					},
				},
			)
		}

		infoList.List = append(infoList.List, info)
	}

	if len(infoList.List) == 0 {
		return nil
	}
	return &infoList
}

func collectQFIs(sess *n3iwf_context.PDUSession) []uint8 {
	if sess == nil {
		return nil
	}

	seen := map[uint8]struct{}{}
	for _, qfi := range sess.QFIList {
		seen[qfi] = struct{}{}
	}
	for id := range sess.QosFlows {
		if id >= 0 && id <= math.MaxUint8 {
			seen[uint8(id)] = struct{}{}
		}
	}

	if len(seen) == 0 {
		return nil
	}

	res := make([]uint8, 0, len(seen))
	for qfi := range seen {
		res = append(res, qfi)
	}
	return res
}

func deriveTargetPLMN(sharedCtx *n3iwf_context.RanUeSharedCtx, targetID *ngapType.TargetID) (ngapType.PLMNIdentity, error) {
	if targetID != nil && targetID.TargetRANNodeID != nil {
		plmn := targetID.TargetRANNodeID.SelectedTAI.PLMNIdentity
		if len(plmn.Value) > 0 {
			return ngapType.PLMNIdentity{Value: append([]byte(nil), plmn.Value...)}, nil
		}

		ran := targetID.TargetRANNodeID.GlobalRANNodeID
		switch ran.Present {
		case ngapType.GlobalRANNodeIDPresentGlobalGNBID:
			if ran.GlobalGNBID != nil && len(ran.GlobalGNBID.PLMNIdentity.Value) > 0 {
				return ngapType.PLMNIdentity{
					Value: append([]byte(nil), ran.GlobalGNBID.PLMNIdentity.Value...),
				}, nil
			}
		case ngapType.GlobalRANNodeIDPresentGlobalN3IWFID:
			if ran.GlobalN3IWFID != nil && len(ran.GlobalN3IWFID.PLMNIdentity.Value) > 0 {
				return ngapType.PLMNIdentity{
					Value: append([]byte(nil), ran.GlobalN3IWFID.PLMNIdentity.Value...),
				}, nil
			}
		}
	}

	if sharedCtx != nil && sharedCtx.Guami != nil && len(sharedCtx.Guami.PLMNIdentity.Value) > 0 {
		return ngapType.PLMNIdentity{
			Value: append([]byte(nil), sharedCtx.Guami.PLMNIdentity.Value...),
		}, nil
	}

	return ngapType.PLMNIdentity{}, errors.New("unable to derive target PLMN")
}

func deriveNRCellIdentity(targetID *ngapType.TargetID, fallback int64) aper.BitString {
	if targetID != nil && targetID.TargetRANNodeID != nil {
		ran := targetID.TargetRANNodeID.GlobalRANNodeID
		if ran.GlobalGNBID != nil && ran.GlobalGNBID.GNBID.GNBID != nil {
			gnbBits := ran.GlobalGNBID.GNBID.GNBID
			if gnbBits.BitLength > 0 && gnbBits.BitLength <= 36 {
				val := bitStringToUint64(*gnbBits) << (36 - gnbBits.BitLength)
				return uintToBitString36(val)
			}
		}
	}

	val := uint64(fallback) & ((uint64(1) << 36) - 1)
	return uintToBitString36(val)
}

func bitStringToUint64(bs aper.BitString) uint64 {
	var out uint64
	for i := 0; i < int(bs.BitLength); i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		bit := (bs.Bytes[byteIdx] >> uint(bitIdx)) & 0x01
		out = (out << 1) | uint64(bit)
	}
	return out
}

func uintToBitString36(val uint64) aper.BitString {
	const bitLength = 36
	mask := uint64((uint64(1) << bitLength) - 1)
	val &= mask

	bytes := make([]byte, 5)
	for i := range 5 {
		shift := uint(8 * (4 - i))
		bytes[i] = byte(val >> shift)
	}

	return aper.BitString{
		Bytes:     bytes,
		BitLength: bitLength,
	}
}
