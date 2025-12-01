package rc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/free5gc/aper"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/ngap/ngapType"
)

type NgapEventSender interface {
	SendNgapEvt(evt n3iwf_context.NgapEvt)
}

type HandoverAlert struct {
	RanUeNgapId             int64
	Cause                   *ngapType.Cause
	TargetID                *ngapType.TargetID
	PDUSessionResourceHORqd []ngapType.PDUSessionResourceItemHORqd
	DirectForwarding        bool
	SourceToTargetContainer []byte
	Metadata                map[string]string
}

type HandoverAlertHandler struct {
	ctx    *n3iwf_context.N3IWFContext
	sender NgapEventSender
}

var (
	handoverHandlerMu sync.RWMutex
	handoverHandler   *HandoverAlertHandler
	hoWaitersMu       sync.Mutex
	hoWaiters         = make(map[int64][]chan hoResult)
)

type hoResult struct {
	status string
	err    error
}

func NewHandoverAlertHandler(
	ctx *n3iwf_context.N3IWFContext,
	sender NgapEventSender,
) *HandoverAlertHandler {
	return &HandoverAlertHandler{
		ctx:    ctx,
		sender: sender,
	}
}

func (h *HandoverAlertHandler) Handle(alert HandoverAlert) error {
	if h == nil {
		return fmt.Errorf("handover alert handler is nil")
	}
	if h.ctx == nil {
		return fmt.Errorf("n3iwf context not available")
	}
	if h.sender == nil {
		return fmt.Errorf("ngap event sender not available")
	}
	if alert.RanUeNgapId == 0 {
		return fmt.Errorf("handover alert missing ranUeNgapId")
	}
	if alert.TargetID == nil {
		return fmt.Errorf("handover alert missing TargetID")
	}

	if _, ok := h.ctx.RanUePoolLoad(alert.RanUeNgapId); !ok {
		return fmt.Errorf("ranUe with id %d not found", alert.RanUeNgapId)
	}

	cause := defaultHandoverCause()
	if alert.Cause != nil {
		cause = *alert.Cause
	}

	evt := n3iwf_context.NewTriggerHandoverEvt(
		alert.RanUeNgapId,
		cause,
		alert.TargetID,
		alert.PDUSessionResourceHORqd,
		alert.DirectForwarding,
		alert.SourceToTargetContainer,
	)

	logger.MainLog.Infof("HO alert received for RanUeNgapId=%d; forwarding to NGAP layer", alert.RanUeNgapId)
	h.sender.SendNgapEvt(evt)
	return nil
}

func defaultHandoverCause() ngapType.Cause {
	cause := ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork,
	}
	cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
	cause.RadioNetwork.Value = ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason
	return cause
}

func DispatchHandoverAlert(
	ctx *n3iwf_context.N3IWFContext,
	sender NgapEventSender,
	alert HandoverAlert,
) error {
	handler := NewHandoverAlertHandler(ctx, sender)
	return handler.Handle(alert)
}

func SetHandoverAlertHandler(handler *HandoverAlertHandler) {
	handoverHandlerMu.Lock()
	defer handoverHandlerMu.Unlock()
	handoverHandler = handler
}

func HandleHandoverAlert(alert HandoverAlert) error {
	handoverHandlerMu.RLock()
	handler := handoverHandler
	handoverHandlerMu.RUnlock()
	if handler == nil {
		return fmt.Errorf("handover alert handler not configured")
	}
	return handler.Handle(alert)
}

type handoverTriggerPayload struct {
	RanUeNgapId             int64             `json:"ranUeNgapId"`
	TargetID                string            `json:"targetId"`
	DirectForwarding        bool              `json:"directForwarding"`
	SourceToTargetContainer string            `json:"sourceToTargetContainer,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
}

// StartHandoverHTTPServer launches a background HTTP server that accepts
// POST /rc/handover requests to trigger an N3IWF handover.
func StartHandoverHTTPServer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":9085"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rc/handover", handleHandoverHTTPPost)
	go func() {
		logger.MainLog.Infof("RC handover HTTP server listening on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.MainLog.Errorf("RC handover HTTP server stopped: %v", err)
		}
	}()
}

func handleHandoverHTTPPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("only POST supported"))
		return
	}
	defer r.Body.Close()
	var payload handoverTriggerPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeHTTPError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON payload: %w", err))
		return
	}
	if payload.RanUeNgapId == 0 {
		writeHTTPError(w, http.StatusBadRequest, errors.New("ranUeNgapId is required"))
		return
	}
	ctx := currentN3iwfContext()
	targetID, err := decodeTargetID(ctx, payload.TargetID)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err)
		return
	}
	container, err := decodeOptionalBytes(payload.SourceToTargetContainer)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err)
		return
	}
	alert := HandoverAlert{
		RanUeNgapId:             payload.RanUeNgapId,
		TargetID:                targetID,
		DirectForwarding:        payload.DirectForwarding,
		SourceToTargetContainer: container,
		Metadata:                payload.Metadata,
	}
	if err := HandleHandoverAlert(alert); err != nil {
		writeHTTPError(w, http.StatusBadGateway, err)
		return
	}
	// Risposta immediata: il trigger è stato accettato, l'esito arriverà sui log/telemetria
	writeHTTPSuccess(w, map[string]interface{}{
		"status":  "triggered",
		"ranUeId": payload.RanUeNgapId,
	})
}

func decodeTargetID(ctx *n3iwf_context.N3IWFContext, encoded string) (*ngapType.TargetID, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("targetId is required")
	}
	// Interpretazione "friendly" mcc-mnc-id (es. 208-93-135) o simile.
	if targetID, err := buildTargetIDFromString(ctx, encoded); err == nil {
		return targetID, nil
	}
	return nil, fmt.Errorf("unable to decode targetId (expected string mcc-mnc-id), got: %s", encoded)
}

func decodeOptionalBytes(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	return data, nil
}

func writeHTTPSuccess(w http.ResponseWriter, payload interface{}) {
	writeHTTPJSON(w, http.StatusAccepted, payload)
}

// NotifyHandoverResult signals completion (success or failure) of a handover for a UE.
// Returns true if at least one waiter was notified.
func NotifyHandoverResult(ranUeNgapId int64, status string, err error) bool {
	hoWaitersMu.Lock()
	waiters := hoWaiters[ranUeNgapId]
	delete(hoWaiters, ranUeNgapId)
	hoWaitersMu.Unlock()

	if len(waiters) == 0 {
		return false
	}
	for _, ch := range waiters {
		ch <- hoResult{status: status, err: err}
	}
	return true
}

func writeHTTPError(w http.ResponseWriter, status int, err error) {
	logger.MainLog.Errorf("RC handover HTTP error: %v", err)
	writeHTTPJSON(w, status, map[string]interface{}{"error": err.Error()})
}

// currentN3iwfContext returns the context currently registered in the handler.
func currentN3iwfContext() *n3iwf_context.N3IWFContext {
	handoverHandlerMu.RLock()
	defer handoverHandlerMu.RUnlock()
	if handoverHandler == nil {
		return nil
	}
	return handoverHandler.ctx
}

// buildTargetIDFromString accetta formati semplici tipo "208-93-135"
// (MCC-MNC-N3IWFID) e costruisce un TargetID con GlobalN3IWFID.
// I valori PLMN/TAC sono prelevati dalla config N3IWF, l'ID dalla stringa.
func buildTargetIDFromString(ctx *n3iwf_context.N3IWFContext, raw string) (*ngapType.TargetID, error) {
	if ctx == nil {
		return nil, fmt.Errorf("n3iwf context not available")
	}
	cfg := ctx.Config()
	if cfg == nil || cfg.Configuration == nil || cfg.Configuration.N3IWFInfo == nil ||
		len(cfg.Configuration.N3IWFInfo.SupportedTAList) == 0 {
		return nil, fmt.Errorf("n3iwf configuration missing supportedTAList")
	}

	supportedTA := cfg.Configuration.N3IWFInfo.SupportedTAList[0]
	if len(supportedTA.BroadcastPLMNList) == 0 {
		return nil, fmt.Errorf("n3iwf configuration missing BroadcastPLMNList")
	}
	plmnInfo := supportedTA.BroadcastPLMNList[0].PLMNID

	// TAC nella config è in esadecimale (3 byte)
	tacStr := strings.TrimSpace(supportedTA.TAC)
	tacBytes, err := parseTacHex(tacStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TAC in config: %w", err)
	}

	// L'ID (N3IWFID) è preso dalla stringa in input (ultimo gruppo numerico).
	parts := splitDigits(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("cannot parse targetId string (need an ID): %s", raw)
	}
	idStr := parts[len(parts)-1]
	n3iwfID, err := strconv.ParseUint(idStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid N3IWF ID: %w", err)
	}

	plmn, err := encodePLMN(plmnInfo.Mcc, plmnInfo.Mnc)
	if err != nil {
		return nil, err
	}
	bs := aper.BitString{
		Bytes:     []byte{byte(n3iwfID >> 8), byte(n3iwfID)},
		BitLength: 16,
	}

	global := ngapType.GlobalRANNodeID{
		Present: ngapType.GlobalRANNodeIDPresentGlobalN3IWFID,
		GlobalN3IWFID: &ngapType.GlobalN3IWFID{
			PLMNIdentity: plmn,
			N3IWFID: ngapType.N3IWFID{
				Present: ngapType.N3IWFIDPresentN3IWFID,
				N3IWFID: &bs,
			},
		},
	}

	tac := ngapType.TAC{Value: tacBytes}
	tai := ngapType.TAI{
		PLMNIdentity: plmn,
		TAC:          tac,
	}

	target := &ngapType.TargetID{
		Present: ngapType.TargetIDPresentTargetRANNodeID,
		TargetRANNodeID: &ngapType.TargetRANNodeID{
			GlobalRANNodeID: global,
			SelectedTAI:     tai,
		},
	}
	return target, nil
}

// splitDigits estrae gruppi numerici separati da qualsiasi separatore non cifra.
func splitDigits(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	var out []string
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// encodePLMN converte MCC/MNC in 3 byte BCD (TS 38.413).
func encodePLMN(mcc, mnc string) (ngapType.PLMNIdentity, error) {
	toDigit := func(b byte) (byte, error) {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("invalid digit: %c", b)
		}
		return b - '0', nil
	}

	d1, err := toDigit(mcc[0])
	if err != nil {
		return ngapType.PLMNIdentity{}, err
	}
	d2, err := toDigit(mcc[1])
	if err != nil {
		return ngapType.PLMNIdentity{}, err
	}
	d3, err := toDigit(mcc[2])
	if err != nil {
		return ngapType.PLMNIdentity{}, err
	}

	var m1, m2, m3 byte = 0x0F, 0, 0
	if len(mnc) == 2 {
		// 2-digit MNC, usa filler 0xF
		m2, err = toDigit(mnc[0])
		if err != nil {
			return ngapType.PLMNIdentity{}, err
		}
		m3, err = toDigit(mnc[1])
		if err != nil {
			return ngapType.PLMNIdentity{}, err
		}
	} else {
		m1, err = toDigit(mnc[2])
		if err != nil {
			return ngapType.PLMNIdentity{}, err
		}
		m2, err = toDigit(mnc[0])
		if err != nil {
			return ngapType.PLMNIdentity{}, err
		}
		m3, err = toDigit(mnc[1])
		if err != nil {
			return ngapType.PLMNIdentity{}, err
		}
	}

	// BCD codifica: byte0 = MCC2|MCC1, byte1 = MNC3|MCC3, byte2 = MNC2|MNC1
	plmnBytes := []byte{
		(d2 << 4) | d1,
		(m1 << 4) | d3,
		(m3 << 4) | m2,
	}
	return ngapType.PLMNIdentity{Value: plmnBytes}, nil
}

func parseTacHex(tac string) ([]byte, error) {
	tac = strings.TrimSpace(tac)
	if len(tac) != 6 {
		return nil, fmt.Errorf("TAC must be 3 bytes hex, got '%s'", tac)
	}
	out := make([]byte, 3)
	for i := 0; i < 3; i++ {
		b, err := strconv.ParseUint(tac[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid TAC hex: %w", err)
		}
		out[i] = byte(b)
	}
	return out, nil
}

func writeHTTPJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.MainLog.Errorf("RC handover HTTP unable to encode response: %v", err)
	}
}
