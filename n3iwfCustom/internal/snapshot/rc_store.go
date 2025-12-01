package snapshot

import (
	"sync"
	"time"

	"github.com/free5gc/ngap/ngapType"
)

// RCStation contiene le informazioni per un singolo client collegato all'access point.
type RCStation struct {
	Interface   string            `json:"interface,omitempty"`
	MAC         string            `json:"mac"`
	IP          string            `json:"ip,omitempty"`
	Fields      map[string]string `json:"fields,omitempty"`
	Hostapd     map[string]string `json:"hostapd,omitempty"`
	StationDump map[string]string `json:"stationDump,omitempty"`
}

// DeepCopy crea una copia indipendente di RCStation.
func (s RCStation) DeepCopy() RCStation {
	out := RCStation{
		Interface: s.Interface,
		MAC:       s.MAC,
	}
	if s.IP != "" {
		out.IP = s.IP
	}
	if len(s.Fields) > 0 {
		out.Fields = make(map[string]string, len(s.Fields))
		for k, v := range s.Fields {
			out.Fields[k] = v
		}
	}
	if len(s.Hostapd) > 0 {
		out.Hostapd = make(map[string]string, len(s.Hostapd))
		for k, v := range s.Hostapd {
			out.Hostapd[k] = v
		}
	}
	if len(s.StationDump) > 0 {
		out.StationDump = make(map[string]string, len(s.StationDump))
		for k, v := range s.StationDump {
			out.StationDump[k] = v
		}
	}
	return out
}

// RCInterfaceSnapshot rappresenta i dati raccolti da hostapd_cli per una specifica interfaccia.
type RCInterfaceSnapshot struct {
	Interface string              `json:"interface"`
	Stations  []RCStation         `json:"stations,omitempty"`
	Survey    []map[string]string `json:"survey,omitempty"`
	Ethtool   map[string]string   `json:"ethtool,omitempty"`
	MetricsTS time.Time           `json:"metricsTimestamp,omitempty"`
	Raw       string              `json:"raw,omitempty"`
	Error     string              `json:"error,omitempty"`
	Command   []string            `json:"command,omitempty"`
}

// DeepCopy crea una copia indipendente dell'RCInterfaceSnapshot.
func (s RCInterfaceSnapshot) DeepCopy() RCInterfaceSnapshot {
	out := RCInterfaceSnapshot{
		Interface: s.Interface,
		MetricsTS: s.MetricsTS,
		Raw:       s.Raw,
		Error:     s.Error,
	}
	if len(s.Command) > 0 {
		out.Command = make([]string, len(s.Command))
		copy(out.Command, s.Command)
	}
	if len(s.Stations) > 0 {
		out.Stations = make([]RCStation, len(s.Stations))
		for i, st := range s.Stations {
			out.Stations[i] = st.DeepCopy()
		}
	}
	if len(s.Survey) > 0 {
		out.Survey = make([]map[string]string, len(s.Survey))
		for i, entry := range s.Survey {
			if len(entry) == 0 {
				continue
			}
			copyEntry := make(map[string]string, len(entry))
			for k, v := range entry {
				copyEntry[k] = v
			}
			out.Survey[i] = copyEntry
		}
	}
	if len(s.Ethtool) > 0 {
		out.Ethtool = make(map[string]string, len(s.Ethtool))
		for k, v := range s.Ethtool {
			out.Ethtool[k] = v
		}
	}
	return out
}

// RCSnapshot contiene lo stato complessivo del collector RC.
type RCSnapshot struct {
	Timestamp    time.Time             `json:"timestamp"`
	Stations     []RCStation           `json:"stations,omitempty"`
	Interfaces   []RCInterfaceSnapshot `json:"interfaces,omitempty"`
	Errors       []string              `json:"errors,omitempty"`
	Associations []RCUEAssociation     `json:"associations,omitempty"`
}

// DeepCopy crea una copia indipendente del RCSnapshot.
func (s RCSnapshot) DeepCopy() RCSnapshot {
	out := RCSnapshot{
		Timestamp: s.Timestamp,
	}
	if len(s.Errors) > 0 {
		out.Errors = make([]string, len(s.Errors))
		copy(out.Errors, s.Errors)
	}
	if len(s.Stations) > 0 {
		out.Stations = make([]RCStation, len(s.Stations))
		for i, st := range s.Stations {
			out.Stations[i] = st.DeepCopy()
		}
	}
	if len(s.Interfaces) > 0 {
		out.Interfaces = make([]RCInterfaceSnapshot, len(s.Interfaces))
		for i, iface := range s.Interfaces {
			out.Interfaces[i] = iface.DeepCopy()
		}
	}
	if len(s.Associations) > 0 {
		out.Associations = make([]RCUEAssociation, len(s.Associations))
		for i, assoc := range s.Associations {
			out.Associations[i] = assoc.DeepCopy()
		}
	}
	return out
}

// RCStore mantiene l'ultimo snapshot disponibile in modo thread-safe.
type RCStore struct {
	mu       sync.RWMutex
	snapshot RCSnapshot
}

// NewRCStore crea un nuovo store vuoto.
func NewRCStore() *RCStore {
	return &RCStore{}
}

// Update salva uno snapshot nel datastore, sovrascrivendo il precedente.
func (s *RCStore) Update(snapshot RCSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snapshot.DeepCopy()
}

// Snapshot restituisce una copia dell'ultimo snapshot disponibile.
func (s *RCStore) Snapshot() RCSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot.DeepCopy()
}

// RCAgg è lo store globale per le metriche RC.
var RCAgg = NewRCStore()

// RCUEAssociation raccoglie i dati unificati per un UE tra hostapd, N3IWF e AMF.
type RCUEAssociation struct {
	Interface  string          `json:"interface,omitempty"`
	MAC        string          `json:"mac,omitempty"`
	UEIP       string          `json:"ueIp,omitempty"`
	Station    RCStation       `json:"station"`
	Counters   Counters        `json:"counters"`
	UE         *RCAssociatedUE `json:"ue,omitempty"`
	Mismatches []string        `json:"mismatches,omitempty"`
}

// DeepCopy restituisce una copia indipendente dell'associazione.
func (a RCUEAssociation) DeepCopy() RCUEAssociation {
	out := RCUEAssociation{
		Interface:  a.Interface,
		MAC:        a.MAC,
		UEIP:       a.UEIP,
		Station:    a.Station.DeepCopy(),
		Counters:   a.Counters,
		Mismatches: nil,
	}
	if len(a.Mismatches) > 0 {
		out.Mismatches = make([]string, len(a.Mismatches))
		copy(out.Mismatches, a.Mismatches)
	}
	if a.UE != nil {
		out.UE = a.UE.DeepCopy()
	}
	return out
}

// RCAssociatedUE contiene le informazioni del contesto N3IWF/AMF rilevanti per l'UE.
type RCAssociatedUE struct {
	RCRanUeSharedCtx
	N3IwfID        string          `json:"n3iwfId,omitempty"`
	AmfName        string          `json:"amfName,omitempty"`
	AmfSCTP        string          `json:"amfSctp,omitempty"`
	IKELocalSPI    uint64          `json:"ikeLocalSpi,omitempty"`
	IKERemoteSPI   uint64          `json:"ikeRemoteSpi,omitempty"`
	IKEState       uint8           `json:"ikeState,omitempty"`
	UeBehindNAT    bool            `json:"ueBehindNat,omitempty"`
	N3iwfBehindNAT bool            `json:"n3iwfBehindNat,omitempty"`
	ChildSAs       []RCChildSAInfo `json:"childSa,omitempty"`
}

// RCRanUeSharedCtx è la versione RC-friendly di RanUeSharedCtx.
type RCRanUeSharedCtx struct {
	RanUeNgapId                      int64                                         `json:"ranUeNgapId"`
	AmfUeNgapId                      int64                                         `json:"amfUeNgapId"`
	IPAddrv4                         string                                        `json:"ipAddrV4,omitempty"`
	IPAddrv6                         string                                        `json:"ipAddrV6,omitempty"`
	PortNumber                       int32                                         `json:"portNumber,omitempty"`
	MaskedIMEISV                     *ngapType.MaskedIMEISV                        `json:"maskedImeisv,omitempty"`
	Guti                             string                                        `json:"guti,omitempty"`
	Guami                            *ngapType.GUAMI                               `json:"guami,omitempty"`
	IndexToRfsp                      int64                                         `json:"indexToRfsp,omitempty"`
	Ambr                             *ngapType.UEAggregateMaximumBitRate           `json:"ambr,omitempty"`
	AllowedNssai                     *ngapType.AllowedNSSAI                        `json:"allowedNssai,omitempty"`
	RadioCapability                  *ngapType.UERadioCapability                   `json:"radioCapability,omitempty"`
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation    `json:"coreNetworkAssistanceInformation,omitempty"`
	IMSVoiceSupported                int32                                         `json:"imsVoiceSupported,omitempty"`
	RRCEstablishmentCause            int16                                         `json:"rrcEstablishmentCause,omitempty"`
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes `json:"pduSessionReleaseList,omitempty"`
	UeCtxRelState                    bool                                          `json:"ueCtxRelState,omitempty"`
	PduSessResRelState               bool                                          `json:"pduSessResRelState,omitempty"`
	PduSessionList                   map[int64]RCPDUSession                        `json:"pduSessionList,omitempty"`
}

type RCPDUSession struct {
	ID                               int64                                       `json:"id"`
	Type                             *ngapType.PDUSessionType                    `json:"type,omitempty"`
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate `json:"ambr,omitempty"`
	SNSSAI                           ngapType.SNSSAI                             `json:"snssai"`
	NetworkInstance                  *ngapType.NetworkInstance                   `json:"networkInstance,omitempty"`
	SecurityCipher                   bool                                        `json:"securityCipher"`
	SecurityIntegrity                bool                                        `json:"securityIntegrity"`
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate `json:"maximumIntegrityDataRateUplink,omitempty"`
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate `json:"maximumIntegrityDataRateDownlink,omitempty"`
	GTPConnInfo                      *RCGTPConnectionInfo                        `json:"gtpConnInfo,omitempty"`
	QFIList                          []uint8                                     `json:"qfiList,omitempty"`
	QosFlows                         map[int64]RCQosFlow                         `json:"qosFlows,omitempty"`
}

// RCChildSAInfo riassume le informazioni sul tunnel IPsec associato all'UE.
type RCChildSAInfo struct {
	InboundSPI        uint32  `json:"inboundSpi,omitempty"`
	OutboundSPI       uint32  `json:"outboundSpi,omitempty"`
	TunnelIface       string  `json:"tunnelIface,omitempty"`
	PeerPublicIP      string  `json:"peerPublicIp,omitempty"`
	LocalPublicIP     string  `json:"localPublicIp,omitempty"`
	N3IWFPort         int     `json:"n3iwfPort,omitempty"`
	NATPort           int     `json:"natPort,omitempty"`
	EnableEncapsulate bool    `json:"enableEncapsulate,omitempty"`
	SelectedIPProto   uint8   `json:"selectedIpProto,omitempty"`
	PduSessionIds     []int64 `json:"pduSessionIds,omitempty"`
}

type RCGTPConnectionInfo struct {
	UPFIPAddr    string     `json:"upfIpAddr,omitempty"`
	UPFUDPAddr   *RCUDPAddr `json:"upfUdpAddr,omitempty"`
	IncomingTEID uint32     `json:"incomingTeid,omitempty"`
	OutgoingTEID uint32     `json:"outgoingTeid,omitempty"`
}

type RCUDPAddr struct {
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	Zone string `json:"zone,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

type RCQosFlow struct {
	Identifier int64                              `json:"identifier"`
	Parameters ngapType.QosFlowLevelQosParameters `json:"parameters"`
}

// DeepCopy crea una copia indipendente dell'UE associato.
func (ue *RCAssociatedUE) DeepCopy() *RCAssociatedUE {
	if ue == nil {
		return nil
	}
	copyUE := *ue
	copyUE.RCRanUeSharedCtx = cloneRCRanUeSharedCtx(ue.RCRanUeSharedCtx)
	if len(ue.ChildSAs) > 0 {
		copyUE.ChildSAs = make([]RCChildSAInfo, len(ue.ChildSAs))
		for i, sa := range ue.ChildSAs {
			copyUE.ChildSAs[i] = sa
			if len(sa.PduSessionIds) > 0 {
				ps := make([]int64, len(sa.PduSessionIds))
				copy(ps, sa.PduSessionIds)
				copyUE.ChildSAs[i].PduSessionIds = ps
			}
		}
	}
	return &copyUE
}

func cloneRCRanUeSharedCtx(src RCRanUeSharedCtx) RCRanUeSharedCtx {
	dst := src
	if len(src.PduSessionList) > 0 {
		dst.PduSessionList = make(map[int64]RCPDUSession, len(src.PduSessionList))
		for id, sess := range src.PduSessionList {
			dst.PduSessionList[id] = cloneRCPDUSession(sess)
		}
	}
	return dst
}

func cloneRCPDUSession(src RCPDUSession) RCPDUSession {
	dst := src
	if len(src.QFIList) > 0 {
		dst.QFIList = append([]uint8(nil), src.QFIList...)
	}
	if len(src.QosFlows) > 0 {
		dst.QosFlows = make(map[int64]RCQosFlow, len(src.QosFlows))
		for k, v := range src.QosFlows {
			dst.QosFlows[k] = v
		}
	}
	if src.GTPConnInfo != nil {
		c := *src.GTPConnInfo
		if src.GTPConnInfo.UPFUDPAddr != nil {
			addr := *src.GTPConnInfo.UPFUDPAddr
			c.UPFUDPAddr = &addr
		}
		dst.GTPConnInfo = &c
	}
	return dst
}
