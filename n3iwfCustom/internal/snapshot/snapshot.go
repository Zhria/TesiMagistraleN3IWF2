package snapshot

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/ngap/ngapType"
	"github.com/vishvananda/netlink"
)

type TransmittedVolumeDLStruct struct {
	Bytes   uint64
	Packets int64
	QoS     string
	UEIP    string
}

type TransmittedVolumeULStruct struct {
	Bytes   uint64
	Packets int64
	QoS     string
	UEIP    string
}

type UEIKESnapshot struct {
	// UE identity
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr net.IPAddr // Used to send UP packets to UE

	// IKE Security Association
	N3IWFIKESecurityAssociation   IKESecurityAssociationSnapshot
	N3IWFChildSecurityAssociation map[uint32]ChildSecurityAssociationSnapshot // inbound SPI as key

	// NAS IKE Connection
	IKEConnection context.UDPSocketInfo

	// Length of PDU Session List
	PduSessionListLen int
}

type IKESecurityAssociationSnapshot struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// State for IKE_AUTH
	State uint8

	// UDP Connection
	IKEConnection context.UDPSocketInfo

	// NAT detection
	UeBehindNAT    bool // If true, N3IWF should enable NAT traversal and
	N3iwfBehindNAT bool // TODO: If true, N3IWF should send UDP keepalive periodically

	DPDReqRetransTimer context.Timer // The time from sending the DPD request to receiving the response
	CurrentRetryTimes  int32         // Accumulate the number of times the DPD response wasn't received
	IsUseDPD           bool
}

type ChildSecurityAssociationSnapshot struct {
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	XfrmStateList  []netlink.XfrmState
	XfrmPolicyList []netlink.XfrmPolicy

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Encapsulate
	EnableEncapsulate bool
	N3IWFPort         int
	NATPort           int

	// PDU Session IDs associated with this child SA
	PDUSessionIds    []int64
	LocalIsInitiator bool
}

/* =========================
   SNAPSHOT COMPLETO
   ========================= */

type N3IWFContextSnapshotFull struct {
	AMFPool              map[string]context.N3IWFAMF `json:"amfPool,omitempty"`
	AllocatedUEIPAddress []AllocatedUeIPSnapshot     `json:"allocatedUeIps,omitempty"`
	IKEUePool            []UEIKESnapshot             `json:"ikeUePool,omitempty"`
	IKESPIToNGAPId       map[uint64]int64            `json:"ikeSpiToNgapId,omitempty"`
	NGAPIdToIKESPI       map[int64]uint64            `json:"ngapIdToIkeSpi,omitempty"`
	IPSecInnerIPPool     any                         `json:"ipsecInnerIpPool,omitempty"`
	XfrmIfaces           map[uint32]string           `json:"xfrmIfaces,omitempty"` // nome iface soltanto
}

/* =========================
   ALTRE MINI STRUCT
   ========================= */

type AllocatedUeIPSnapshot struct {
	UeIPv4 string `json:"ueIpv4"`
}

/* =========================
   VISTA "APP" CON UEs
   ========================= */

type N3iwfAppSnapshot struct {
	XfrmParentIface   string                   `json:"xfrmParentIface,omitempty"`
	XfrmIfaceIdOffset uint32                   `json:"xfrmIfaceIdOffset"`
	RanUeCount        int                      `json:"ranUeCount"`
	IkeUeCount        int                      `json:"ikeUeCount"`
	ChildSACount      int                      `json:"childSaCount"`
	AmfKeys           []string                 `json:"amfKeys,omitempty"`
	UeIPs             []string                 `json:"allocatedUeIps,omitempty"`
	UEs               []context.N3IWFRanUe     `json:"ues,omitempty"`
	N3IWFContext      N3IWFContextSnapshotFull `json:"n3iwfContext,omitempty"` // full context incluso
}

/* =========================
   FUNZIONE UNICA (FULL + APP)
   ========================= */

func MakeN3IWFContextSnapshotFull(ctx *context.N3IWFContext) *N3iwfAppSnapshot {
	snap := &N3iwfAppSnapshot{
		XfrmParentIface:   ctx.XfrmParentIfaceName,
		XfrmIfaceIdOffset: ctx.XfrmIfaceIdOffsetForUP,
	}

	// ---------- FULL ----------
	full := N3IWFContextSnapshotFull{
		AMFPool:          make(map[string]context.N3IWFAMF),
		IKESPIToNGAPId:   make(map[uint64]int64),
		NGAPIdToIKESPI:   make(map[int64]uint64),
		XfrmIfaces:       make(map[uint32]string),
		IPSecInnerIPPool: ctx.IPSecInnerIPPool,
	}

	full.AMFPool = getAMFPoolSnapshot(&ctx.AMFPool)

	// // GTP with UPF
	// ctx.GTPConnectionWithUPF.Range(func(k, v any) bool {

	// 	full.GTPConnectionWithUPF = append(full.GTPConnectionWithUPF, v.(gtpv1.UPlaneConn))

	// 	return true
	// })

	// Allocated UE IP
	ctx.AllocatedUEIPAddress.Range(func(k, _ any) bool {
		if ip, ok := k.(string); ok {
			full.AllocatedUEIPAddress = append(full.AllocatedUEIPAddress, AllocatedUeIPSnapshot{UeIPv4: ip})
		}
		return true
	})

	// IKE UE pool
	ctx.IKEUePool.Range(func(_, v any) bool {
		snap.IkeUeCount++
		ikeUe, _ := v.(*context.N3IWFIkeUe)
		if ikeUe == nil {
			return true
		}

		item := UEIKESnapshot{
			IPSecInnerIP:      ikeUe.IPSecInnerIP,
			IPSecInnerIPAddr:  net.IPAddr{},
			IKEConnection:     context.UDPSocketInfo{},
			PduSessionListLen: ikeUe.PduSessionListLen,
		}
		if ikeUe.IPSecInnerIPAddr != nil {
			item.IPSecInnerIPAddr = *ikeUe.IPSecInnerIPAddr
		}

		if ikeUe.IKEConnection != nil {
			item.IKEConnection = *ikeUe.IKEConnection
		}

		item.N3IWFIKESecurityAssociation = IKESecurityAssociationSnapshot{
			RemoteSPI:          ikeUe.N3IWFIKESecurityAssociation.RemoteSPI,
			LocalSPI:           ikeUe.N3IWFIKESecurityAssociation.LocalSPI,
			InitiatorMessageID: ikeUe.N3IWFIKESecurityAssociation.InitiatorMessageID,
			ResponderMessageID: ikeUe.N3IWFIKESecurityAssociation.ResponderMessageID,

			State:              ikeUe.N3IWFIKESecurityAssociation.State,
			IKEConnection:      context.UDPSocketInfo{},
			UeBehindNAT:        ikeUe.N3IWFIKESecurityAssociation.UeBehindNAT,
			N3iwfBehindNAT:     ikeUe.N3IWFIKESecurityAssociation.N3iwfBehindNAT,
			DPDReqRetransTimer: context.Timer{},
			CurrentRetryTimes:  ikeUe.N3IWFIKESecurityAssociation.CurrentRetryTimes,
			IsUseDPD:           ikeUe.N3IWFIKESecurityAssociation.IsUseDPD,
		}
		if ikeUe.N3IWFIKESecurityAssociation.IKEConnection != nil {
			item.N3IWFIKESecurityAssociation.IKEConnection = *ikeUe.N3IWFIKESecurityAssociation.IKEConnection
		}
		if ikeUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer != nil {
			item.N3IWFIKESecurityAssociation.DPDReqRetransTimer = *ikeUe.N3IWFIKESecurityAssociation.DPDReqRetransTimer
		}

		item.N3IWFChildSecurityAssociation = make(map[uint32]ChildSecurityAssociationSnapshot)
		for spi, childSA := range ikeUe.N3IWFChildSecurityAssociation {

			// Initialize the XfrmStateList for this ChildSA
			item.N3IWFChildSecurityAssociation[spi] = ChildSecurityAssociationSnapshot{
				InboundSPI:            childSA.InboundSPI,
				OutboundSPI:           childSA.OutboundSPI,
				XfrmIface:             childSA.XfrmIface,
				XfrmStateList:         []netlink.XfrmState{},
				XfrmPolicyList:        childSA.XfrmPolicyList,
				PeerPublicIPAddr:      childSA.PeerPublicIPAddr,
				LocalPublicIPAddr:     childSA.LocalPublicIPAddr,
				SelectedIPProtocol:    childSA.SelectedIPProtocol,
				TrafficSelectorLocal:  childSA.TrafficSelectorLocal,
				TrafficSelectorRemote: childSA.TrafficSelectorRemote,
				EnableEncapsulate:     childSA.EnableEncapsulate,
				N3IWFPort:             childSA.N3IWFPort,
				NATPort:               childSA.NATPort,
				PDUSessionIds:         childSA.PDUSessionIds,
				LocalIsInitiator:      childSA.LocalIsInitiator,
			}

			if childSA.XfrmIface != nil && childSA.XfrmIface.Attrs() != nil {
				nameIface := childSA.XfrmIface.Attrs().Name
				if nameIface != "" {
					//Retrieve the Xfrm interface
					lnk, err := netlink.LinkByName(nameIface)
					if err != nil {
						continue
					}
					//Ho un lnk aggiornato, lo uso per il snapshot
					childSASnap := item.N3IWFChildSecurityAssociation[spi]
					childSASnap.XfrmIface = lnk
					item.N3IWFChildSecurityAssociation[spi] = childSASnap
				}
			}
			for _, st := range childSA.XfrmStateList {
				live, err := netlink.XfrmStateGet(&netlink.XfrmState{
					Dst:   st.Dst,
					Spi:   st.Spi,
					Proto: st.Proto,
				})
				if err != nil {
					continue
				}
				// Retrieve, modify, and put back the struct in the map
				childSASnap := item.N3IWFChildSecurityAssociation[spi]
				childSASnap.XfrmStateList = append(childSASnap.XfrmStateList, *live)
				item.N3IWFChildSecurityAssociation[spi] = childSASnap
			}

		}

		full.IKEUePool = append(full.IKEUePool, item)
		return true
	})

	// SPI<->NGAP maps
	ctx.IKESPIToNGAPId.Range(func(k, v any) bool {
		if spi, ok := k.(uint64); ok {
			if id, ok2 := v.(int64); ok2 {
				full.IKESPIToNGAPId[spi] = id
			}
		}
		return true
	})
	ctx.NGAPIdToIKESPI.Range(func(k, v any) bool {
		if id, ok := k.(int64); ok {
			if spi, ok2 := v.(uint64); ok2 {
				full.NGAPIdToIKESPI[id] = spi
			}
		}
		return true
	})

	// XFRM ifaces
	ctx.XfrmIfaces.Range(func(k, v any) bool {
		ifid, ok := k.(uint32)
		if !ok {
			return true
		}
		// nel context è dichiarato come *netlink.Link oppure netlink.Link: gestiamo entrambi
		if lnk, ok := v.(netlink.Link); ok && lnk != nil {
			full.XfrmIfaces[ifid] = lnk.Attrs().Name
		} else if plnk, ok := v.(*netlink.Link); ok && plnk != nil && *plnk != nil {
			full.XfrmIfaces[ifid] = (*plnk).Attrs().Name
		} else {
			full.XfrmIfaces[ifid] = ""
		}
		return true
	})

	// Attacca il full context
	snap.N3IWFContext = full

	// ---------- APP (summary + UEs opzionali) ----------

	// AMF keys
	ctx.AMFPool.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			snap.AmfKeys = append(snap.AmfKeys, s)
		}
		return true
	})

	// ChildSA count
	ctx.ChildSA.Range(func(_, _ any) bool {
		snap.ChildSACount++
		return true
	})

	// Allocated UE IPs (solo chiavi IP)
	ctx.AllocatedUEIPAddress.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			snap.UeIPs = append(snap.UeIPs, s)
		}
		return true
	})

	// UE dettagliati opzionali (dati esistenti nel RanUeSharedCtx)

	ctx.RANUePool.Range(func(_, v any) bool {
		ru, ok := v.(*context.N3IWFRanUe)
		if !ok || ru == nil {
			return true
		}
		//Faccio una copia per evitare problemi di concorrenza
		us := context.N3IWFRanUe{
			RanUeSharedCtx:                  ru.RanUeSharedCtx, // Copia il contesto condiviso
			IsNASTCPConnEstablished:         ru.IsNASTCPConnEstablished,
			IsNASTCPConnEstablishedComplete: ru.IsNASTCPConnEstablishedComplete,
			TCPConnection:                   ru.TCPConnection, // Copia il puntatore alla connessione TCP
		}
		us.RanUeSharedCtx.N3iwfCtx = nil // Non serve il contesto N3iwfCtx nel snapshot

		snap.UEs = append(snap.UEs, us)
		snap.RanUeCount++
		return true
	})

	return snap
}

func getAMFPoolSnapshot(amfPool *sync.Map) map[string]context.N3IWFAMF {
	if amfPool == nil {
		return nil
	}
	full := make(map[string]context.N3IWFAMF)
	// AMFPool
	amfPool.Range(func(k, v any) bool {
		addr, ok := k.(string)
		if !ok {
			return true
		}
		amf, _ := v.(*context.N3IWFAMF)
		amfSnap := *amf
		// Rimuovo i campi non necessari per il snapshot
		full[addr] = amfSnap
		return true
	})
	return full
}

type Direction uint8

const (
	DL Direction = 0
	UL Direction = 1
)

type Record struct {
	TsUnix          int64
	BucketS         int64
	UEIP            string
	TEID            uint32
	QFI             uint8
	SNSSAI          string // "sst-sd" (es. "1-010203")
	Dir             Direction
	IncomingOctets  uint64
	TransmitOctets  uint64
	IncomingPackets uint64
	TransmitPackets uint64
	DroppedOctets   uint64
}

type Counters struct {
	IncomingOctets  uint64 `json:"incomingOctets"`
	TransmitOctets  uint64 `json:"transmitOctets"`
	IncomingPackets uint64 `json:"incomingPkts"`
	TransmitPackets uint64 `json:"transmitPkts"`
	DroppedOctets   uint64 `json:"droppedOctets"`
}

func (c *Counters) add(r Record) {
	c.IncomingOctets += r.IncomingOctets
	c.TransmitOctets += r.TransmitOctets
	c.IncomingPackets += r.IncomingPackets
	c.TransmitPackets += r.TransmitPackets
	c.DroppedOctets += r.DroppedOctets
}

type idSet map[int]struct{} // se in futuro vuoi ancora fare intersect sugli ID

// Aggregati per singola dimensione
type AggStore struct {
	mu sync.RWMutex

	// contatori per chiave singola
	byBucket map[int64]*Counters
	byUEIP   map[string]*Counters
	byTEID   map[uint32]*Counters
	byQFI    map[uint8]*Counters
	bySNSSAI map[string]*Counters
	byDir    map[Direction]*Counters

	// (opzionale) contatore globale
	total Counters

	// (facoltativo) tabella combinata per query multi-dimensione
	// key composto per tutte le dimensioni principali
	byKey map[string]*Counters
}

func NewAggStore() *AggStore {
	return &AggStore{
		byBucket: make(map[int64]*Counters),
		byUEIP:   make(map[string]*Counters),
		byTEID:   make(map[uint32]*Counters),
		byQFI:    make(map[uint8]*Counters),
		bySNSSAI: make(map[string]*Counters),
		byDir:    make(map[Direction]*Counters),
		byKey:    make(map[string]*Counters),
	}
}

func getOrMake[T comparable](m map[T]*Counters, k T) *Counters {
	if c, ok := m[k]; ok {
		return c
	}
	c := &Counters{}
	m[k] = c
	return c
}

func keyComposite(r Record) string {
	// chiave stabile per query multi-filtro (bucket/ueip/teid/qfi/snssai/dir)
	return fmt.Sprintf("b=%d|ip=%s|teid=%d|qfi=%d|s=%s|d=%d",
		r.BucketS, r.UEIP, r.TEID, r.QFI, r.SNSSAI, r.Dir)
}

func u64sub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}

func (s *AggStore) Ingest(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// aggiorna per dimensione
	getOrMake(s.byBucket, r.BucketS).add(r)
	if r.UEIP != "" {
		getOrMake(s.byUEIP, r.UEIP).add(r)
	}
	if r.TEID != 0 {
		getOrMake(s.byTEID, r.TEID).add(r)
	}
	if r.QFI != 0 {
		getOrMake(s.byQFI, r.QFI).add(r)
	}
	if r.SNSSAI != "" {
		getOrMake(s.bySNSSAI, r.SNSSAI).add(r)
	}
	getOrMake(s.byDir, r.Dir).add(r)

	// globale
	s.total.add(r)

	// combinata
	getOrMake(s.byKey, keyComposite(r)).add(r)
}

// --- Helpers per creare Record dai tuoi hook DL/UL ---

func NowBucketS(granSeconds int64) int64 {
	if granSeconds <= 0 {
		return time.Now().Unix()
	}
	return time.Now().Unix() / granSeconds
}

func NewRecord(ueIP string, qfi uint8, teid uint32, snssai string, dir Direction, inOct, txOct, inPkts, txPkts uint64, bucketS int64) Record {
	return Record{
		TsUnix:          time.Now().Unix(),
		BucketS:         bucketS,
		UEIP:            ueIP,
		TEID:            teid,
		QFI:             qfi,
		SNSSAI:          snssai,
		Dir:             dir,
		IncomingOctets:  inOct,
		TransmitOctets:  txOct,
		IncomingPackets: inPkts,
		TransmitPackets: txPkts,
		DroppedOctets:   u64sub(inOct, txOct),
	}
}

type Snapshot struct {
	Total    Counters               `json:"total"`
	ByBucket map[int64]Counters     `json:"byBucket"`
	ByUEIP   map[string]Counters    `json:"byUEIP"`
	ByTEID   map[uint32]Counters    `json:"byTEID"`
	ByQFI    map[uint8]Counters     `json:"byQFI"`
	BySNSSAI map[string]Counters    `json:"bySNSSAI"`
	ByDir    map[Direction]Counters `json:"byDir"`
}

func (s *AggStore) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cpB := make(map[int64]Counters, len(s.byBucket))
	for k, v := range s.byBucket {
		cpB[k] = *v
	}
	cpIP := make(map[string]Counters, len(s.byUEIP))
	for k, v := range s.byUEIP {
		cpIP[k] = *v
	}
	cpTEID := make(map[uint32]Counters, len(s.byTEID))
	for k, v := range s.byTEID {
		cpTEID[k] = *v
	}
	cpQFI := make(map[uint8]Counters, len(s.byQFI))
	for k, v := range s.byQFI {
		cpQFI[k] = *v
	}
	cpS := make(map[string]Counters, len(s.bySNSSAI))
	for k, v := range s.bySNSSAI {
		cpS[k] = *v
	}
	cpD := make(map[Direction]Counters, len(s.byDir))
	for k, v := range s.byDir {
		cpD[k] = *v
	}
	// If cpD is empty, initialize both directions to zero
	if len(cpD) == 0 {
		cpD[DL] = Counters{}
		cpD[UL] = Counters{}
	}

	return Snapshot{
		Total:    s.total,
		ByBucket: cpB,
		ByUEIP:   cpIP,
		ByTEID:   cpTEID,
		ByQFI:    cpQFI,
		BySNSSAI: cpS,
		ByDir:    cpD,
	}
}

func (s *AggStore) SnapshotJSON() []byte {
	snap := s.Snapshot()
	b, _ := json.MarshalIndent(snap, "", "  ")
	return b
}

/*
func (s *AggStore) getSnapshot() Snapshot {
	return s.Snapshot()
}*/

type Query struct {
	BucketS *int64
	UEIP    *string
	TEID    *uint32
	QFI     *uint8
	SNSSAI  *string
	Dir     *Direction
}

func (s *AggStore) QueryJSON(q Query) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]Counters)
	for k, c := range s.byKey {
		// parsing semplice della composite key
		// per performance potresti conservare anche una struct Key {BucketS, UEIP, ...}
		match := true
		if q.BucketS != nil && !containsToken(k, fmt.Sprintf("b=%d", *q.BucketS)) {
			match = false
		}
		if match && q.UEIP != nil && !containsToken(k, "ip="+*q.UEIP) {
			match = false
		}
		if match && q.TEID != nil && !containsToken(k, fmt.Sprintf("teid=%d", *q.TEID)) {
			match = false
		}
		if match && q.QFI != nil && !containsToken(k, fmt.Sprintf("qfi=%d", *q.QFI)) {
			match = false
		}
		if match && q.SNSSAI != nil && !containsToken(k, "s="+*q.SNSSAI) {
			match = false
		}
		if match && q.Dir != nil && !containsToken(k, fmt.Sprintf("d=%d", *q.Dir)) {
			match = false
		}
		if match {
			out[k] = *c
		}
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

// helper fast&cheap (per demo)
func containsToken(s, token string) bool {
	return len(s) >= len(token) && (s == token || (len(s) > len(token) && (containsWithSep(s, token))))
}
func containsWithSep(s, token string) bool {
	// key composta con '|' come separatore
	// "b=...|ip=...|..." => cerca "|token" o "token|" o inizio/fine
	if len(s) < len(token) || token == "" {
		return false
	}
	if s == token || hasPrefixToken(s, token) || hasSuffixToken(s, token) {
		return true
	}
	return hasMidToken(s, token)
}
func hasPrefixToken(s, token string) bool { return len(s) >= len(token) && s[:len(token)] == token }
func hasSuffixToken(s, token string) bool {
	return len(s) >= len(token) && s[len(s)-len(token):] == token
}
func hasMidToken(s, token string) bool {
	if token == "" {
		return false
	}
	padded := "|" + s + "|"
	needle := "|" + token + "|"
	return strings.Contains(padded, needle)
}

var Agg = NewAggStore()

func formatSNSSAI(s ngapType.SNSSAI) string {
	var sst uint8
	if len(s.SST.Value) > 0 {
		sst = s.SST.Value[0]
	}
	sd := 0
	if len(s.SD.Value) == 3 {
		sd = int(s.SD.Value[0])<<16 | int(s.SD.Value[1])<<8 | int(s.SD.Value[2])
	}
	return fmt.Sprintf("%d-%06x", sst, sd)
}

func TransmittedVolumeDL(byteIncoming, byteTransmitted uint64, ueIP string, qfi uint8, _ bool, teid uint32, _ *context.QosFlow, snssai ngapType.SNSSAI) {
	rec := NewRecord(
		ueIP, qfi, teid, formatSNSSAI(snssai),
		DL,
		byteIncoming, byteTransmitted,
		1, func() uint64 {
			if byteTransmitted == 0 {
				return 0
			}
			return 1
		}(),
		NowBucketS(1), // granularity 1s
	)
	Agg.Ingest(rec)
}

func TransmittedVolumeUL(byteIncoming, byteTransmitted uint64, ueIP string, qfi uint8, _ bool, teid uint32, _ *context.QosFlow, snssai ngapType.SNSSAI) {
	rec := NewRecord(
		ueIP, qfi, teid, formatSNSSAI(snssai),
		UL,
		byteIncoming, byteTransmitted,
		1, func() uint64 {
			if byteTransmitted == 0 {
				return 0
			}
			return 1
		}(),
		NowBucketS(1),
	)
	Agg.Ingest(rec)
}
