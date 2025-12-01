package rc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/snapshot"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/vishvananda/netlink"
)

// EnrichSnapshot associa le informazioni provenienti da hostapd con i contatori
// raccolti dal N3IWF e con il contesto UE esposto da AMF/N3IWF.
func EnrichSnapshot(rcSnap *snapshot.RCSnapshot, metrics snapshot.Snapshot, ctx *snapshot.N3iwfAppSnapshot) {
	if rcSnap == nil {
		return
	}

	ipMetrics := metrics.ByUEIP
	ueByIP := buildUEMap(ctx)
	arpMap := loadARPTable()
	ueByMAC := make(map[string]*context.N3IWFRanUe)
	for mac, ip := range arpMap {
		if ue, ok := ueByIP[ip]; ok {
			ueByMAC[mac] = ue
		}
	}
	ikeByRan := buildIKEByRanID(ctx)
	n3iwfID := n3iwfIdentifier()

	var associations []snapshot.RCUEAssociation
	for _, station := range rcSnap.Stations {
		assocStation := station.DeepCopy()
		assoc := snapshot.RCUEAssociation{
			Interface: station.Interface,
			MAC:       station.MAC,
			Station:   assocStation,
		}

		ip := extractIPFromStation(station)
		if ip == "" {
			ip = strings.TrimSpace(arpMap[strings.ToLower(station.MAC)])
		}
		assoc.UEIP = ip
		if assoc.UEIP != "" {
			if assocStation.Fields == nil {
				assocStation.Fields = make(map[string]string)
			}
			assocStation.Fields["ip"] = assoc.UEIP
			assocStation.IP = assoc.UEIP
		}

		if counters, ok := ipMetrics[ip]; ok {
			assoc.Counters = counters
		}

		var matchedUE *context.N3IWFRanUe
		var ok bool
		if ue, found := ueByIP[ip]; found && ip != "" {
			matchedUE = ue
			ok = true
		} else if ue, found := ueByMAC[strings.ToLower(station.MAC)]; found {
			matchedUE = ue
			ok = true
			if assoc.UEIP == "" {
				if v4 := strings.TrimSpace(matchedUE.RanUeSharedCtx.IPAddrv4); v4 != "" {
					assoc.UEIP = v4
					assocStation.Fields["ip"] = v4
					assocStation.IP = v4
				} else if v6 := strings.TrimSpace(matchedUE.RanUeSharedCtx.IPAddrv6); v6 != "" {
					assoc.UEIP = v6
					assocStation.Fields["ip"] = v6
					assocStation.IP = v6
				}
			}
		}

		if ok {
			assoc.UE = buildUEInfo(matchedUE, ikeByRan[matchedUE.RanUeSharedCtx.RanUeNgapId], n3iwfID)
		} else if assoc.UEIP != "" && len(ipMetrics) > 0 {
			assoc.Mismatches = append(assoc.Mismatches, "ue_not_found")
		}

		associations = append(associations, assoc)
	}

	rcSnap.Associations = associations
	rcSnap.Stations = nil
}

func buildUEMap(ctx *snapshot.N3iwfAppSnapshot) map[string]*context.N3IWFRanUe {
	result := make(map[string]*context.N3IWFRanUe)
	if ctx == nil {
		return result
	}
	for i := range ctx.UEs {
		ue := &ctx.UEs[i]
		if ip := strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv4); ip != "" {
			result[ip] = ue
		}
		if ip := strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv6); ip != "" {
			result[ip] = ue
		}
	}
	return result
}

func extractIPFromStation(station snapshot.RCStation) string {
	if station.IP != "" {
		return strings.TrimSpace(station.IP)
	}
	searchMaps := []map[string]string{
		station.Fields,
		station.Hostapd,
		station.StationDump,
	}
	for _, m := range searchMaps {
		if ip := extractIPFromMap(m); ip != "" {
			return ip
		}
	}
	return ""
}

func extractIPFromMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	candidates := []string{
		m["ip_addr"],
		m["ip"],
		m["ipv4"],
		m["addr"],
	}
	for _, val := range candidates {
		if val == "" {
			continue
		}
		parts := strings.FieldsFunc(val, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func buildUEInfo(ue *context.N3IWFRanUe, ike *snapshot.UEIKESnapshot, n3iwfID string) *snapshot.RCAssociatedUE {
	if ue == nil {
		return nil
	}
	shared := makeRCRanUeSharedCtx(ue)
	info := &snapshot.RCAssociatedUE{
		RCRanUeSharedCtx: shared,
		N3IwfID:          n3iwfID,
		AmfName:          "",
	}

	if ue.RanUeSharedCtx.AMF != nil {
		info.AmfSCTP = ue.RanUeSharedCtx.AMF.SCTPAddr
		if ue.RanUeSharedCtx.AMF.AMFName != nil {
			info.AmfName = string(ue.RanUeSharedCtx.AMF.AMFName.Value)
		}
	}

	if ike != nil {
		info.IKELocalSPI = ike.N3IWFIKESecurityAssociation.LocalSPI
		info.IKERemoteSPI = ike.N3IWFIKESecurityAssociation.RemoteSPI
		info.IKEState = ike.N3IWFIKESecurityAssociation.State
		info.UeBehindNAT = ike.N3IWFIKESecurityAssociation.UeBehindNAT
		info.N3iwfBehindNAT = ike.N3IWFIKESecurityAssociation.N3iwfBehindNAT
		info.ChildSAs = convertChildSAs(ike.N3IWFChildSecurityAssociation)
	}

	return info
}

func loadARPTable() map[string]string {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return map[string]string{}
	}
	defer file.Close()

	result := make(map[string]string)
	scanner := bufio.NewScanner(file)
	firstLine := true
	for scanner.Scan() {
		if firstLine {
			firstLine = false
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip := strings.TrimSpace(fields[0])
		mac := strings.ToLower(strings.TrimSpace(fields[3]))
		if mac == "" || mac == "00:00:00:00:00:00" || ip == "" {
			continue
		}
		result[mac] = ip
	}
	return result
}

func buildIKEByRanID(ctx *snapshot.N3iwfAppSnapshot) map[int64]*snapshot.UEIKESnapshot {
	result := make(map[int64]*snapshot.UEIKESnapshot)
	if ctx == nil {
		return result
	}

	spiMap := make(map[uint64]*snapshot.UEIKESnapshot)
	for i := range ctx.N3IWFContext.IKEUePool {
		item := &ctx.N3IWFContext.IKEUePool[i]
		if spi := item.N3IWFIKESecurityAssociation.LocalSPI; spi != 0 {
			spiMap[spi] = item
		}
		if spi := item.N3IWFIKESecurityAssociation.RemoteSPI; spi != 0 {
			spiMap[spi] = item
		}
	}

	for ranID, spi := range ctx.N3IWFContext.NGAPIdToIKESPI {
		if ike, ok := spiMap[spi]; ok {
			result[ranID] = ike
		}
	}

	return result
}

func convertChildSAs(child map[uint32]snapshot.ChildSecurityAssociationSnapshot) []snapshot.RCChildSAInfo {
	if len(child) == 0 {
		return nil
	}
	keys := make([]uint32, 0, len(child))
	for spi := range child {
		keys = append(keys, spi)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	result := make([]snapshot.RCChildSAInfo, 0, len(child))
	for _, spi := range keys {
		item := child[spi]
		info := snapshot.RCChildSAInfo{
			InboundSPI:        item.InboundSPI,
			OutboundSPI:       item.OutboundSPI,
			TunnelIface:       ifaceName(item.XfrmIface),
			PeerPublicIP:      ipString(item.PeerPublicIPAddr),
			LocalPublicIP:     ipString(item.LocalPublicIPAddr),
			N3IWFPort:         item.N3IWFPort,
			NATPort:           item.NATPort,
			EnableEncapsulate: item.EnableEncapsulate,
			SelectedIPProto:   item.SelectedIPProtocol,
		}
		if len(item.PDUSessionIds) > 0 {
			info.PduSessionIds = append([]int64(nil), item.PDUSessionIds...)
		}
		result = append(result, info)
	}
	return result
}

func makeRCRanUeSharedCtx(ue *context.N3IWFRanUe) snapshot.RCRanUeSharedCtx {
	if ue == nil {
		return snapshot.RCRanUeSharedCtx{}
	}
	shared := snapshot.RCRanUeSharedCtx{
		RanUeNgapId:                      ue.RanUeSharedCtx.RanUeNgapId,
		AmfUeNgapId:                      ue.RanUeSharedCtx.AmfUeNgapId,
		IPAddrv4:                         strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv4),
		IPAddrv6:                         strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv6),
		PortNumber:                       ue.RanUeSharedCtx.PortNumber,
		MaskedIMEISV:                     ue.RanUeSharedCtx.MaskedIMEISV,
		Guti:                             strings.TrimSpace(ue.RanUeSharedCtx.Guti),
		Guami:                            ue.RanUeSharedCtx.Guami,
		IndexToRfsp:                      ue.RanUeSharedCtx.IndexToRfsp,
		Ambr:                             ue.RanUeSharedCtx.Ambr,
		AllowedNssai:                     ue.RanUeSharedCtx.AllowedNssai,
		RadioCapability:                  ue.RanUeSharedCtx.RadioCapability,
		CoreNetworkAssistanceInformation: ue.RanUeSharedCtx.CoreNetworkAssistanceInformation,
		IMSVoiceSupported:                ue.RanUeSharedCtx.IMSVoiceSupported,
		RRCEstablishmentCause:            ue.RanUeSharedCtx.RRCEstablishmentCause,
		PduSessionReleaseList:            ue.RanUeSharedCtx.PduSessionReleaseList,
		UeCtxRelState:                    bool(ue.RanUeSharedCtx.UeCtxRelState),
		PduSessResRelState:               bool(ue.RanUeSharedCtx.PduSessResRelState),
	}
	if len(ue.RanUeSharedCtx.PduSessionList) > 0 {
		shared.PduSessionList = make(map[int64]snapshot.RCPDUSession, len(ue.RanUeSharedCtx.PduSessionList))
		for id, sess := range ue.RanUeSharedCtx.PduSessionList {
			shared.PduSessionList[id] = makeRCPDUSession(sess)
		}
	}
	return shared
}

func makeRCPDUSession(sess *context.PDUSession) snapshot.RCPDUSession {
	if sess == nil {
		return snapshot.RCPDUSession{}
	}
	out := snapshot.RCPDUSession{
		ID:                               sess.Id,
		Type:                             sess.Type,
		Ambr:                             sess.Ambr,
		SNSSAI:                           sess.Snssai,
		NetworkInstance:                  sess.NetworkInstance,
		SecurityCipher:                   sess.SecurityCipher,
		SecurityIntegrity:                sess.SecurityIntegrity,
		MaximumIntegrityDataRateUplink:   sess.MaximumIntegrityDataRateUplink,
		MaximumIntegrityDataRateDownlink: sess.MaximumIntegrityDataRateDownlink,
	}
	if len(sess.QFIList) > 0 {
		out.QFIList = append([]uint8(nil), sess.QFIList...)
	}
	if len(sess.QosFlows) > 0 {
		out.QosFlows = make(map[int64]snapshot.RCQosFlow, len(sess.QosFlows))
		for id, flow := range sess.QosFlows {
			if flow == nil {
				continue
			}
			out.QosFlows[id] = snapshot.RCQosFlow{
				Identifier: flow.Identifier,
				Parameters: flow.Parameters,
			}
		}
	}
	if sess.GTPConnInfo != nil {
		out.GTPConnInfo = makeRCGTPConnectionInfo(sess.GTPConnInfo)
	}
	return out
}

func makeRCGTPConnectionInfo(info *context.GTPConnectionInfo) *snapshot.RCGTPConnectionInfo {
	if info == nil {
		return nil
	}
	rc := &snapshot.RCGTPConnectionInfo{
		UPFIPAddr:    info.UPFIPAddr,
		IncomingTEID: info.IncomingTEID,
		OutgoingTEID: info.OutgoingTEID,
	}
	if info.UPFUDPAddr != nil {
		rc.UPFUDPAddr = makeRCUDPAddr(info.UPFUDPAddr)
	}
	return rc
}

func makeRCUDPAddr(addr net.Addr) *snapshot.RCUDPAddr {
	if addr == nil {
		return nil
	}
	switch v := addr.(type) {
	case *net.UDPAddr:
		return &snapshot.RCUDPAddr{
			IP:   v.IP.String(),
			Port: v.Port,
			Zone: v.Zone,
		}
	default:
		return &snapshot.RCUDPAddr{Raw: addr.String()}
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func ifaceName(lnk netlink.Link) string {
	if lnk == nil {
		return ""
	}
	attrs := lnk.Attrs()
	if attrs == nil {
		return ""
	}
	return attrs.Name
}

func n3iwfIdentifier() string {
	if factory.N3iwfConfig == nil || factory.N3iwfConfig.Configuration == nil ||
		factory.N3iwfConfig.Configuration.N3IWFInfo == nil ||
		factory.N3iwfConfig.Configuration.N3IWFInfo.GlobalN3IWFID == nil {
		return ""
	}
	global := factory.N3iwfConfig.Configuration.N3IWFInfo.GlobalN3IWFID
	if global.PLMNID == nil {
		return fmt.Sprintf("%d", global.N3IWFID)
	}
	return fmt.Sprintf("%s-%s-%d", global.PLMNID.Mcc, global.PLMNID.Mnc, global.N3IWFID)
}
