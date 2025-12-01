package rc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/free5gc/n3iwf/internal/snapshot"
)

// CollectWiFiMetricsSnapshot legge il file JSON generato dal wifi-metrics-exporter
// e produce uno snapshot RC compatibile con l'arricchimento UE.
func CollectWiFiMetricsSnapshot(path string) (snapshot.RCSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		err := fmt.Errorf("wifi metrics file %s is empty", path)
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	var payload map[string]wifiInterfaceMetrics
	if err := json.Unmarshal(data, &payload); err != nil {
		err = fmt.Errorf("cannot parse wifi metrics JSON: %w", err)
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	stations := make([]snapshot.RCStation, 0, len(payload)*4)
	for name, metrics := range payload {
		ifName := strings.TrimSpace(name)

		// Costruisci la lista di station combinando hostapd e iw station dump
		hostapdStations := normalizeStationMap(metrics.Hostapd.Stations)
		iwStations := normalizeStationMap(metrics.StationDump)
		stations = append(stations, buildStationsFromMetrics(ifName, hostapdStations, iwStations)...)
	}

	return snapshot.RCSnapshot{
		Timestamp: time.Now(),
		Stations:  stations,
	}, nil
}

type wifiInterfaceMetrics struct {
	TS          int64                        `json:"ts"`
	Hostapd     wifiHostapdMetrics           `json:"hostapd"`
	StationDump map[string]map[string]string `json:"station_dump"`
	Survey      []map[string]any             `json:"survey"`
	Ethtool     map[string]any               `json:"ethtool"`
}

type wifiHostapdMetrics struct {
	Status   map[string]string            `json:"status"`
	Stations map[string]map[string]string `json:"stations"`
}

func buildStationsFromMetrics(iface string, hostapd, stationDump map[string]map[string]string) []snapshot.RCStation {
	allMACs := make(map[string]struct{})
	for mac := range hostapd {
		allMACs[mac] = struct{}{}
	}
	for mac := range stationDump {
		allMACs[mac] = struct{}{}
	}

	if len(allMACs) == 0 {
		return nil
	}

	keys := make([]string, 0, len(allMACs))
	for mac := range allMACs {
		keys = append(keys, mac)
	}
	sort.Strings(keys)

	stations := make([]snapshot.RCStation, 0, len(keys))
	for _, mac := range keys {
		hostData := copyStringMap(hostapd[mac])
		iwData := copyStringMap(stationDump[mac])

		fields := make(map[string]string, len(hostData)+len(iwData)+1)
		var ip string

		if len(hostData) > 0 {
			keys := sortedKeys(hostData)
			for _, k := range keys {
				v := hostData[k]
				fields[k] = v
				if ip == "" && (k == "ip" || k == "ip_addr" || k == "ipv4") {
					ip = strings.TrimSpace(v)
				}
			}
		}

		if len(iwData) > 0 {
			keys := sortedKeys(iwData)
			for _, k := range keys {
				v := iwData[k]
				prefKey := "iw." + k
				fields[prefKey] = v
				if ip == "" && (k == "ip" || k == "ipv4_addr" || k == "addr") {
					ip = strings.TrimSpace(v)
				}
			}
		}

		if ip != "" {
			fields["ip"] = ip
		}

		stations = append(stations, snapshot.RCStation{
			Interface:   iface,
			MAC:         mac,
			IP:          ip,
			Fields:      fields,
			Hostapd:     hostData,
			StationDump: iwData,
		})
	}

	return stations
}

func normalizeStationMap(in map[string]map[string]string) map[string]map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(in))
	for mac, fields := range in {
		lower := strings.ToLower(strings.TrimSpace(mac))
		if lower == "" {
			continue
		}
		out[lower] = copyStringMap(fields)
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
