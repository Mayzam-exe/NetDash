package engine

import (
	"netdash/internal/snmp"
)

// ProbeRouter reports what the configured router answers over SNMP — its
// identity, interfaces, and whether it exposes a per-station Wi-Fi signal
// tree. Empty host/community fall back to the saved SNMP settings.
func (e *Engine) ProbeRouter(host, community string) snmp.ProbeReport {
	st := e.Settings()
	if host == "" {
		host = st.SnmpHost
	}
	if host == "" {
		host = st.GatewayIP
	}
	if community == "" {
		community = st.SnmpCommunity
	}
	rep, err := snmp.Probe(snmp.Config{Host: host, Community: community})
	if err != nil {
		return snmp.ProbeReport{Error: err.Error()}
	}
	return rep
}
