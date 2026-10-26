package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/scan"
)

// startScan runs an ARP sweep through the live capture session; replies are
// picked up by the normal parse pipeline.
func (rt *rtime) startScan(ctx context.Context, cidr string) {
	if rt.session == nil {
		rt.engine.Emit(model.Event{Kind: model.EventInfo, Message: "scan skipped: capture unavailable in passive mode"})
		return
	}
	nets := rt.iface.LocalNets()
	if cidr == "" && len(nets) > 0 {
		cidr = nets[0].String()
	}
	if cidr == "" {
		rt.engine.Emit(model.Event{Kind: model.EventInfo, Message: "scan skipped: interface has no IPv4 subnet"})
		return
	}
	rt.engine.Emit(model.Event{Kind: model.EventScan, Message: fmt.Sprintf("ARP sweep of %s started", cidr), Details: map[string]string{"cidr": cidr, "state": "started"}})
	start := time.Now()
	n, err := scan.ARPSweep(ctx, rt.session, rt.iface, cidr, scan.Options{Passes: 2})
	msg := fmt.Sprintf("ARP sweep of %s sent %d requests in %s", cidr, n, time.Since(start).Round(time.Millisecond))
	if err != nil && ctx.Err() == nil {
		msg += " (" + err.Error() + ")"
	}
	rt.engine.Emit(model.Event{Kind: model.EventScan, Message: msg, Details: map[string]string{"cidr": cidr, "state": "done"}})
}
