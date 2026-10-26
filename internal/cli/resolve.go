package cli

import (
	"fmt"
	"net"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

// resolveDevice accepts a MAC (any spelling) or an IP and returns the device.
// An IP resolves to the device most recently seen using it.
func resolveDevice(st *store.Store, ref string) (*model.Device, error) {
	if mac, err := model.NormalizeMAC(ref); err == nil {
		d, err := st.GetDevice(mac)
		if err != nil {
			return nil, err
		}
		if d == nil {
			return nil, fmt.Errorf("no device with MAC %s", mac)
		}
		return d, nil
	}
	if ip := net.ParseIP(ref); ip != nil {
		bindings, err := st.ListBindings()
		if err != nil {
			return nil, err
		}
		for _, b := range bindings { // newest first
			if b.IP == ref {
				d, err := st.GetDevice(b.MAC)
				if err != nil {
					return nil, err
				}
				if d != nil {
					return d, nil
				}
			}
		}
		return nil, fmt.Errorf("no device has been seen at %s", ref)
	}
	// Fall back to label / hostname match.
	devs, err := st.ListDevices()
	if err != nil {
		return nil, err
	}
	var hit *model.Device
	for i := range devs {
		if devs[i].Label == ref || devs[i].Hostname == ref {
			if hit != nil {
				return nil, fmt.Errorf("%q matches more than one device; use the MAC", ref)
			}
			hit = &devs[i]
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("%q is not a MAC, IP, label or hostname of a known device", ref)
	}
	return hit, nil
}
