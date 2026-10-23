package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/krystal/aopctl/aopctl"
)

const (
	hostnameZoneUsage = "zone name or ID: act only on the hostnames in it, found with Zone > Zone > Read. The ID in CLOUDFLARE_ZONE_ID looks nothing up and keeps every hostname"
	zoneZoneUsage     = "zone name or ID, instead of CLOUDFLARE_ZONE_ID. A name is looked up with Zone > Zone > Read"
)

// zoneFlag adds --zone. It completes nothing, as completion never calls
// the API.
func zoneFlag(cmd *cobra.Command, p *string, usage string) {
	cmd.Flags().StringVar(p, "zone", "", usage)
}

// zoneArg is a --zone value: a zone ID or a zone name, which has a dot.
// Both are empty without --zone.
type zoneArg struct {
	id   string
	name string
}

func parseZoneArg(v string) (zoneArg, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return zoneArg{}, nil
	}
	if aopctl.ValidZoneID(v) {
		return zoneArg{id: strings.ToLower(v)}, nil
	}
	names, err := aopctl.NormalizeHostnames([]string{v})
	if err != nil || len(names) != 1 || !strings.Contains(names[0], ".") {
		return zoneArg{}, usagef("invalid --zone %q: want a zone name, such as example.com, or a zone ID of 32 hex digits", v)
	}
	return zoneArg{name: names[0]}, nil
}

func (z zoneArg) given() bool { return z.id != "" || z.name != "" }

func (a *app) envZoneID() string {
	return strings.TrimSpace(a.getenv("CLOUDFLARE_ZONE_ID"))
}

// zoneHint is the --zone of a command printed before the zone is
// resolved: the --zone given, or else CLOUDFLARE_ZONE_ID.
func (a *app) zoneHint(z zoneArg) string {
	if v := cmp.Or(z.id, z.name, a.envZoneID()); v != "" {
		return " --zone " + v
	}
	return ""
}

// zoneCmd starts a printed command that acts in the zone, such as
// "aopctl hostname prune --zone <ID>".
func (a *app) zoneCmd(zoneID, sub string) string {
	return a.commandPath() + " " + sub + " --zone " + zoneID
}

func (a *app) newClient(token, zoneID string) (*aopctl.Client, error) {
	return aopctl.NewClient(token, zoneID, aopctl.Options{BaseURL: a.baseURL, Now: a.now, Wait: a.wait})
}

// zoneCommandZone returns the zone ID a zone command acts in: --zone, then
// CLOUDFLARE_ZONE_ID. Only a --zone name is looked up.
func (a *app) zoneCommandZone(ctx context.Context, token string, z zoneArg) (string, error) {
	switch {
	case z.id != "":
		return z.id, nil
	case z.name != "":
		finder, err := aopctl.NewZoneFinder(token, aopctl.Options{BaseURL: a.baseURL})
		if err != nil {
			return "", err
		}
		zone, err := finder.ZoneNamed(ctx, z.name)
		if err != nil {
			return "", lookupError(err)
		}
		return zone.ID, nil
	}
	if id := a.envZoneID(); id != "" {
		return id, nil
	}
	return "", errors.New("no zone: pass --zone or set CLOUDFLARE_ZONE_ID")
}

// zoneHosts is a zone a hostname command acts in, and its hostnames.
// zone.Name is "" for CLOUDFLARE_ZONE_ID's zone, which is not looked up.
type zoneHosts struct {
	zone  aopctl.Zone
	hosts []string
}

// hostnameZones groups the hostnames by the zone a hostname command acts
// in. fromFlags means they came from --hostname rather than AOP_HOSTNAMES.
//
// With CLOUDFLARE_ZONE_ID set and no --zone, or a --zone with the same ID,
// every hostname is in that zone and nothing is looked up. Another --zone
// keeps only the hostnames in it: one from --hostname outside it is a usage
// error, and AOP_HOSTNAMES entries outside it are skipped. Without either,
// each hostname is in the zone it resolves to. A zone with more than
// aopctl.MaxHostnames hostnames is a usage error.
func (a *app) hostnameZones(ctx context.Context, token string, z zoneArg, hosts []string, fromFlags bool) ([]zoneHosts, error) {
	groups, err := a.groupHostnames(ctx, token, z, hosts, fromFlags)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if len(g.hosts) <= aopctl.MaxHostnames {
			continue
		}
		if g.zone.Name == "" {
			return nil, usagef("%d hostnames given: a certificate can serve at most %d", len(g.hosts), aopctl.MaxHostnames)
		}
		return nil, usagef("%d hostnames in zone %s: a certificate can serve at most %d", len(g.hosts), g.zone.Name, aopctl.MaxHostnames)
	}
	return groups, nil
}

func (a *app) groupHostnames(ctx context.Context, token string, z zoneArg, hosts []string, fromFlags bool) ([]zoneHosts, error) {
	if envID := a.envZoneID(); envID != "" && (!z.given() || strings.EqualFold(z.id, envID)) {
		return []zoneHosts{{zone: aopctl.Zone{ID: envID}, hosts: hosts}}, nil
	}
	if !z.given() && len(hosts) == 0 {
		return nil, errors.New("no zone: pass --zone, set CLOUDFLARE_ZONE_ID or list hostnames")
	}
	finder, err := aopctl.NewZoneFinder(token, aopctl.Options{BaseURL: a.baseURL})
	if err != nil {
		return nil, err
	}

	if !z.given() {
		var groups []zoneHosts
		index := map[string]int{}
		for _, h := range hosts {
			zone, err := finder.HostnameZone(ctx, h)
			if err != nil {
				return nil, lookupError(err)
			}
			i, ok := index[zone.ID]
			if !ok {
				i = len(groups)
				index[zone.ID] = i
				groups = append(groups, zoneHosts{zone: zone})
			}
			groups[i].hosts = append(groups[i].hosts, h)
		}
		return groups, nil
	}

	var zone aopctl.Zone
	if z.id != "" {
		zone, err = finder.Zone(ctx, z.id)
	} else {
		zone, err = finder.ZoneNamed(ctx, z.name)
	}
	if err != nil {
		return nil, lookupError(err)
	}
	g := zoneHosts{zone: zone}
	for _, h := range hosts {
		in, err := inZone(ctx, finder, zone, h)
		if err != nil {
			return nil, lookupError(err)
		}
		switch {
		case in:
			g.hosts = append(g.hosts, h)
		case fromFlags:
			return nil, usagef("--hostname %s is not in zone %s", h, zone.Name)
		}
	}
	return []zoneHosts{g}, nil
}

// inZone reports whether the hostname is in the zone: it is the zone's name
// or ends with it, and is not in a subdomain zone.
func inZone(ctx context.Context, finder *aopctl.ZoneFinder, zone aopctl.Zone, host string) (bool, error) {
	if host != zone.Name && !strings.HasSuffix(host, "."+zone.Name) {
		return false, nil
	}
	found, err := finder.HostnameZone(ctx, host)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(found.ID, zone.ID), nil
}

// writeZone returns the one zone a hostname command that writes acts in.
// Hostnames in several zones are a usage error, as such a command changes
// one zone at a time.
func writeZone(command string, groups []zoneHosts) (zoneHosts, error) {
	if len(groups) > 1 {
		var b strings.Builder
		fmt.Fprintf(&b, "the hostnames are in %d zones, and %s changes one zone at a time:", len(groups), command)
		for _, g := range groups {
			fmt.Fprintf(&b, "\n  %s (%s): %d hostname(s)", g.zone.Name, g.zone.ID, len(g.hosts))
		}
		b.WriteString("\nPass --zone to pick one.")
		return zoneHosts{}, &usageError{msg: b.String()}
	}
	g := groups[0]
	if len(g.hosts) == 0 {
		return zoneHosts{}, fmt.Errorf("none of the hostnames in AOP_HOSTNAMES is in zone %s", g.zone.Name)
	}
	return g, nil
}

// printZone names the zone a hostname command acts in, unless it is
// CLOUDFLARE_ZONE_ID's, which keeps the output as it was before zones were
// looked up.
func printZone(w io.Writer, zone aopctl.Zone) {
	if zone.Name != "" {
		fmt.Fprintf(w, "Zone: %s (%s)\n", zone.Name, zone.ID)
	}
}

// lookupError says how to fix a failed zone lookup, or avoid it.
func lookupError(err error) error {
	if errors.Is(err, aopctl.ErrZoneListForbidden) {
		return fmt.Errorf("%w\nTo skip the lookup, set CLOUDFLARE_ZONE_ID, or pass a zone command --zone with the zone's ID", err)
	}
	if e, ok := errors.AsType[*aopctl.ZoneMatchError](err); ok {
		if e.Matches == 0 {
			return fmt.Errorf("%w: check that CLOUDFLARE_API_TOKEN can read the zone, which needs Zone > Zone > Read", err)
		}
		return fmt.Errorf("%w: set CLOUDFLARE_ZONE_ID to the zone's ID", err)
	}
	return err
}
