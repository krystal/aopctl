package aopctl

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// maxNameBytes is the longest zone name Cloudflare allows, and so the
// longest hostname HostnameZone looks up. It bounds the names one lookup
// tries.
const maxNameBytes = 253

var zoneIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{32}$`)

// ValidZoneID reports whether id is a zone ID: 32 hex digits, in either
// case. A zone name has a dot, so it is never one.
func ValidZoneID(id string) bool {
	return zoneIDPattern.MatchString(id)
}

// Zone is a Cloudflare zone.
type Zone struct {
	ID   string
	Name string
}

// ZoneFinder looks up the active Cloudflare zones the API token can read:
// by ID, by name, or as the zone a hostname is in. Looking up a name or a
// hostname lists zones, which needs the token's Zone > Zone > Read
// permission. A zone's ID needs no lookup: pass it to NewClient.
//
// A ZoneFinder caches the zones it lists for each name, including names
// no zone has, so it lists each name once. It does not cache a failed list.
// It is safe for concurrent use.
type ZoneFinder struct {
	cf *cfClient

	mu    sync.Mutex
	named map[string][]Zone
}

// NewZoneFinder returns a ZoneFinder that uses opts.HTTPClient and
// opts.BaseURL.
func NewZoneFinder(apiToken string, opts Options) (*ZoneFinder, error) {
	if apiToken == "" {
		return nil, errors.New("no API token")
	}
	return &ZoneFinder{cf: newCFClient(apiToken, "", opts), named: map[string][]Zone{}}, nil
}

// Zone reads the zone with the ID, and fails unless it is active.
func (f *ZoneFinder) Zone(ctx context.Context, id string) (Zone, error) {
	if !ValidZoneID(id) {
		return Zone{}, fmt.Errorf("invalid zone ID %q: want 32 hex digits", id)
	}
	// The ID takes the place of {zone}, so errors redact it.
	cf := *f.cf
	cf.zoneID = id
	zone, err := cf.getZone(ctx)
	if err != nil {
		return Zone{}, fmt.Errorf("read zone: %w", err)
	}
	if !strings.EqualFold(zone.ID, id) || zone.Name == "" {
		return Zone{}, errors.New("read zone: the response describes another zone")
	}
	name := strings.ToLower(zone.Name)
	if zone.Status != statusActive {
		return Zone{}, fmt.Errorf("zone %s is not %s: its status is %q", name, statusActive, zone.Status)
	}
	return Zone{ID: zone.ID, Name: name}, nil
}

// ZoneNamed returns the active zone with the name. It fails with a
// *ZoneMatchError when no active zone has the name, or more than one has.
func (f *ZoneFinder) ZoneNamed(ctx context.Context, name string) (Zone, error) {
	name, err := normalizeName(name)
	if err != nil {
		return Zone{}, fmt.Errorf("invalid zone name: %w", err)
	}
	zones, err := f.list(ctx, name)
	if err != nil {
		return Zone{}, err
	}
	if len(zones) != 1 {
		return Zone{}, &ZoneMatchError{Name: name, Matches: len(zones)}
	}
	return zones[0], nil
}

// HostnameZone returns the active zone whose name is the longest the
// hostname equals or ends with, so a subdomain zone such as eu.example.com
// wins over example.com. It looks up the hostname, then each parent name
// with a dot in it, and stops at the first that an active zone has.
//
// It fails with a *ZoneMatchError when no name matches, or when more than
// one active zone has the first name that does. A failed lookup fails it
// too, without trying the shorter names, which could match a parent of the
// hostname's zone.
func (f *ZoneFinder) HostnameZone(ctx context.Context, hostname string) (Zone, error) {
	host, err := normalizeName(hostname)
	if err != nil {
		return Zone{}, err
	}
	for name := host; strings.Contains(name, "."); name = name[strings.IndexByte(name, '.')+1:] {
		zones, err := f.list(ctx, name)
		if err != nil {
			return Zone{}, fmt.Errorf("find the zone of %s: %w", host, err)
		}
		if len(zones) > 1 {
			return Zone{}, &ZoneMatchError{Hostname: host, Name: name, Matches: len(zones)}
		}
		if len(zones) == 1 {
			return zones[0], nil
		}
	}
	return Zone{}, &ZoneMatchError{Hostname: host}
}

// list returns the active zones named name, listing them once. Errors are
// not cached.
func (f *ZoneFinder) list(ctx context.Context, name string) ([]Zone, error) {
	f.mu.Lock()
	zones, ok := f.named[name]
	f.mu.Unlock()
	if ok {
		return zones, nil
	}
	zones, err := f.cf.listZones(ctx, name)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.named[name] = zones
	f.mu.Unlock()
	return zones, nil
}

// normalizeName normalizes a hostname or zone name as NormalizeHostnames
// does, and rejects one longer than Cloudflare allows.
func normalizeName(raw string) (string, error) {
	names, err := NormalizeHostnames([]string{raw})
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", errors.New("empty hostname")
	}
	if len(names[0]) > maxNameBytes {
		return "", fmt.Errorf("invalid hostname %q: longer than %d bytes", raw, maxNameBytes)
	}
	return names[0], nil
}
