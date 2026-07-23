// Package geo resolves IP addresses to approximate map coordinates using a local
// MaxMind-format city database (DB-IP Lite, CC-BY). Lookups are in-memory (mmap),
// so they add no network latency to the request path.
package geo

import (
	"net"
	"sync"

	geoip2 "github.com/oschwald/geoip2-golang"
)

var (
	mu     sync.RWMutex
	reader *geoip2.Reader
)

// Point is a resolved IP location for plotting on a map.
type Point struct {
	IP      string  `json:"ip"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	City    string  `json:"city,omitempty"`
	Country string  `json:"country,omitempty"`
}

// Init opens the city database at path. Call once at startup; safe to skip (a
// missing DB just disables geolocation, Lookup then returns ok=false).
func Init(path string) error {
	r, err := geoip2.Open(path)
	if err != nil {
		return err
	}
	mu.Lock()
	if reader != nil {
		_ = reader.Close()
	}
	reader = r
	mu.Unlock()
	return nil
}

// Ready reports whether a database is loaded.
func Ready() bool {
	mu.RLock()
	defer mu.RUnlock()
	return reader != nil
}

// Lookup resolves ipStr to a Point. Returns ok=false when the DB is absent, the
// IP is unparseable/private, or no location is recorded.
func Lookup(ipStr string) (Point, bool) {
	mu.RLock()
	r := reader
	mu.RUnlock()
	if r == nil {
		return Point{}, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Point{}, false
	}
	rec, err := r.City(ip)
	if err != nil || rec == nil {
		return Point{}, false
	}
	lat, lon := rec.Location.Latitude, rec.Location.Longitude
	if lat == 0 && lon == 0 {
		return Point{}, false // no usable location
	}
	return Point{
		IP:      ipStr,
		Lat:     lat,
		Lon:     lon,
		City:    rec.City.Names["en"],
		Country: rec.Country.Names["en"],
	}, true
}
