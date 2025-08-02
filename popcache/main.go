package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/yzp0n/ncdn/httprps"
	"github.com/yzp0n/ncdn/popcache/cache"
	"github.com/yzp0n/ncdn/types"
)

var (
	originURLStr = flag.String("originURL", "http://localhost:8888", "Origin server URL")
	listenAddr   = flag.String("listenAddr", ":8889", "Address to listen on")
	nodeID       = flag.String("nodeId", "unknown_node", "Name of the node")
)

// Server represents the PoP cache server
type Server struct {
	originURL  *url.URL
	cacheStore *cache.CacheStore
	rps        *httprps.Middleware
	startTime  time.Time
	nodeID     string
}

// NewServer creates a new PoP cache server
func NewServer(originURL *url.URL, nodeID string) *Server {
	mux := http.NewServeMux()
	rps := httprps.NewMiddleware(mux)

	server := &Server{
		originURL:  originURL,
		cacheStore: cache.NewCacheStore(),
		rps:        rps,
		startTime:  time.Now(),
		nodeID:     nodeID,
	}

	server.setupRoutes(mux)
	http.Handle("/", rps)

	return server
}

// setupRoutes configures all the HTTP routes for the server
func (s *Server) setupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/statusz", s.handleStatus)
	mux.HandleFunc("/latencyz", s.handleLatency)
	mux.HandleFunc("/", s.handleRequest)
}

// handleStatus returns the current status of the PoP server
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := types.PoPStatus{
		Id:     s.nodeID,
		Uptime: time.Since(s.startTime).Seconds(),
		Load:   s.rps.GetRPS(),
	}

	bs, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal PoP status: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bs)
}

// handleLatency returns a 204 No Content response for latency checks
func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// handleRequest handles all incoming requests with caching logic
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.proxyToOrigin(w, r)
		return
	}

	if s.serveCachedResponse(w, r) {
		return
	}

	s.fetchAndCache(w, r)
}

// proxyToOrigin forwards non-GET requests to the origin server
func (s *Server) proxyToOrigin(w http.ResponseWriter, r *http.Request) {
	proxy := httputil.ReverseProxy{
		Rewrite: func(rp *httputil.ProxyRequest) {
			rp.SetXForwarded()
			rp.Out.Header.Set("X-NCDN-PoPCache-NodeId", s.nodeID)
			rp.SetURL(s.originURL)
		},
	}
	proxy.ServeHTTP(w, r)
}

// serveCachedResponse attempts to serve a cached response if available and fresh
func (s *Server) serveCachedResponse(w http.ResponseWriter, r *http.Request) bool {
	key := r.URL.String()

	cachedResp, exists := s.cacheStore.Get(key)
	if !exists {
		return false
	}

	headerStruct := cache.NewParsedHeaders(cachedResp.Header)
	maxAge, hasMaxAge := headerStruct.GetDirective("Cache-Control", "max-age")
	if !hasMaxAge {
		return false
	}

	maxAgeInt, err := strconv.Atoi(maxAge)
	if err != nil {
		log.Printf("Invalid max-age value %q for key %q: %v", maxAge, key, err)
		return false
	}

	if !cache.IsFresh(cachedResp.StoredAt, maxAgeInt) {
		return false
	}

	s.writeCachedResponse(w, cachedResp)
	return true
}

// writeCachedResponse writes a cached response to the ResponseWriter
func (s *Server) writeCachedResponse(w http.ResponseWriter, cachedResp *cache.CachedResponse) {
	for k, vals := range cachedResp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(cachedResp.StatusCode)
	w.Write(cachedResp.Body)
}

// fetchAndCache fetches a response from origin and caches it if cacheable
func (s *Server) fetchAndCache(w http.ResponseWriter, r *http.Request) {
	req := s.buildOriginRequest(r)

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("Origin fetch failed for %s: %v", req.URL.String(), err)
		http.Error(w, "Origin fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body for %s: %v", req.URL.String(), err)
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)

	if cache.IsCacheable(resp) {
		s.cacheResponse(r.URL.String(), resp, body)
	}
}

// buildOriginRequest creates a request to the origin server
func (s *Server) buildOriginRequest(r *http.Request) *http.Request {
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.URL.Scheme = s.originURL.Scheme
	req.URL.Host = s.originURL.Host
	req.URL.Path = r.URL.Path
	req.URL.RawQuery = r.URL.RawQuery
	req.Host = s.originURL.Host
	return req
}

// cacheResponse stores a response in the cache
func (s *Server) cacheResponse(key string, resp *http.Response, body []byte) {
	cached := &cache.CachedResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       body,
		StoredAt:   time.Now(),
	}
	s.cacheStore.Set(key, cached)
}

func main() {
	flag.Parse()

	originURL, err := url.Parse(*originURLStr)
	if err != nil {
		log.Fatalf("Failed to parse origin URL %q: %v", *originURLStr, err)
	}

	_ = NewServer(originURL, *nodeID)

	log.Printf("Starting PoP cache server on %s, proxying to %s", *listenAddr, *originURLStr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
