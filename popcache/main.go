package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/yzp0n/ncdn/httprps"
	"github.com/yzp0n/ncdn/types"

	"github.com/yzp0n/ncdn/popcache/rfc9111"
)

var originURLStr = flag.String("originURL", "http://localhost:8888", "Origin server URL")
var listenAddr = flag.String("listenAddr", ":8889", "Address to listen on")
var nodeId = flag.String("nodeId", "unknown_node", "Name of the node")

func main() {
	flag.Parse()

	originURL, err := url.Parse(*originURLStr)
	if err != nil {
		log.Fatalf("Failed to parse origin URL %q: %v", *originURLStr, err)
	}

	start := time.Now()

	mux := http.NewServeMux()
	rps := httprps.NewMiddleware(mux)
	http.Handle("/", rps)

	cacheStore := rfc9111.NewCacheStore()

	mux.HandleFunc("/statusz", func(w http.ResponseWriter, r *http.Request) {
		s := types.PoPStatus{
			Id:     *nodeId,
			Uptime: time.Since(start).Seconds(),
			Load:   rps.GetRPS(),
		}
		bs, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal PoP status: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(bs)
	})
	mux.HandleFunc("/latencyz", func(w http.ResponseWriter, r *http.Request) {
		// return 204
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Handle non-GET requests with reverse proxy
		if r.Method != http.MethodGet {
			proxy := httputil.ReverseProxy{
				Rewrite: func(rp *httputil.ProxyRequest) {
					rp.SetXForwarded()
					rp.Out.Header.Set("X-NCDN-PoPCache-NodeId", *nodeId)
					rp.SetURL(originURL)
				},
			}
			proxy.ServeHTTP(w, r)
			return
		}

		key := r.URL.String()

		if cachedResp, ok := cacheStore.Get(key); ok {
			for k, vals := range cachedResp.Header {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(cachedResp.StatusCode)
			_, _ = w.Write(cachedResp.Body)
			return
		}

		req := r.Clone(r.Context())
		req.RequestURI = ""
		req.URL.Scheme = originURL.Scheme
		req.URL.Host = originURL.Host
		req.URL.Path = r.URL.Path
		req.URL.RawQuery = r.URL.RawQuery
		req.Host = originURL.Host

		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, "Origin fetch failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read response body", http.StatusInternalServerError)
			return
		}

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

		if rfc9111.IsCacheable(resp) {
			cached := &rfc9111.CachedResponse{
				StatusCode: resp.StatusCode,
				Header:     resp.Header.Clone(),
				Body:       body,
				StoredAt:   time.Now(),
			}
			cacheStore.Set(key, cached)
		}
	})

	log.Printf("Listening on %s...", *listenAddr)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatal(err)
	}
}
