package extism

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient_redirectToAllowedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "final")
	}))
	defer srv.Close()

	resp, err := newHTTPClient([]string{"127.0.0.1"}).Get(srv.URL + "/start")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "final", string(body))
}

func TestHTTPClient_redirectToDisallowedHost(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		fmt.Fprint(w, "not allowed")
	}))
	defer other.Close()
	otherURL := fmt.Sprintf("http://localhost:%d/", other.Listener.Addr().(*net.TCPAddr).Port)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL, http.StatusFound)
	}))
	defer srv.Close()

	_, err := newHTTPClient([]string{"127.0.0.1"}).Get(srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not allowed")
	assert.Equal(t, int32(0), otherHits.Load())
}

func TestHTTPClient_redirectLimit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer srv.Close()

	_, err := newHTTPClient([]string{"127.0.0.1"}).Get(srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stopped after 10 redirects")
	assert.Equal(t, int32(10), hits.Load())
}

func TestHTTPClient_keepsDefaultClientSettings(t *testing.T) {
	old := *http.DefaultClient
	defer func() { *http.DefaultClient = old }()

	called := false
	http.DefaultClient.Timeout = 5 * time.Second
	http.DefaultClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		called = true
		return http.ErrUseLastResponse
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	client := newHTTPClient([]string{"127.0.0.1"})
	assert.Equal(t, 5*time.Second, client.Timeout)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	resp.Body.Close()
	assert.True(t, called)
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}
