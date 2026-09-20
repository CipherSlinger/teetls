package teetls

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// listener wraps a net.Listener and produces secure *Conn connections upon Accept().
type listener struct {
	net.Listener
	cfg *Config
}

// Accept waits for and returns the next connection to the listener, wrapped as a *Conn.
func (l *listener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewServerConn(rawConn, l.cfg), nil
}

// Listen creates a TCP listener securing connections with TEE-TLS 1.3.
func Listen(network, addr string, cfg *Config) (net.Listener, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("teetls: invalid listen config: %w", err)
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("teetls: listen: %w", err)
	}

	return &listener{
		Listener: l,
		cfg:      cfg,
	}, nil
}

// Dial establishes a TEE-TLS 1.3 connection to addr and performs the handshake.
func Dial(network, addr string, cfg *Config) (*Conn, error) {
	return DialContext(context.Background(), network, addr, cfg)
}

// DialContext connects to the address on the named network using the provided context and performs handshake.
func DialContext(ctx context.Context, network, addr string, cfg *Config) (*Conn, error) {
	if cfg == nil {
		cfg = &Config{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("teetls: invalid dial config: %w", err)
	}
	if cfg.Mode == ModeStrict && !cfg.InsecureSkipAttestationVerify && len(cfg.ExpectedMeasurements) == 0 {
		return nil, fmt.Errorf("teetls: client dialing in strict mode requires ExpectedMeasurements")
	}

	var d net.Dialer
	if cfg.Timeout > 0 {
		d.Timeout = cfg.Timeout
	}

	rawConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("teetls: dial %s: %w", addr, err)
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if cfg.Timeout > 0 {
		timeoutDeadline := time.Now().Add(cfg.Timeout)
		if deadline.IsZero() || timeoutDeadline.Before(deadline) {
			deadline = timeoutDeadline
		}
	}
	if !deadline.IsZero() {
		_ = rawConn.SetDeadline(deadline)
	}

	ctxDone := make(chan struct{})
	defer close(ctxDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.SetDeadline(time.Now())
		case <-ctxDone:
		}
	}()

	conn := NewClientConn(rawConn, cfg)
	if err := conn.Handshake(); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, fmt.Errorf("teetls: dial %s: %w", addr, ctx.Err())
		}
		return nil, fmt.Errorf("teetls: handshake failed: %w", err)
	}

	_ = rawConn.SetDeadline(time.Time{})
	return conn, nil
}

// NewHTTPTransport creates an http.Transport configured to use TEE-TLS 1.3 for TLS connections.
func NewHTTPTransport(cfg *Config) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialContext(ctx, network, addr, cfg)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewHTTPClient creates an http.Client equipped with TEE-TLS 1.3 Transport and configured timeout.
func NewHTTPClient(cfg *Config) *http.Client {
	timeout := 10 * time.Second
	if cfg != nil && cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	return &http.Client{
		Transport: NewHTTPTransport(cfg),
		Timeout:   timeout,
	}
}
