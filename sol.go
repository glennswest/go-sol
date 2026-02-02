// Package sol implements IPMI Serial Over LAN (SOL) in pure Go.
// This provides a bidirectional console connection to server BMCs
// without requiring ipmitool or PTY allocation.
package sol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Session represents an active SOL connection to a BMC.
type Session struct {
	conn     net.Conn
	host     string
	port     int
	username string
	password string

	// RMCP+ session state
	sessionID       uint32
	remoteSessionID uint32
	sessionSeq      uint32 // Session sequence number
	authAlg         uint8
	integrityAlg    uint8
	cryptoAlg       uint8
	sik             []byte // Session Integrity Key
	k1              []byte // Integrity key
	k2              []byte // Encryption key

	// SOL state
	solPayloadInstance uint8
	solSeqNum          uint8
	ackSeqNum          uint8
	maxOutbound        uint16

	// Data channels
	readCh  chan []byte
	writeCh chan []byte
	errCh   chan error
	done    chan struct{}

	mu     sync.Mutex
	closed bool
}

// Config holds SOL connection configuration.
type Config struct {
	Host     string
	Port     int // Default: 623
	Username string
	Password string
	Timeout  time.Duration // Default: 30s
}

// New creates a new SOL session (not yet connected).
func New(cfg Config) *Session {
	if cfg.Port == 0 {
		cfg.Port = 623
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Session{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		readCh:   make(chan []byte, 1000),
		writeCh:  make(chan []byte, 100),
		errCh:    make(chan error, 1),
		done:     make(chan struct{}),
	}
}

// Connect establishes the RMCP+ session and activates SOL.
func (s *Session) Connect(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)

	conn, err := net.DialTimeout("udp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	s.conn = conn

	// Step 1: Get Channel Authentication Capabilities
	if err := s.getChannelAuthCaps(ctx); err != nil {
		s.conn.Close()
		return fmt.Errorf("get auth caps: %w", err)
	}

	// Step 2: Open RMCP+ Session
	if err := s.openSession(ctx); err != nil {
		s.conn.Close()
		return fmt.Errorf("open session: %w", err)
	}

	// Step 3: RAKP handshake (authentication)
	if err := s.rakpHandshake(ctx); err != nil {
		s.conn.Close()
		return fmt.Errorf("RAKP handshake: %w", err)
	}

	// Step 4: Deactivate any existing SOL session
	s.deactivateSOL(ctx) // Ignore errors

	// Step 5: Activate SOL payload
	if err := s.activateSOL(ctx); err != nil {
		s.conn.Close()
		return fmt.Errorf("activate SOL: %w", err)
	}

	// Start read/write loops
	go s.readLoop()
	go s.writeLoop()

	return nil
}

// Read returns a channel that receives console output data.
func (s *Session) Read() <-chan []byte {
	return s.readCh
}

// Write sends data to the console.
func (s *Session) Write(data []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("session closed")
	}
	s.mu.Unlock()

	select {
	case s.writeCh <- data:
		return nil
	case <-s.done:
		return errors.New("session closed")
	}
}

// Close terminates the SOL session.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	close(s.done)

	// Deactivate SOL payload
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.deactivateSOL(ctx)

	// Close session
	s.closeSession(ctx)

	return s.conn.Close()
}

// Err returns any error that caused the session to fail.
func (s *Session) Err() <-chan error {
	return s.errCh
}
