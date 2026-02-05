package sol

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// SOL payload constants
const (
	solPayloadType = 0x01

	// SOL operation/status bits (outbound)
	solOpNack          = 0x40 // Request packet retransmission
	solOpRingWor       = 0x20 // Ring indicator / Wake on Ring
	solOpBreak         = 0x10 // Generate serial break
	solOpCtsDeassert   = 0x08 // Deassert CTS
	solOpDropDcdDsr    = 0x04 // Drop DCD/DSR
	solOpFlushInbound  = 0x02 // Flush inbound data
	solOpFlushOutbound = 0x01 // Flush outbound data

	// SOL status bits (inbound from BMC)
	solStatusNack       = 0x40
	solStatusTransfer   = 0x20 // Character transfer unavailable
	solStatusBreak      = 0x10 // Break detected
	solStatusRxOverrun  = 0x08 // Receive overrun
	solStatusDeassert   = 0x04 // CTS/DCD/DSR deasserted
	solStatusFlushOut   = 0x02
	solStatusFlushIn    = 0x01
)

// solPacketHeader is the 4-byte SOL packet header
type solPacketHeader struct {
	PacketSeq    uint8 // Packet sequence number
	AckSeq       uint8 // Acknowledged packet number
	AcceptedChar uint8 // Number of accepted characters
	OpStatus     uint8 // Operation/status byte
}

func (h solPacketHeader) pack() []byte {
	return []byte{h.PacketSeq, h.AckSeq, h.AcceptedChar, h.OpStatus}
}

func parseSolHeader(data []byte) solPacketHeader {
	if len(data) < 4 {
		return solPacketHeader{}
	}
	return solPacketHeader{
		PacketSeq:    data[0],
		AckSeq:       data[1],
		AcceptedChar: data[2],
		OpStatus:     data[3],
	}
}

// activateSOL activates the SOL payload
func (s *Session) activateSOL(ctx context.Context) error {
	// Activate Payload request
	// Payload type (1) + Payload instance (1) + Aux data (4)
	data := []byte{
		solPayloadType, // Payload type = SOL
		0x01,           // Payload instance = 1
		0x00,           // Aux data byte 1: no special options
		0x00,           // Aux data byte 2
		0x00,           // Aux data byte 3
		0x00,           // Aux data byte 4
	}

	msg := buildIPMIMessage(0x20, netFnApp, 0, 0x81, 0, 0, cmdActivatePayload, data)
	packet := s.buildAuthenticatedPacket(payloadIPMI, msg)

	resp, err := s.sendRecv(ctx, packet, 5*time.Second)
	if err != nil {
		return err
	}

	// Parse Activate Payload response
	// RMCP(4) + Session(12) + IPMI header (6) + completion code (1) + data
	if len(resp) < 30 {
		return fmt.Errorf("activate payload response too short: %d", len(resp))
	}

	// Completion code is at offset 22: RMCP(4) + Session(12) + rsAddr(1) + netFn(1) + chk(1) + rqAddr(1) + rqSeq(1) + cmd(1) = 22
	cc := resp[22]
	if cc != 0x00 {
		return fmt.Errorf("activate payload failed: completion code 0x%02X", cc)
	}

	// Response data starts after completion code (offset 23)
	// aux data (4), inbound payload size (2), outbound payload size (2), port (2)
	respData := resp[23:]

	// Store max outbound payload size (at offset 6 in response data)
	if len(respData) >= 8 {
		s.maxOutbound = binary.LittleEndian.Uint16(respData[6:8])
	}
	if s.maxOutbound == 0 || s.maxOutbound > 255 {
		s.maxOutbound = 200 // Default safe value
	}

	s.solPayloadInstance = 0x01
	s.solSeqNum = 1 // Start sequence at 1

	return nil
}

// deactivateSOL deactivates the SOL payload
func (s *Session) deactivateSOL(ctx context.Context) error {
	data := []byte{
		solPayloadType,       // Payload type = SOL
		s.solPayloadInstance, // Payload instance
		0x00, 0x00, 0x00, 0x00, // Aux data
	}

	msg := buildIPMIMessage(0x20, netFnApp, 0, 0x81, 0, 0, cmdDeactivatePayload, data)
	packet := s.buildAuthenticatedPacket(payloadIPMI, msg)

	_, err := s.sendRecv(ctx, packet, 2*time.Second)
	return err
}

// readLoop reads SOL data from BMC as fast as possible
func (s *Session) readLoop() {
	defer close(s.readCh)

	// Internal queue for bursty traffic - read fast, drain separately
	queue := make(chan []byte, 10000)
	done := make(chan struct{})

	// Goroutine to drain queue to readCh
	go func() {
		defer close(done)
		for data := range queue {
			select {
			case s.readCh <- data:
			case <-s.done:
				return
			}
		}
	}()

	buf := make([]byte, 1024)
	logInterval := time.NewTicker(60 * time.Second)
	defer logInterval.Stop()
	var totalReads, totalTimeouts, totalPackets, totalSOL, totalData int64

	s.logf("readLoop started for %s:%d", s.host, s.port)

	for {
		select {
		case <-s.done:
			close(queue)
			<-done
			return
		case <-logInterval.C:
			s.logf("readLoop stats for %s: reads=%d timeouts=%d packets=%d sol=%d data=%d",
				s.host, totalReads, totalTimeouts, totalPackets, totalSOL, totalData)
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := s.conn.Read(buf)
		totalReads++
		if err != nil {
			// Timeout is normal - check inactivity
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				totalTimeouts++
				if s.inactivityTimeout > 0 {
					last := time.Unix(0, s.lastRecvTime.Load())
					if time.Since(last) > s.inactivityTimeout {
						s.logf("readLoop inactivity timeout for %s (last recv %v ago)", s.host, time.Since(last))
						select {
						case s.errCh <- errors.New("SOL inactivity timeout"):
						default:
						}
						close(queue)
						<-done
						return
					}
				}
				continue
			}
			s.logf("readLoop error for %s: %v", s.host, err)
			select {
			case s.errCh <- err:
			default:
			}
			close(queue)
			<-done
			return
		}

		totalPackets++

		if n < 20 {
			continue // Too short for SOL, but BMC responded
		}

		// Check if this is a SOL packet
		// RMCP header (4) + Session header (12) + SOL header (4) + data
		payloadType := buf[5] & 0x3F // Mask out encrypted/authenticated bits
		if payloadType != solPayloadType {
			continue // Not SOL data
		}
		totalSOL++
		// SOL packet received - session is alive
		s.lastRecvTime.Store(time.Now().UnixNano())

		// Get payload length from session header (offset 14-15, little endian)
		payloadLen := int(binary.LittleEndian.Uint16(buf[14:16]))
		if payloadLen < 4 || 16+payloadLen > n {
			continue // Invalid payload length
		}

		header := parseSolHeader(buf[16:20])

		// Check for NACK - need to retransmit
		if header.OpStatus&solStatusNack != 0 {
			// Retransmission requested - handle in write loop
			continue
		}

		// Update our ACK sequence
		s.mu.Lock()
		s.ackSeqNum = header.PacketSeq
		s.mu.Unlock()

		// Extract character data (payload minus 4-byte SOL header)
		dataLen := payloadLen - 4
		if dataLen > 0 {
			totalData++
			data := make([]byte, dataLen)
			copy(data, buf[20:20+dataLen])

			// Send ACK immediately
			s.sendSolAck()

			// Queue data - never block the read loop
			select {
			case queue <- data:
			default:
			}
		} else if header.PacketSeq != 0 {
			// ACK-only packet from BMC, send our ACK
			s.sendSolAck()
		}
	}
}

// writeLoop sends SOL data to BMC
func (s *Session) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case data := <-s.writeCh:
			s.sendSolData(data)
		}
	}
}

// sendSolData sends character data to BMC
func (s *Session) sendSolData(data []byte) error {
	s.mu.Lock()
	seqNum := s.solSeqNum
	s.solSeqNum++
	if s.solSeqNum == 0 {
		s.solSeqNum = 1 // Sequence 0 means no packet
	}
	ackSeq := s.ackSeqNum
	s.mu.Unlock()

	// Build SOL packet
	header := solPacketHeader{
		PacketSeq:    seqNum,
		AckSeq:       ackSeq,
		AcceptedChar: 0,
		OpStatus:     0,
	}

	// Chunk data if too large
	maxData := int(s.maxOutbound) - 4 // Subtract header size
	if maxData < 1 {
		maxData = 200
	}

	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxData {
			chunk = data[:maxData]
			data = data[maxData:]
		} else {
			data = nil
		}

		payload := make([]byte, 4+len(chunk))
		copy(payload[0:4], header.pack())
		copy(payload[4:], chunk)

		packet := s.buildSolPacket(payload)

		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := s.conn.Write(packet); err != nil {
			return err
		}

		// Increment sequence for next chunk
		header.PacketSeq++
		if header.PacketSeq == 0 {
			header.PacketSeq = 1
		}
	}

	return nil
}

// sendSolAck sends an ACK-only packet
func (s *Session) sendSolAck() error {
	s.mu.Lock()
	ackSeq := s.ackSeqNum
	s.mu.Unlock()

	header := solPacketHeader{
		PacketSeq:    0, // 0 = ACK only, no data
		AckSeq:       ackSeq,
		AcceptedChar: 0xFF, // Accept all
		OpStatus:     0,
	}

	payload := header.pack()
	packet := s.buildSolPacket(payload)

	s.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err := s.conn.Write(packet)
	return err
}

// keepaliveLoop periodically sends ASF Presence Pings to detect dead BMCs.
// The BMC responds with a Presence Pong, which readLoop picks up to update lastRecvTime.
func (s *Session) keepaliveLoop() {
	interval := s.inactivityTimeout / 3
	if interval < 10*time.Second {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sendPresencePing()
		}
	}
}

// sendPresencePing sends an ASF Presence Ping (RMCP ping).
// This is a lightweight, unauthenticated packet that any IPMI BMC will respond to.
func (s *Session) sendPresencePing() {
	ping := []byte{
		0x06, 0x00, 0xFF, 0x06, // RMCP header: version=6, reserved=0, seq=0xFF, class=ASF
		0x00, 0x00, 0x11, 0xBE, // IANA Enterprise Number (ASF-RMCP)
		0x80,                   // Message Type: Presence Ping
		0x00,                   // Message Tag
		0x00,                   // Reserved
		0x00,                   // Data Length
	}
	s.conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	s.conn.Write(ping)
}

// buildSolPacket builds a complete SOL packet
func (s *Session) buildSolPacket(payload []byte) []byte {
	// SOL uses payload type 1
	payloadType := uint8(solPayloadType)

	// Add authenticated bit if we have integrity
	if s.integrityAlg != integrityNone {
		payloadType |= 0x40
	}

	// Build RMCP + session header
	rmcp := rmcpHeader{
		Version:  rmcpVersion,
		Reserved: 0,
		Sequence: rmcpSequence,
		Class:    rmcpClassIPMI,
	}

	session := ipmi20SessionHeader{
		AuthType:    ipmiAuthRMCPP,
		PayloadType: payloadType,
		SessionID:   s.remoteSessionID,
		Sequence:    0, // SOL doesn't use session sequence
		PayloadLen:  uint16(len(payload)),
	}

	packet := make([]byte, 0, 4+12+len(payload)+16)
	packet = append(packet, rmcp.pack()...)
	packet = append(packet, session.pack()...)
	packet = append(packet, payload...)

	// Add integrity if needed
	if s.integrityAlg != integrityNone {
		padLen := (4 - (len(payload) % 4)) % 4
		for i := 0; i < padLen; i++ {
			packet = append(packet, 0xFF)
		}
		packet = append(packet, uint8(padLen))
		packet = append(packet, 0x07)

		authCode := hmacHash(s.integrityAlg, s.k1, packet[4:])
		packet = append(packet, authCode[:12]...)
	}

	return packet
}
