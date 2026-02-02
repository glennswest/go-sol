package sol

import (
	"context"
	"encoding/binary"
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
		0xC0,           // Aux data byte 1: enable encryption/authentication based on session
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
	if len(resp) < 28 {
		return fmt.Errorf("activate payload response too short: %d", len(resp))
	}

	// Extract response data - skip headers, find completion code
	// Response includes: aux data (4), inbound payload size (2), outbound payload size (2), port (2)
	respData := resp[20:]
	if len(respData) < 12 {
		return fmt.Errorf("activate payload data too short")
	}

	// Check completion code (first byte after message header in response)
	cc := resp[19] // Completion code position varies
	if cc != 0x00 {
		return fmt.Errorf("activate payload failed: completion code 0x%02X", cc)
	}

	// Store max outbound payload size
	s.maxOutbound = binary.LittleEndian.Uint16(respData[4:6])
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

// readLoop reads SOL data from BMC
func (s *Session) readLoop() {
	defer close(s.readCh)

	buf := make([]byte, 1024)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := s.conn.Read(buf)
		if err != nil {
			// Timeout is normal, continue
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				continue
			}
			select {
			case s.errCh <- err:
			default:
			}
			return
		}

		if n < 20 {
			continue // Too short
		}

		// Check if this is a SOL packet
		// RMCP header (4) + Session header (12) + SOL header (4) + data
		payloadType := buf[5] & 0x3F // Mask out encrypted/authenticated bits
		if payloadType != solPayloadType {
			continue // Not SOL data
		}

		// Extract SOL data
		// Session header ends at offset 16, SOL header is 4 bytes
		if n < 20 {
			continue
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

		// Extract character data
		dataLen := n - 20
		if dataLen > 0 {
			data := make([]byte, dataLen)
			copy(data, buf[20:n])

			// Send ACK
			s.sendSolAck()

			select {
			case s.readCh <- data:
			default:
				// Channel full, drop data
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

	session := ipmiSessionHeader{
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
