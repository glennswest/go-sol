package sol

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"
)

// getChannelAuthCaps retrieves channel authentication capabilities
func (s *Session) getChannelAuthCaps(ctx context.Context) error {
	// Build Get Channel Authentication Capabilities request
	// Channel 0x0E = current channel, request IPMI v2.0
	data := []byte{0x8E, privAdmin} // Channel with IPMI v2.0 bit, requested privilege

	msg := buildIPMIMessage(0x20, netFnApp, 0, 0x81, 0, 0, cmdGetChannelAuthCaps, data)
	packet := buildRMCPPacket(ipmiAuthNone, payloadIPMI, 0, 0, msg)

	resp, err := s.sendRecv(ctx, packet, 5*time.Second)
	if err != nil {
		return err
	}

	// Parse response - we mainly care that it succeeds
	// Response contains auth types, OEM info, etc.
	if len(resp) < 20 {
		return fmt.Errorf("auth caps response too short")
	}

	// Check if RMCP+ is supported (byte offset depends on response format)
	// For now, assume success means RMCP+ is available
	return nil
}

// openSession sends RMCP+ Open Session Request
func (s *Session) openSession(ctx context.Context) error {
	// Generate random console session ID
	randBytes, err := generateRandomBytes(4)
	if err != nil {
		return err
	}
	s.sessionID = binary.LittleEndian.Uint32(randBytes)

	// Open Session Request payload
	// Message tag (1) + Requested max priv (1) + Reserved (2) + Console Session ID (4)
	// + Auth payload (8) + Integrity payload (8) + Confidentiality payload (8)
	payload := make([]byte, 32)
	payload[0] = 0 // Message tag
	payload[1] = privAdmin
	// payload[2:4] reserved
	binary.LittleEndian.PutUint32(payload[4:8], s.sessionID)

	// Authentication algorithm payload
	payload[8] = 0x00  // Payload type
	payload[9] = 0x00  // Reserved
	payload[10] = 0x00 // Reserved
	payload[11] = 0x08 // Payload length
	payload[12] = authRakpHmacSHA1 // Auth algorithm
	// payload[13:16] reserved

	// Integrity algorithm payload
	payload[16] = 0x01 // Payload type
	payload[17] = 0x00
	payload[18] = 0x00
	payload[19] = 0x08
	payload[20] = integrityHmacSHA1
	// payload[21:24] reserved

	// Confidentiality algorithm payload
	payload[24] = 0x02 // Payload type
	payload[25] = 0x00
	payload[26] = 0x00
	payload[27] = 0x08
	payload[28] = cryptoNone // No encryption for simplicity
	// payload[29:32] reserved

	packet := buildRMCPPacket(ipmiAuthRMCPP, payloadOpenReq, 0, 0, payload)

	resp, err := s.sendRecv(ctx, packet, 5*time.Second)
	if err != nil {
		return err
	}

	// Parse Open Session Response
	if len(resp) < 36 {
		return fmt.Errorf("open session response too short: %d", len(resp))
	}

	// Skip RMCP header (4) + IPMI session header (12)
	respData := resp[16:]

	// Check status code
	if len(respData) < 20 {
		return fmt.Errorf("open session response data too short")
	}

	statusCode := respData[1]
	if statusCode != 0 {
		return fmt.Errorf("open session failed with status: 0x%02X", statusCode)
	}

	// Extract BMC session ID
	s.remoteSessionID = binary.LittleEndian.Uint32(respData[4:8])
	s.authAlg = respData[12]
	s.integrityAlg = respData[20]
	s.cryptoAlg = respData[28]

	return nil
}

// rakpHandshake performs RAKP 1-4 authentication
func (s *Session) rakpHandshake(ctx context.Context) error {
	// Generate random number for console
	rmRand, err := generateRandomBytes(16)
	if err != nil {
		return err
	}

	// RAKP Message 1
	rakp1 := make([]byte, 28+len(s.username))
	rakp1[0] = 0 // Message tag
	// rakp1[1:4] reserved
	binary.LittleEndian.PutUint32(rakp1[4:8], s.remoteSessionID)
	copy(rakp1[8:24], rmRand) // Console random number
	rakp1[24] = privAdmin     // Requested role
	// rakp1[25:26] reserved
	rakp1[27] = uint8(len(s.username))
	copy(rakp1[28:], []byte(s.username))

	packet := buildRMCPPacket(ipmiAuthRMCPP, payloadRAKP1, 0, 0, rakp1)
	resp, err := s.sendRecv(ctx, packet, 5*time.Second)
	if err != nil {
		return fmt.Errorf("RAKP1 failed: %w", err)
	}

	// Parse RAKP Message 2
	if len(resp) < 40 {
		return fmt.Errorf("RAKP2 response too short")
	}
	respData := resp[16:] // Skip headers

	if respData[1] != 0 {
		return fmt.Errorf("RAKP2 status error: 0x%02X", respData[1])
	}

	mcRand := respData[8:24]          // BMC random number
	mcGUID := respData[24:40]         // BMC GUID
	_ = mcGUID                        // Not used currently

	// Generate session keys
	// For RAKP-HMAC-SHA1, Kg is password padded/truncated to 20 bytes
	kg := make([]byte, 20)
	copy(kg, []byte(s.password))

	s.sik = generateSIK(s.authAlg, kg, rmRand, mcRand, privAdmin, s.username)
	s.k1 = generateK1(s.authAlg, s.sik)
	s.k2 = generateK2(s.authAlg, s.sik)

	// RAKP Message 3
	// Calculate auth code for RAKP3
	authData := make([]byte, 22+len(s.username))
	copy(authData[0:16], mcRand)
	binary.LittleEndian.PutUint32(authData[16:20], s.sessionID)
	authData[20] = privAdmin
	authData[21] = uint8(len(s.username))
	copy(authData[22:], []byte(s.username))

	authCode := hmacHash(s.authAlg, kg, authData)

	rakp3 := make([]byte, 8+len(authCode))
	rakp3[0] = 0 // Message tag
	// rakp3[1:4] reserved
	binary.LittleEndian.PutUint32(rakp3[4:8], s.remoteSessionID)
	copy(rakp3[8:], authCode)

	packet = buildRMCPPacket(ipmiAuthRMCPP, payloadRAKP3, 0, 0, rakp3)
	resp, err = s.sendRecv(ctx, packet, 5*time.Second)
	if err != nil {
		return fmt.Errorf("RAKP3 failed: %w", err)
	}

	// Parse RAKP Message 4
	if len(resp) < 24 {
		return fmt.Errorf("RAKP4 response too short")
	}
	respData = resp[16:]

	if respData[1] != 0 {
		return fmt.Errorf("RAKP4 status error: 0x%02X", respData[1])
	}

	// Authentication complete
	return nil
}

// closeSession closes the RMCP+ session
func (s *Session) closeSession(ctx context.Context) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, s.remoteSessionID)

	msg := buildIPMIMessage(0x20, netFnApp, 0, 0x81, 0, 0, cmdCloseSession, data)
	packet := s.buildAuthenticatedPacket(payloadIPMI, msg)

	_, err := s.sendRecv(ctx, packet, 2*time.Second)
	return err
}

// buildAuthenticatedPacket builds a packet with integrity
func (s *Session) buildAuthenticatedPacket(payloadType uint8, payload []byte) []byte {
	// For unauthenticated/unencrypted, just wrap normally
	if s.integrityAlg == integrityNone {
		return buildRMCPPacket(ipmiAuthRMCPP, payloadType, s.remoteSessionID, 0, payload)
	}

	// With integrity: add AuthCode trailer
	// Payload type has authenticated bit set (0x40)
	packet := buildRMCPPacket(ipmiAuthRMCPP, payloadType|0x40, s.remoteSessionID, 0, payload)

	// Add pad and AuthCode
	padLen := (4 - (len(payload) % 4)) % 4
	for i := 0; i < padLen; i++ {
		packet = append(packet, 0xFF)
	}
	packet = append(packet, uint8(padLen))  // Pad length
	packet = append(packet, 0x07)           // Next header (always 0x07)

	// Calculate AuthCode over packet starting from AuthType
	authCode := hmacHash(s.integrityAlg, s.k1, packet[4:])
	packet = append(packet, authCode[:12]...) // Use first 12 bytes

	return packet
}

// sendRecv sends a packet and waits for response
func (s *Session) sendRecv(ctx context.Context, packet []byte, timeout time.Duration) ([]byte, error) {
	if err := s.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if _, err := s.conn.Write(packet); err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	resp := make([]byte, 1024)
	n, err := s.conn.Read(resp)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	return resp[:n], nil
}
