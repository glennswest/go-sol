package sol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
)

// RMCP constants
const (
	rmcpVersion    = 0x06
	rmcpSequence   = 0xFF // No RMCP ACK
	rmcpClassIPMI  = 0x07
	rmcpClassASF   = 0x06

	// IPMI message types
	ipmiAuthNone    = 0x00
	ipmiAuthRMCPP   = 0x06

	// Payload types
	payloadIPMI      = 0x00
	payloadSOL       = 0x01
	payloadOpenReq   = 0x10
	payloadOpenResp  = 0x11
	payloadRAKP1     = 0x12
	payloadRAKP2     = 0x13
	payloadRAKP3     = 0x14
	payloadRAKP4     = 0x15

	// Authentication algorithms
	authRakpNone     = 0x00
	authRakpHmacSHA1 = 0x01
	authRakpHmacMD5  = 0x02
	authRakpHmacSHA256 = 0x03

	// Integrity algorithms
	integrityNone       = 0x00
	integrityHmacSHA1   = 0x01
	integrityHmacMD5    = 0x02
	integrityMD5        = 0x03
	integrityHmacSHA256 = 0x04

	// Confidentiality algorithms
	cryptoNone     = 0x00
	cryptoAesCBC   = 0x01

	// Network functions
	netFnChassis   = 0x00
	netFnApp       = 0x06
	netFnTransport = 0x0C

	// Commands
	cmdGetChannelAuthCaps  = 0x38
	cmdGetSessionChallenge = 0x39
	cmdActivateSession     = 0x3A
	cmdSetSessionPriv      = 0x3B
	cmdCloseSession        = 0x3C
	cmdActivatePayload     = 0x48
	cmdDeactivatePayload   = 0x49
	cmdGetPayloadStatus    = 0x4A

	// Privilege levels
	privCallback  = 0x01
	privUser      = 0x02
	privOperator  = 0x03
	privAdmin     = 0x04
)

// rmcpHeader is the RMCP header (4 bytes)
type rmcpHeader struct {
	Version  uint8
	Reserved uint8
	Sequence uint8
	Class    uint8
}

func (h rmcpHeader) pack() []byte {
	return []byte{h.Version, h.Reserved, h.Sequence, h.Class}
}

// ipmiSessionHeader is the IPMI session header for RMCP+
type ipmiSessionHeader struct {
	AuthType    uint8
	PayloadType uint8 // Includes encrypted/authenticated bits
	SessionID   uint32
	Sequence    uint32
	PayloadLen  uint16
}

func (h ipmiSessionHeader) pack() []byte {
	buf := make([]byte, 12)
	buf[0] = h.AuthType
	buf[1] = h.PayloadType
	binary.LittleEndian.PutUint32(buf[2:6], h.SessionID)
	binary.LittleEndian.PutUint32(buf[6:10], h.Sequence)
	binary.LittleEndian.PutUint16(buf[10:12], h.PayloadLen)
	return buf
}

// buildRMCPPacket builds a complete RMCP+ packet
func buildRMCPPacket(authType uint8, payloadType uint8, sessionID uint32, sequence uint32, payload []byte) []byte {
	rmcp := rmcpHeader{
		Version:  rmcpVersion,
		Reserved: 0,
		Sequence: rmcpSequence,
		Class:    rmcpClassIPMI,
	}

	session := ipmiSessionHeader{
		AuthType:    authType,
		PayloadType: payloadType,
		SessionID:   sessionID,
		Sequence:    sequence,
		PayloadLen:  uint16(len(payload)),
	}

	packet := make([]byte, 0, 4+12+len(payload))
	packet = append(packet, rmcp.pack()...)
	packet = append(packet, session.pack()...)
	packet = append(packet, payload...)
	return packet
}

// buildIPMIMessage builds an IPMI message payload
func buildIPMIMessage(rsAddr, netFn, rsLUN, rqAddr, rqSeq, rqLUN, cmd uint8, data []byte) []byte {
	msg := make([]byte, 0, 7+len(data))
	msg = append(msg, rsAddr)
	msg = append(msg, (netFn<<2)|rsLUN)

	// Checksum 1: rsAddr + netFn/LUN
	chk1 := uint8(0) - rsAddr - ((netFn << 2) | rsLUN)
	msg = append(msg, chk1)

	msg = append(msg, rqAddr)
	msg = append(msg, (rqSeq<<2)|rqLUN)
	msg = append(msg, cmd)
	msg = append(msg, data...)

	// Checksum 2: sum from rqAddr to end
	chk2 := uint8(0)
	for i := 3; i < len(msg); i++ {
		chk2 -= msg[i]
	}
	msg = append(msg, chk2)

	return msg
}

// generateRandomBytes generates n random bytes
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// hmacHash computes HMAC with the specified algorithm
func hmacHash(alg uint8, key, data []byte) []byte {
	var h func() hash.Hash
	switch alg {
	case authRakpHmacSHA1: // Same value as integrityHmacSHA1 (0x01)
		h = sha1.New
	case authRakpHmacSHA256: // Same value as integrityHmacSHA256 (0x04 for integrity)
		h = sha256.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// generateSIK generates the Session Integrity Key
func generateSIK(authAlg uint8, kg, rmRand, mcRand []byte, rolePriv uint8, username string) []byte {
	// SIK = HMAC_kg(Rm || Rc || Role || ULength || <username>)
	data := make([]byte, 0, 32+32+2+len(username))
	data = append(data, rmRand...)
	data = append(data, mcRand...)
	data = append(data, rolePriv)
	data = append(data, uint8(len(username)))
	data = append(data, []byte(username)...)
	return hmacHash(authAlg, kg, data)
}

// generateK1 generates K1 integrity key from SIK
func generateK1(authAlg uint8, sik []byte) []byte {
	const1 := make([]byte, 20)
	for i := range const1 {
		const1[i] = 0x01
	}
	return hmacHash(authAlg, sik, const1)
}

// generateK2 generates K2 encryption key from SIK
func generateK2(authAlg uint8, sik []byte) []byte {
	const2 := make([]byte, 20)
	for i := range const2 {
		const2[i] = 0x02
	}
	return hmacHash(authAlg, sik, const2)
}

// parseIPMIResponse parses an IPMI response
func parseIPMIResponse(data []byte) (completionCode uint8, responseData []byte, err error) {
	if len(data) < 8 {
		return 0, nil, fmt.Errorf("response too short: %d bytes", len(data))
	}
	// Skip RMCP header (4) + session header (12 or variable)
	// Find the completion code
	completionCode = data[len(data)-2] // Second to last byte before checksum
	if len(data) > 8 {
		responseData = data[7 : len(data)-1]
	}
	return completionCode, responseData, nil
}
