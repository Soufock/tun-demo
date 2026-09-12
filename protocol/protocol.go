package protocol

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const (
	Magic      = "VTUN"
	Version    = 1
	HeaderSize = 16
	MaxPacket  = 65535

	// Packet Type
	TypeAuth     = 1
	TypeAuthOK   = 2
	TypeAuthFail = 3

	TypeGatewayAuth     = 4
	TypeGatewayAuthOK   = 5
	TypeGatewayAuthFail = 6

	TypeIP = 7

	// 心跳第一阶段只定义常量，第二阶段实现
	TypeHeartbeat   = 8
	TypeHeartbeatOK = 9
)

// ============================================================
// Header
//
// 0       4   5   6       8       12      16
// +-------+---+---+-------+-------+-------+
// | Magic | V | T | Len   | Sess  | Seq   |
// +-------+---+---+-------+-------+-------+
// |              Payload                |
// +-------------------------------------+
//
// 全部字段使用大端序
// ============================================================

type Header struct {
	Version   uint8
	Type      uint8
	Length    uint16
	SessionID uint32
	Sequence  uint32
}

// ============================================================
// Pack
// ============================================================

func Pack(
	packetType uint8,
	sessionID uint32,
	sequence uint32,
	payload []byte,
) []byte {

	if len(payload) > MaxPacket {
		panic("payload too large")
	}

	data := make(
		[]byte,
		HeaderSize+len(payload),
	)

	// Magic
	copy(
		data[0:4],
		Magic,
	)

	// Version
	data[4] = Version

	// Type
	data[5] = packetType

	// Payload length
	binary.BigEndian.PutUint16(
		data[6:8],
		uint16(len(payload)),
	)

	// SessionID
	binary.BigEndian.PutUint32(
		data[8:12],
		sessionID,
	)

	// Sequence
	binary.BigEndian.PutUint32(
		data[12:16],
		sequence,
	)

	// Payload
	copy(
		data[HeaderSize:],
		payload,
	)

	return data
}

// ============================================================
// Unpack
// ============================================================

func Unpack(
	data []byte,
) (
	*Header,
	[]byte,
	error,
) {

	if len(data) < HeaderSize {
		return nil, nil, fmt.Errorf(
			"packet too short: %d",
			len(data),
		)
	}

	// ============================================================
	// Magic
	// ============================================================

	if string(data[0:4]) != Magic {
		return nil, nil, fmt.Errorf(
			"invalid magic: %q",
			string(data[0:4]),
		)
	}

	// ============================================================
	// Version
	// ============================================================

	if data[4] != Version {
		return nil, nil, fmt.Errorf(
			"invalid version: %d",
			data[4],
		)
	}

	// ============================================================
	// Header
	// ============================================================

	header := &Header{
		Version: data[4],
		Type:    data[5],

		Length: binary.BigEndian.Uint16(
			data[6:8],
		),

		SessionID: binary.BigEndian.Uint32(
			data[8:12],
		),

		Sequence: binary.BigEndian.Uint32(
			data[12:16],
		),
	}

	// ============================================================
	// Payload length
	// ============================================================

	payloadLen := int(
		header.Length,
	)

	if HeaderSize+payloadLen > len(data) {
		return nil, nil, fmt.Errorf(
			"invalid packet length: header=%d payload=%d udp=%d",
			HeaderSize,
			payloadLen,
			len(data),
		)
	}

	// ============================================================
	// Payload
	// ============================================================

	payload := data[HeaderSize : HeaderSize+payloadLen]

	return header, payload, nil
}

// ============================================================
// Gateway 注册
//
// GATEWAY_AUTH payload 使用 JSON：
//
// {
//   "gateway_id": "company-a",
//   "token": "123456",
//   "networks": ["192.168.0.0/24"]
// }
// ============================================================

type GatewayAuth struct {
	GatewayID string   `json:"gateway_id"`
	Token     string   `json:"token"`
	Networks  []string `json:"networks"`
}

func MarshalGatewayAuth(
	auth *GatewayAuth,
) ([]byte, error) {

	return json.Marshal(auth)
}

func UnmarshalGatewayAuth(
	data []byte,
) (*GatewayAuth, error) {

	auth := &GatewayAuth{}

	if err := json.Unmarshal(data, auth); err != nil {
		return nil, fmt.Errorf(
			"invalid gateway auth payload: %w",
			err,
		)
	}

	return auth, nil
}
