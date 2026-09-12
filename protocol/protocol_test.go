package protocol

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// ============================================================
// Pack / Unpack 往返
// ============================================================

func TestPackUnpackRoundTrip(t *testing.T) {

	payload := []byte("hello vpn")

	data := Pack(
		TypeIP,
		10001,
		42,
		payload,
	)

	if len(data) != HeaderSize+len(payload) {
		t.Fatalf(
			"unexpected packet length: %d",
			len(data),
		)
	}

	header, gotPayload, err := Unpack(data)
	if err != nil {
		t.Fatalf("unpack failed: %v", err)
	}

	if header.Version != Version {
		t.Fatalf(
			"unexpected version: %d",
			header.Version,
		)
	}

	if header.Type != TypeIP {
		t.Fatalf(
			"unexpected type: %d",
			header.Type,
		)
	}

	if header.Length != uint16(len(payload)) {
		t.Fatalf(
			"unexpected length: %d",
			header.Length,
		)
	}

	if header.SessionID != 10001 {
		t.Fatalf(
			"unexpected session id: %d",
			header.SessionID,
		)
	}

	if header.Sequence != 42 {
		t.Fatalf(
			"unexpected sequence: %d",
			header.Sequence,
		)
	}

	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf(
			"payload mismatch: %q != %q",
			gotPayload,
			payload,
		)
	}
}

func TestPackUnpackEmptyPayload(t *testing.T) {

	data := Pack(
		TypeGatewayAuthOK,
		0,
		0,
		nil,
	)

	header, payload, err := Unpack(data)
	if err != nil {
		t.Fatalf("unpack failed: %v", err)
	}

	if header.Type != TypeGatewayAuthOK {
		t.Fatalf(
			"unexpected type: %d",
			header.Type,
		)
	}

	if len(payload) != 0 {
		t.Fatalf(
			"unexpected payload length: %d",
			len(payload),
		)
	}
}

func TestHeaderBigEndian(t *testing.T) {

	data := Pack(
		TypeAuth,
		0x01020304,
		0x05060708,
		[]byte("ab"),
	)

	if string(data[0:4]) != Magic {
		t.Fatalf(
			"unexpected magic: %q",
			string(data[0:4]),
		)
	}

	if binary.BigEndian.Uint16(data[6:8]) != 2 {
		t.Fatal("length is not big endian")
	}

	if binary.BigEndian.Uint32(data[8:12]) != 0x01020304 {
		t.Fatal("session id is not big endian")
	}

	if binary.BigEndian.Uint32(data[12:16]) != 0x05060708 {
		t.Fatal("sequence is not big endian")
	}
}

// ============================================================
// Unpack 校验错误
// ============================================================

func TestUnpackTooShort(t *testing.T) {

	_, _, err := Unpack(
		make([]byte, HeaderSize-1),
	)
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestUnpackInvalidMagic(t *testing.T) {

	data := Pack(
		TypeAuth,
		0,
		0,
		[]byte("x"),
	)

	copy(
		data[0:4],
		"XXXX",
	)

	_, _, err := Unpack(data)
	if err == nil {
		t.Fatal("expected error for invalid magic")
	}
}

func TestUnpackInvalidVersion(t *testing.T) {

	data := Pack(
		TypeAuth,
		0,
		0,
		[]byte("x"),
	)

	data[4] = 2

	_, _, err := Unpack(data)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestUnpackTruncatedPayload(t *testing.T) {

	data := Pack(
		TypeIP,
		0,
		0,
		[]byte("0123456789"),
	)

	// 截掉部分 payload，但保留 Length 字段
	truncated := data[:HeaderSize+4]

	_, _, err := Unpack(truncated)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// ============================================================
// Gateway Auth JSON
// ============================================================

func TestGatewayAuthRoundTrip(t *testing.T) {

	auth := &GatewayAuth{
		GatewayID: "company-a",
		Token:     "123456",
		Networks: []string{
			"192.168.0.0/24",
			"192.168.10.0/24",
		},
	}

	data, err := MarshalGatewayAuth(auth)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	got, err := UnmarshalGatewayAuth(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !reflect.DeepEqual(auth, got) {
		t.Fatalf(
			"gateway auth mismatch: %+v != %+v",
			auth,
			got,
		)
	}
}

func TestGatewayAuthFieldNames(t *testing.T) {

	raw := []byte(
		`{"gateway_id":"company-a","token":"123456","networks":["192.168.0.0/24"]}`,
	)

	auth, err := UnmarshalGatewayAuth(raw)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if auth.GatewayID != "company-a" {
		t.Fatalf(
			"unexpected gateway id: %s",
			auth.GatewayID,
		)
	}

	if auth.Token != "123456" {
		t.Fatalf(
			"unexpected token: %s",
			auth.Token,
		)
	}

	if len(auth.Networks) != 1 ||
		auth.Networks[0] != "192.168.0.0/24" {

		t.Fatalf(
			"unexpected networks: %v",
			auth.Networks,
		)
	}
}

func TestUnmarshalGatewayAuthInvalid(t *testing.T) {

	_, err := UnmarshalGatewayAuth(
		[]byte("not json"),
	)
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}
