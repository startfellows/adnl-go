package adnl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

type Params [160]byte

func NewParameters() (Params, error) {
	var p Params
	_, err := io.ReadFull(rand.Reader, p[:])
	return p, err
}

func (p Params) RxKey() []byte {
	return p[0:32]
}

func (p Params) TxKey() []byte {
	return p[32:64]
}

func (p Params) RxNonce() []byte {
	return p[64:80]
}

func (p Params) TxNonce() []byte {
	return p[80:96]
}

func (p Params) Padding() []byte {
	return p[96:160]
}

func (p Params) Hash() []byte {
	h := sha256.New()
	h.Write(p[:])
	return h.Sum(nil)
}

type Packet struct {
	payload []byte
	nonce   [32]byte
}

func NewPacket(payload []byte) (Packet, error) {
	packet := Packet{payload: payload}
	_, err := io.ReadFull(rand.Reader, packet.nonce[:])
	return packet, err
}

func (p Packet) Hash() []byte {
	h := sha256.New()
	h.Write(p.nonce[:])
	h.Write(p.payload)
	return h.Sum(nil)
}

func (p Packet) Size() []byte {
	s := make([]byte, 4)
	binary.LittleEndian.PutUint32(s[:], uint32(len(p.payload)+32+32))
	return s
}
func (p Packet) Marshal() []byte {
	b := make([]byte, 4+32+len(p.payload)+32)
	copy(b[:4], p.Size())
	copy(b[4:36], p.nonce[:])
	copy(b[36:36+len(p.payload)], p.payload)
	copy(b[36+len(p.payload):], p.Hash())
	return b
}

func ParsePacket(data []byte) (Packet, error) {
	var p Packet
	if len(data) < 4 {
		return p, fmt.Errorf("not enough bytes (%v) for parsing packet", len(data))
	}
	length := int(binary.LittleEndian.Uint32(data[:4]))
	if length+4 != len(data) {
		return p, fmt.Errorf("invalid packe length. should be %v by header but real length is %v", length, len(data)-4)
	}
	copy(p.nonce[:], data[4:36])
	p.payload = make([]byte, length-32-32)
	copy(p.payload, data[36:36+len(p.payload)])
	hash := make([]byte, 32)
	copy(hash, data[len(data)-36:])
	if !bytes.Equal(hash, p.Hash()) {
		return p, fmt.Errorf("checksum error")
	}
	return p, nil
}

type Address struct {
	pubkey ed25519.PublicKey
}

func NewAddress(key []byte) (Address, error) {
	if len(key) != 32 {
		return Address{}, fmt.Errorf("invalid key length: %v", len(key))
	}
	var a Address
	a.pubkey = key
	return a, nil
}

func (a Address) Hash() []byte {
	h := sha256.New()
	h.Write([]byte{0xc6, 0xb4, 0x13, 0x48})
	h.Write(a.pubkey[:])
	return h.Sum(nil)
}