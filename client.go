package adnl

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
)

type Client struct {
	address Address
	params  Params
	keys    Keys

	cipher   cipher.Stream
	decipher cipher.Stream

	conn net.Conn
}

func NewClient(peerPublicKey []byte, host string) (*Client, error) {
	a, err := NewAddress(peerPublicKey)
	if err != nil {
		return nil, err
	}
	params, err := NewParameters()
	if err != nil {
		return nil, err
	}
	ci, err := aes.NewCipher(params.TxKey())
	if err != nil {
		return nil, err
	}
	dci, err := aes.NewCipher(params.RxKey())
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	keys, err := NewKeys(a.pubkey)
	if err != nil {
		return nil, err
	}
	var c = &Client{
		address:  a,
		params:   params,
		keys:     keys,
		cipher:   cipher.NewCTR(ci, params.TxNonce()),
		decipher: cipher.NewCTR(dci, params.TxNonce()),
		conn:     conn,
	}
	go c.reader()
	err = c.handshake()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) reader() {
	conn := bufio.NewReader(c.conn)
	for {
		b := make([]byte, 4)
		_, err := conn.Read(b)
		if err != nil {
			panic(err)
		}
		c.decipher.XORKeyStream(b, b)
		length := binary.LittleEndian.Uint32(b)
		payload := make([]byte, length)
		conn.Read(payload)
		p, err := ParsePacket(b)
		if err != nil {
			panic(err)
		}
		fmt.Println(p)
	}
}

func (c *Client) handshake() error {
	key := append(c.keys.shared[:16], c.params.Hash()[16:32]...)
	nonce := append(c.params.Hash()[0:4], c.keys.shared[20:32]...)
	cipheKey, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	data := append([]byte{}, c.params[:]...)
	cipher.NewCTR(cipheKey, nonce).XORKeyStream(data, data)

	req := make([]byte, 256)
	copy(req[:32], c.address.Hash())
	copy(req[32:64], c.keys.public)
	copy(req[64:96], c.params.Hash())
	copy(req[96:], data)
	_, err = c.conn.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Send(p Packet) error {
	b := p.Marshal()
	c.cipher.XORKeyStream(b, b)
	_, err := c.conn.Write(b)
	return err
}
