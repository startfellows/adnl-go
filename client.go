package adnl

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
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
		decipher: cipher.NewCTR(dci, params.RxNonce()),
		conn:     conn,
	}

	err = c.handshake()
	go c.reader()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) reader() {
	conn := bufio.NewReader(c.conn)
	for {
		p, err := ParsePacket(conn, c.decipher)
		if err != nil {
			panic(err)
		}
		fmt.Println("read nonce", p.nonce)
	}
}

func (c *Client) handshake() error {
	key := append([]byte{}, c.keys.shared[:16]...)
	key = append(key, c.params.Hash()[16:32]...)
	nonce := append([]byte{}, c.params.Hash()[0:4]...)
	nonce = append(nonce, c.keys.shared[20:32]...)
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
	_, err = c.conn.Write(req)
	if err != nil {
		return err
	}
	p, err := ParsePacket(c.conn, c.decipher)
	if err != nil {
		return err
	}
	fmt.Println("handshake", p)
	return nil
}

func (c *Client) Send(p Packet) error {
	b := p.Marshal()
	fmt.Println("send nonce", p.nonce)
	c.cipher.XORKeyStream(b, b)

	_, err := c.conn.Write(b)
	return err
}
