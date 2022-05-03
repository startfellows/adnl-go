package adnl

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"net"
)

type Client struct {
	address Address
	params  params
	keys    x25519Keys

	cipher   cipher.Stream
	decipher cipher.Stream

	conn net.Conn
	resp chan Packet
}

func NewClient(ctx context.Context, peerPublicKey []byte, host string) (*Client, error) {
	a, err := NewAddress(peerPublicKey)
	if err != nil {
		return nil, err
	}
	params, err := newParameters()
	if err != nil {
		return nil, err
	}
	ci, err := aes.NewCipher(params.txKey())
	if err != nil {
		return nil, err
	}
	dci, err := aes.NewCipher(params.rxKey())
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	keys, err := newKeys(a.pubkey)
	if err != nil {
		return nil, err
	}
	var c = &Client{
		address:  a,
		params:   params,
		keys:     keys,
		cipher:   cipher.NewCTR(ci, params.txNonce()),
		decipher: cipher.NewCTR(dci, params.rxNonce()),
		conn:     conn,
		resp:     make(chan Packet, 1000),
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
		c.resp <- p
	}
}

func (c *Client) handshake() error {
	key := append([]byte{}, c.keys.shared[:16]...)
	key = append(key, c.params.hash()[16:32]...)
	nonce := append([]byte{}, c.params.hash()[0:4]...)
	nonce = append(nonce, c.keys.shared[20:32]...)
	cipherKey, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	data := append([]byte{}, c.params[:]...)
	cipher.NewCTR(cipherKey, nonce).XORKeyStream(data, data)
	req := make([]byte, 256)
	copy(req[:32], c.address.hash())
	copy(req[32:64], c.keys.public)
	copy(req[64:96], c.params.hash())
	copy(req[96:], data)
	_, err = c.conn.Write(req)
	if err != nil {
		return err
	}
	_, err = ParsePacket(c.conn, c.decipher)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) Send(p Packet) error {
	b := p.marshal()
	c.cipher.XORKeyStream(b, b)
	_, err := c.conn.Write(b)
	return err
}

func (c *Client) Responses() chan Packet {
	return c.resp
}
