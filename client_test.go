package adnl

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"
)

func TestClien(t *testing.T) {
	pubkey, err := base64.StdEncoding.DecodeString("Z3X5IRueR4Lbdc0I+1SZwyWmnuDNHdUf14JwIPsGgRw=")
	if err != nil {
		panic(err)
	}
	c, err := NewClient(pubkey, "127.0.0.1:7742")
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	b, _ := hex.DecodeString("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")
	packet, err := NewPacket(b)
	if err != nil {
		panic(err)
	}
	err = c.Send(packet)
	if err != nil {
		panic(err)
	}
	time.Sleep(time.Second * 10)
}
