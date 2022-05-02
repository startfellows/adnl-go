package adnl

import (
	"encoding/base64"
	"fmt"
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
	fmt.Println(c.conn.RemoteAddr())
	time.Sleep(time.Second)
}
