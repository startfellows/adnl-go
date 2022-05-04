## ADNL pure-golang implementation.

### Installation

```shell

go get github.com/startfellows/adnl-go

```

### Usage 

Raw network example

```go
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/startfellows/adnl-go"
)

func main() {
	
    myPayload, _ := hex.DecodeString("7af98bb435263e6c95d6fecb497dfd0aa5f031e7d412986b5ce720496db512052e8f2d100cdf068c7904345aad16000000000000")
	serverPubkey, err := base64.StdEncoding.DecodeString("Z3X5IRueR4Lbdc0I+1SZwyWmnuDNHdUf14JwIPsGgRw=")
	if err != nil {
		panic(err)
	}
	c, err := adnl.NewConnection(context.Background(), serverPubkey, "127.0.0.1:7742")
	if err != nil {
		panic(err)
	}
	packet, err := adnl.NewPacket(myPayload)
	if err != nil {
		panic(err)
	}
    err = c.Send(packet)
	if err != nil {
		panic(err)
	}
	for p := range c.Responses() {
		fmt.Printf("received %x\n", p.Payload)
	}
}

```

LiteServer query

```go
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/startfellows/adnl-go"
	"github.com/startfellows/tongo/lightclient"
	"github.com/startfellows/tongo"
)

func main() {
	
	serverPubkey, err := base64.StdEncoding.DecodeString("Z3X5IRueR4Lbdc0I+1SZwyWmnuDNHdUf14JwIPsGgRw=")
	if err != nil {
		panic(err)
	}
	c, err := adnl.NewConnection(context.Background(), serverPubkey, "127.0.0.1:7742")
	if err != nil {
		panic(err)
	}
    req :=lightclient.AccountStateRequest(tongo.MustParseAccount("0:0c307d4bf558ca82f33dda0db140bfa2a8a511c61993582e69d4b834e6495e3c"))
	client := adnl.NewClient(c)
	resp, err := client.Request(context.Background(), req)
	if err != nil {
		panic(err)
	}
	state, err := lightclient.ParseAccountState(resp)
	if err !=nil {
		panic(err)
    }
	fmt.Printf("%x\n", state.TonBalance)
}

```