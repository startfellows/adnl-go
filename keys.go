package adnl

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/oasisprotocol/curve25519-voi/curve"
	ed25519crv "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
)

type Keys struct {
	public []byte
	shared []byte
}

func NewKeys(peerPublicKey ed25519.PublicKey) (Keys, error) {
	public, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Keys{}, err
	}

	shared, err := sharedKey(privateKey, peerPublicKey)
	if err != nil {
		return Keys{}, err
	}
	return Keys{shared: shared, public: public}, nil
}

func sharedKey(ourKey ed25519.PrivateKey, serverKey ed25519.PublicKey) ([]byte, error) {
	comp, err := curve.NewCompressedEdwardsYFromBytes(serverKey)
	if err != nil {
		return nil, err
	}

	ep, err := curve.NewEdwardsPoint().SetCompressedY(comp)
	if err != nil {
		return nil, err
	}

	mp := curve.NewMontgomeryPoint().SetEdwards(ep)
	bb := x25519.EdPrivateKeyToX25519(ed25519crv.PrivateKey(ourKey))

	key, err := x25519.X25519(bb, mp[:])
	if err != nil {
		return nil, err
	}

	return key, nil
}
