package schnorr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestVerify(t *testing.T) {
	message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	publicKey, _ := hex.DecodeString("021b34e02fbfab6153513c7578de070e1c9f2654b88109fb3906bb7f63dffd957d")
	R, _ := hex.DecodeString("032bfdb8ad7bbf0829baf2357534a1fd609ee0ff8f129b3cbb5935e064ef5c6eff")
	s, _ := hex.DecodeString("bb8abf79eade60eb11674f53ffc7173b346c404bdc2e7d00372c2bdb3cb46185")

	var publicKey33 [33]byte
	copy(publicKey33[:], publicKey)
	var R33 [33]byte
	copy(R33[:], R)
	var s32 [32]byte
	copy(s32[:], s)

	ret, err := Verify(publicKey33, message, R33, s32)
	if err != nil {
		panic(err)
	}
	if !ret {
		panic("验证失败")
	}
}

func TestSign(t *testing.T)  {
	message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")

	d, _ := hex.DecodeString("b2b084220e17de5bb85c6b33fe4630dc0cc3a0382c49509461a26341bc3c27e4")
	P, _ := hex.DecodeString("021b34e02fbfab6153513c7578de070e1c9f2654b88109fb3906bb7f63dffd957d")
	var d32 [32]byte
	var P33 [33]byte
	copy(d32[:], d)
	copy(P33[:], P)

	k := GetPrivateK(d32, message)
	R := GetPublicR(P33, message)

	privateKey := &PrivateKey{D:d32, K:k}
	publicKey := &PublicKey{P:P33, R:R}

	Rx, Ry, s, err := Sign(message, privateKey, publicKey)
	if err != nil {
		panic(err)
	}

	R_ := Marshal(Curve, Rx, Ry)
	var R_33 [33]byte
	copy(R_33[:], R_)

	var s32 [32]byte
	copy(s32[:], IntToByte(s))

	ret, err := Verify(publicKey.P, message, R_33, s32)
	if err != nil {
		panic(err)
	}
	if !ret {
		panic("验证失败")
	}

	if bytes.Equal(IntToByte(Rx), publicKey.R[:]) {
		panic("Rx 错误")
	}
	fmt.Println(hex.EncodeToString(s32[:]))
}

func TestAggregateSignatures(t *testing.T) {
	message, _ := hex.DecodeString("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
	var privkDs = []string{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
		"C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7",
		"6d6c66873739bc7bfb3526629670d0ea357e92cc4581490d62779ae15f6b787b",
	}

	var privateKeys []*PrivateKey
	var publicKeys []*PublicKey
	PubX, PubY := Zero, Zero
	for _, privkD := range privkDs[:]  {
		d, _ := hex.DecodeString(privkD)
		var d32 [32]byte
		copy(d32[:], d)
		k := GetPrivateK(d32, message)

		Px, Py := Curve.ScalarBaseMult(d[:])
		PubX, PubY = Curve.Add(PubX, PubY, Px, Py)
		Rx, Ry := Curve.ScalarBaseMult(k[:])

		P := Marshal(Curve, Px, Py)
		R := Marshal(Curve, Rx, Ry)
		var P33 [33]byte
		var R33 [33]byte
		copy(P33[:], P)
		copy(R33[:], R)

		privateKeys = append(privateKeys, &PrivateKey{D:d32, K:k})
		publicKeys = append(publicKeys, &PublicKey{P:P33, R:R33})
	}

	publicKey := Marshal(Curve, PubX, PubY)
	var publicKey33 [33]byte
	copy(publicKey33[:], publicKey)

	var R [33]byte
	var s [32]byte
	var err error
	for i, privateKey := range privateKeys {
		R, s, err = AppendSignature(R, s, message, privateKey, AggregationPublicKey(publicKeys[:i]), AggregationPublicKey(publicKeys))
		if err != nil {
			panic(err)
		}
	}

	ret, err := Verify(publicKey33, message, R, s)
	if err != nil {
		panic(err)
	}
	if !ret {
		panic("验证失败")
	}
}


func decodeSignature(s string, t *testing.T) (sig [64]byte) {
	signature, err := hex.DecodeString(s)
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", s, err)
	}
	copy(sig[:], signature)
	return
}

func decodeMessage(m string, t *testing.T) (msg [32]byte) {
	message, err := hex.DecodeString(m)
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", m, err)
	}
	copy(msg[:], message)
	return
}

func decodePublicKey(pk string, t *testing.T) (pubKey [33]byte) {
	publicKey, err := hex.DecodeString(pk)
	if err != nil && t != nil {
		t.Fatalf("Unexpected error from hex.DecodeString(%s): %v", pk, err)
	}
	copy(pubKey[:], publicKey)
	return
}

func decodePrivateKey(d string, t *testing.T) *big.Int {
	privKey, ok := new(big.Int).SetString(d, 16)
	if !ok && t != nil {
		t.Fatalf("Unexpected error from new(big.Int).SetString(%s, 16)", d)
	}
	return privKey
}