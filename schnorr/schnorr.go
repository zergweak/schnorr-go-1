package schnorr

import (
	"bytes"
	"errors"
	"math/big"
)

//PrivateKey 私钥
type PrivateKey struct {
	D [32]byte     //签名私钥
	K [32]byte	   //随机数
}

//PublicKey 公钥
type PublicKey struct {
	P [33]byte	   //签名公钥
	R [33]byte	   //k0*G
}

// AppendSignature 实现一个聚合签名，可以在一个签名的基础上追加一个签名
// signInput 是上一个参与者的签名结果，如果本次为第一个，则为nil
// privateKey是私钥，
// message是签名消息
// publicKeys 是公钥的集合，按照签名顺序排序
// index 当前签名的序号，小于index的已经签完
func AppendSignature(R_in [33]byte, s_in [32]byte, message []byte, privateKey *PrivateKey, pubSigned *PublicKey, pub *PublicKey) (R_out [33]byte, s_out [32]byte, err error) {
	//校验privateKey
	var zero33 [33]byte
	flag := !bytes.Equal(R_in[:], zero33[:]) || !bytes.Equal(s_in[:], zero33[:32])

	RxSigned, RySigned := Zero, Zero
	if flag {
		if pubSigned == nil {
			return R_out, s_out, errors.New("pubSigned is nil")
		}
		ret, err := VerifySignInput(pubSigned, pub, message, R_in, s_in)
		if err != nil {
			return R_out, s_out, err
		}
		if !ret {
			return R_out, s_out, errors.New("signature verification failed")
		}
		RxSigned, RySigned = Unmarshal(Curve, pubSigned.R[:])
	}


	Rix, Riy, s, err := Sign(message, privateKey, pub)
	if flag {
		Rix, Riy = Curve.Add(RxSigned, RySigned, Rix, Riy)
		sSigned := new(big.Int).SetBytes(s_in[:])
		s = s.Add(s, sSigned)
		s = s.Mod(s, Curve.N)
	}

	R33 := Marshal(Curve, Rix, Riy)
	copy(R_out[:], R33[:])
	copy(s_out[:], IntToByte(s))
	return  R_out, s_out, nil
}

// Sign 一个参与者签名
// privateKey是私钥
// publicKey是公钥
// message是签名消息
// pub 是公钥或者公钥的聚合
func Sign(message []byte, privateKey *PrivateKey, pub *PublicKey) (Rx, Ry, s *big.Int, err error){
	//Bip32分散k0
	Rx, Ry = Curve.ScalarBaseMult(privateKey.K[:])

	k := new(big.Int).SetBytes(privateKey.K[:])
	e := getE(pub.P, pub.R, message)
	// s = k + de
	priKey := new(big.Int).SetBytes(privateKey.D[:])
	e.Mul(e, priKey)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	return Rx, Ry, k,nil
}

//Verify
func Verify(publicKey [33]byte, message []byte, R [33]byte, s [32]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])
	e := getE(publicKey, R, message)
	sGx, sGy := Curve.ScalarBaseMult(s[:])
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, IntToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	R_ := Marshal(Curve, Rx, Ry)
	if !bytes.Equal(R_[:], R[:]) {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

//MultiVerify
func MultiVerify(publicKey [][33]byte, message []byte, R [33]byte, s [32]byte) (bool, error) {
	pubKey := aggregationPubKey(publicKey)
	return Verify(pubKey, message, R, s)
}

//VerifySignInput 验证签名的中间过程
//publicKeysSigned 已经参与的签名公钥
//publicKeys	所有参与签名的公钥
//message		签名消息
//R_in, s_in	签名中间结果
func VerifySignInput(pubSigned *PublicKey, pub *PublicKey, message []byte, R_in [33]byte, s_in [32]byte) (bool, error) {
	pubSignedPx, pubSignedPy := Unmarshal(Curve, pubSigned.P[:])
	s := new(big.Int).SetBytes(s_in[:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(pub.P, pub.R, message)
	sGx, sGy := Curve.ScalarBaseMult(IntToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(pubSignedPx, pubSignedPy, IntToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx1, Ry1 := Curve.Add(sGx, sGy, ePx, ePy)
	if Rx1.Sign() == 0 && Ry1.Sign() == 0 {
		return false, errors.New("signature verification failed : Rx1, Rx1 are zero")
	}

	R1 := Marshal(Curve, Rx1, Ry1)
	if !bytes.Equal(pubSigned.R[:], R_in[:]) {
		return false, errors.New("signature verification failed : pubSignedR is not equal R_in")
	}

	if !bytes.Equal(R1[:], R_in[:]) {
		return false, errors.New("signature verification failed : R1 is not equal R_in")
	}
	return true, nil
}