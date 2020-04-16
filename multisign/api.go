package multisign

import (
	"errors"
	"schnorr/schnorr-go/schnorr"
)

// AppendSignature 实现一个聚合签名，可以在一个签名的基础上追加一个签名
// R_in, s_in 是上一个参与者的签名结果，如果本次为第一个，则为空
// privateKey是私钥，
// message是签名消息
// publicSigneds 是已经签名的公钥
// publicKeys 是公钥的集合
func AppendSignature(R_in [33]byte, s_in [32]byte, message []byte, privateKey [32]byte, publicSigneds [][33]byte, publicKeys [][33]byte) (R_out [33]byte, s_out [32]byte, err error){
	k := schnorr.GetPrivateK(privateKey, message)
	privKey := &schnorr.PrivateKey{D:privateKey, K:k}

	if len(publicKeys) == 0 {
		return R_out, s_out, errors.New("invalid publicKeys")
	}
	var pubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeys {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubKeys = append(pubKeys, pubKey)
	}

	var pubSigned []*schnorr.PublicKey
	for _, publicKey := range publicSigneds {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubSigned = append(pubSigned, pubKey)
	}

	return schnorr.AppendSignature(R_in, s_in, message, privKey, schnorr.AggregationPublicKey(pubSigned), schnorr.AggregationPublicKey(pubKeys))
}

func Sign(message []byte, privateKey [32]byte, publicKeys [][33]byte) (R [33]byte, s [32]byte, err error){
	k0 := schnorr.GetPrivateK(privateKey, message)
	privKey := &schnorr.PrivateKey{D:privateKey, K:k0}

	if len(publicKeys) == 0 {
		return R, s, errors.New("invalid publicKeys")
	}
	var pubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeys {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubKeys = append(pubKeys, pubKey)
	}
	Rx, Ry, s_, err := schnorr.Sign(message, privKey, schnorr.AggregationPublicKey(pubKeys))
	if err != nil {
		return R, s, err
	}

	R_ := schnorr.Marshal(schnorr.Curve, Rx, Ry)
	copy(R[:], R_)
	copy(s[:], schnorr.IntToByte(s_))
	return R, s, nil
}

//Verify
func Verify(publicKey [33]byte, message []byte, R [33]byte, s [32]byte) (bool, error) {
	return schnorr.Verify(publicKey, message, R, s)
}

//MultiVerify
func MultiVerify(publicKey [][33]byte, message []byte, R [33]byte, s [32]byte) (bool, error) {
	return schnorr.MultiVerify(publicKey, message, R, s)
}

//VerifySignInput 验证签名的中间过程
//publicKeysSigned 已经参与的签名公钥
//publicKeys	所有参与签名的公钥
//message		签名消息
//signInput		签名中间结果
func VerifySignInput(publicKeysSigned [][33]byte, publicKeys [][33]byte, message []byte, R [33]byte, s [32]byte) (bool, error) {
	if len(publicKeysSigned) == 0 {
		return true, nil //没有签过
	}

	if len(publicKeys) == 0 {
		return false, errors.New("invalid publicKeys")
	}

	if len(publicKeys) < len(publicKeysSigned) {
		return false, errors.New("publicKeysSigned size bigger than publicKeys")
	}

	var signedPubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeysSigned {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		signedPubKeys = append(signedPubKeys, pubKey)
	}

	var pubKeys []*schnorr.PublicKey
	for _, publicKey := range publicKeys {
		R := schnorr.GetPublicR(publicKey, message)
		pubKey := &schnorr.PublicKey{P:publicKey, R:R}
		pubKeys = append(pubKeys, pubKey)
	}

	return schnorr.VerifySignInput(schnorr.AggregationPublicKey(signedPubKeys), schnorr.AggregationPublicKey(pubKeys), message, R, s)
}
