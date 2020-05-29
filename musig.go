// 基于https://github.com/xuperchain/crypto/blob/master/core/multisign/signature.go改写
package musig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"

	"errors"
	"fmt"

	//"github.com/arnaucube/cryptofun/ecc"
	//"github.com/btcsuite/btcd/btcec"
	//blake2b "github.com/minio/blake2b-simd"
	"golang.org/x/crypto/pbkdf2"
	"math/big"
)

//var (
//	//// Curve is a KoblitzCurve which implements secp256k1.
//	//// p = 2^256 -2^32 -977
//	//// y = x^3 +7
//	//Curve = btcec.S256()
//	//// Curve = curve25519.New()
//	//// One holds a big integer of 1
//	//One = New(big.Int).SetInt64(1)
//)

const (
	MinimumsParticipant = 2
)

type aSign struct {
	R []byte
	S []byte
}

//// 生成公私钥对
//// 对 i = 1, 2, ..., n，第i个签名者随机选择一个整数di < n 作为他的私钥，对应
//// 的公钥是Pi = diG，用L={P1, P2, ..., Pn}表示所有公钥的集合。
//func GenKeyPairs() ecdsa.PrivateKey{
//
//	ecdsaPrivateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
//
//	return ecdsaPrivateKey
//}
//
//// 对 i = 1, 2, ..., n，第i个签名者计算 ai = H(L || Pi) 以及
//// 聚合公钥 P = a1P1 + a2P2 + ... + anPn。 ai可视为随机数
//
//
//// Sign签名
//func Sign(privateKey *big.Int, message []byte) ([64]byte, error) {
//
//	if privateKey.Cmp(One) < 0 || privateKey.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
//		return sig, errors.New("the privateKey must be an integer in the range 1..n-1")
//	}
//	// 1. 计算 k = H(m || x)
//
//	// 2. 计算 e = H(m || k * G)
//	// 计算 K * G
//	// 计算 H(m || k * G)
//
//	// 计算 k = s + e * x, s = k - e * x
//	// 生成schnorr签名：(sum(s), R)
//
//	// 封装成json格式
//	k := crypto.BLAKE2b_256.New()
//	sig := [64]byte{}
//	d := intToByte(privateKey)
//	blake2b.New()
//	ed25519.
//	return sig, nil
//}
//
//// Verify 验签
//func Verify(publicKey [33]byte, message []byte, signature [64]byte) (bool, error) {
//	if len()
//	// 1. 计算： e = H(C,R,m)
//
//	// 2. 计算： Rv = sG - eC
//
//	// 3. 如果Rv == R 则返回true，否则返回false
//
//	return true, nil
//}

// AggregationSign 生成特定消息的多重签名，所有参与签名的私钥必须使用同一条椭圆曲线
// 1. di' < n 作为第i个签名者的临时私钥(随机数)，计算Pi' = di'G, ti = H(Pi')，将ti发给所有其他签名者。
// 2. 第 i 个签名者收到所有其他签名者的tj后，将Pi'发给其他签名者。
// 3. 收到其他签名者发来的Pj'后，验证 tj = H(Pj')是否成立。如果成立，进入下一步；否则，终止签名程序。
// 4. 第i个签名者计算 P' = P1' + P2' + ... + Pn', 计算公共公钥P = P1 + P2 + ... + Pn.
//    Z = H(P || P' || message), Si = (di' + Zdi) mod n，并将Si发给所有其他签名者。
// 5. 第i个签名者收到其他签名者发来的Sj后，计算S = (S1 + S2 + ... + Sn) mod n
// 6. 多重签名为(P', S)
func AggregationSign(privateKeys []*ecdsa.PrivateKey, message []byte) ([]byte, error) {
	var sig []byte
	if len(privateKeys) < MinimumsParticipant {
		return sig, errors.New("the total num of keys should be greater than one")
	}
	if len(message) == 0 {
		return sig, errors.New("message to be sign should not be nil")
	}

	// 1. 生成公私钥对(X1, P1), (X2, P2), ..., (Xn, Pn), X代表私钥中的参数大数D，P代表公钥。
	// 检验传入私钥参数是否合法，是否使用同一条曲线
	// TODO

	// 2. 生成临时随机数(d1', d2', ..., dn')，作为临时私钥
	num := len(privateKeys)
	arrayOkk := func(num int) [][]byte {

		arrayOfK := make([][]byte, num)
		for i := 0; i < num; i++ {
			randomBytes := func() []byte {
				var entropyBitLength = 256
				entropyByte := func(bitSize int) []byte {
					entropy := make([]byte, bitSize/8)
					_, _ = rand.Read(entropy)
					return entropy
				}(entropyBitLength)
				return func(randomPassword []byte) []byte {
					salt := "zong xun jie"
					seed := pbkdf2.Key(randomPassword, []byte(salt), 2048, 32, sha512.New)
					return seed
				}(entropyByte)
			}()
			arrayOfK[i] = randomBytes
		}
		return arrayOfK
	}(num)
	//fmt.Printf("step 2 arrayOfK is %v\n", arrayOkk)

	// 3. 计算： Pi' = di'G, G代表基点,
	// 计算 r = P' = P1' + P2' + ... + Pn' = d1'*G + d2'*G + ... + dn'*G
	r := func(keys []*ecdsa.PrivateKey, arrayOfk [][]byte) []byte {
		num := len(keys)
		curve := privateKeys[0].Curve
		x, y := big.NewInt(0), big.NewInt(0)
		for i := 0; i < num; i++ {
			// 计算Pi' = di*G
			xi, yi := curve.ScalarBaseMult(arrayOkk[i])
			// 计算P' = P1' + P2' + ... + Pn' = d1'*G + d2'*G + ... + dn'*G
			x, y = curve.Add(x, y, xi, yi)
		}
		// 计算P',用r表示，converts a point into the uncompressed form specified in section 4.3.6 of ANSI x9.62
		r := elliptic.Marshal(curve, x, y)
		return r
	}(privateKeys, arrayOkk)
	//fmt.Printf("step 3 r is %v\n", r)

	// 4. 计算公共公钥： P = P1 + P2 + ... + Pn
	P := func(keys []*ecdsa.PrivateKey) []byte {
		num := len(keys)
		curve := keys[0].Curve
		x, y := big.NewInt(0), big.NewInt(0)
		for i := 0; i < num; i++ {
			if keys[i] == nil {
				return nil
			}
			x, y = curve.Add(keys[i].PublicKey.X, keys[i].PublicKey.Y, x, y)
		}
		// 计算L，converts a point into the uncompressed form specified in section 4.3.6 of ANSI x9.62
		L := elliptic.Marshal(curve, x, y)
		return L
	}(privateKeys)
	//fmt.Printf("step 4 P is %v\n", P)

	// 5. 各方计算： si = di' + HASH(P, P', message) * di
	// 计算 S = sum(si)
	s := func(keys []*ecdsa.PrivateKey, arrayOfk [][]byte, c []byte, r []byte, message []byte) []byte {
		num := len(arrayOkk)
		s := big.NewInt(0)
		for i := 0; i < num; i++ {
			// 计算HASH(P, P',m)
			hashBytes := hash(c, r, message)

			// 计算HASH(P, P', m) * di
			tempRhs := new(big.Int).Mul(new(big.Int).SetBytes(hashBytes), keys[i].D)

			// 计算di' + HASH(P,R,m) * di
			res := new(big.Int).Add(new(big.Int).SetBytes(arrayOkk[i]), tempRhs)
			// 计算s1 + s2 + ... + sn
			s = s.Add(s, res)
		}
		return s.Bytes()
	}(privateKeys, arrayOkk, P, r, message)
	//fmt.Printf("step 5 s is %v\n", s)

	// 6. 生成多重签名：(P', S)
	multiSig := &aSign{
		R: r,
		S: s,
	}
	fmt.Printf("step 6 multiSig is %v\n", multiSig)
	// 7. 生成超级签名(转换json)
	sig, err := json.Marshal(multiSig)
	if err != nil {
		return sig, err
	}
	fmt.Printf("step 7 sig is %v\n", string(sig))
	return sig, nil
}

// AggregationVerify验证签名
// 已知公钥集合L={P1, P2, ..., Pn}，message和(P'，S)
// 1. 计算 ai = H(L||Pi)
// 2. 计算 P = a1P1 + a2P2 + ... + anPn
// 3. 计算 z = H(P||P'||message)
// 4. 验证 SG = zP + P'是否成立
func AggregationVerify(publicKeys []*ecdsa.PublicKey, aggregationSign []byte, message []byte) (bool, error) {
	if len(publicKeys) < MinimumsParticipant {
		return false, errors.New("the total num of keys should be greater than one")
	}
	//if aggregationSign == nil || len(aggregationSign) != 64 {
	//	return false, errors.New("signature must not be nil")
	//}

	sig := &aSign{}
	fmt.Printf("aggregation sign %s\n", aggregationSign)
	err := json.Unmarshal(aggregationSign, sig)
	if err != nil {
		return false, err
	}
	curve := publicKeys[0].Curve
	fmt.Printf("sig=%v\n", sig)

	// 1. 计算 ai = H(L||Pi)
	//   计算公共公钥 P = a1P1 + a2P2 + ... + anPn
	//    P = P1 + P2 + ... + Pn
	P := func(keys []*ecdsa.PublicKey) []byte {
		num := len(keys)
		curve := keys[0].Curve
		x, y := big.NewInt(0), big.NewInt(0)
		for i := 0; i < num; i++ {
			if keys[i] == nil {
				return nil
			}
			x, y = curve.Add(keys[i].X, keys[i].Y, x, y)
		}
		return elliptic.Marshal(curve, x, y)
	}(publicKeys)
	fmt.Printf("2. P: %v\n", P)

	// 2. 计算 z = H(P||P'||message)
	hashBytes := hash(P, sig.R, message)
	fmt.Printf("3. hashBytes: %v\n", hashBytes)
	// 3. 验证 SG = zP + P'是否成立，即验证P' = SG - zP
	// 3.1 计算SG
	lhsX, lhsY := curve.ScalarBaseMult(sig.S)
	fmt.Printf("3.1\n")
	// 3.2 计算zP，zP= H(P||P'||message)*P
	x, y := elliptic.Unmarshal(curve, P)
	rhsX, rhsY := curve.ScalarMult(x, y, hashBytes)
	fmt.Printf("3.2\n")
	// 3.3 计算 -zP，如果zP = (x, y), 则 -zP = (x, -y mod P)
	negativeOne := big.NewInt(-1)
	rhsY = new(big.Int).Mod(new(big.Int).Mul(negativeOne, rhsY), curve.Params().P)
	fmt.Printf("3.3\n")
	// 3.4 计算 Rv = SG - zP
	resX, resY := curve.Add(lhsX, lhsY, rhsX, rhsY)
	fmt.Printf("3.4 resX=%v, resY=%v\n", resX, resY)
	// 3.5 原始签名中的P'
	rX, rY := elliptic.Unmarshal(curve, sig.R)
	fmt.Printf("3.5 rX=%v, rY=%v\n", rX, rY)
	// 3.6 对比签名是否一致
	if resX.Cmp(rX) == 0 && resY.Cmp(rY) == 0 {
		return true, nil
	}
	fmt.Printf("3.6\n")
	return false, nil

}

//func intToByte(i *big.Int) []byte {
//	b1, b2 := [32]byte{}, i.Bytes()
//	copy(b1[32-len(b2):], b2)
//	return b1[:]
//}

// hash calculates a hash that concatenate a given message. H(M||R)
func hash(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer
	for i := 0; i < len(pBytes); i++ {
		buffer.Write(pBytes[i])
	}
	message := buffer.Bytes()
	var b []byte
	b = append(b, message...)
	h := sha256.New()
	h.Write(b)
	hash := h.Sum(nil)
	return hash
}
