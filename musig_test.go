package musig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestAggregationSign(t *testing.T) {
	var pks []*ecdsa.PrivateKey
	//pk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//pk2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//fmt.Printf("pk1 %v\n", pk1)
	//fmt.Printf("pk2 %v\n", pk2)

	pkx11, _ := new(big.Int).SetString("28473537578834350355027095962410793654161922185636299138898935548646518245676", 10)
	pky11, _ := new(big.Int).SetString("56413289167690379226165833434322227986957660290817107142220274640314374628197", 10)
	pkD11, _ := new(big.Int).SetString("88032970423708664743162806614123043178160081083686188982768548388151740298717", 10)

	p256 := struct {
		*elliptic.CurveParams
	}{}
	p256.CurveParams = &elliptic.CurveParams{Name: "P-256"}
	p256.P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	p256.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
	p256.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	p256.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	p256.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	p256.BitSize = 256

	pk11 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: p256,
			X:     pkx11,
			Y:     pky11,
		},
		D: pkD11,
	}

	pkx22, _ := new(big.Int).SetString("16593074712446291678474083039807552988166424671205149915860858557022909740167", 10)
	pky22, _ := new(big.Int).SetString("57377533216444846907100182478785223880724150146640836102112480693633989832390", 10)
	pkD22, _ := new(big.Int).SetString("67709460604642704174197019174421292329009483518523489516657692630261856928687", 10)

	pk22 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			//Curve:elliptic.P256(),
			Curve: p256,
			X:     pkx22,
			Y:     pky22,
		},
		D: pkD22,
	}

	pks = append(pks, pk11)
	pks = append(pks, pk22)
	message := []byte("drive your car by yourself")
	aggregationSign, _ := AggregationSign(pks, message)

	fmt.Printf("pk11 %v\n", pk11)
	fmt.Printf("pk22 %v\n", pk22)
	fmt.Printf("message %s\n", string(message))
	fmt.Printf("aggregation sign %v\n", aggregationSign)

	// 因为签名算法里面使用了随机数作为临时私钥，所以即使每次输入一样的公私钥对，也无法得到固定一致的签名。
	// 测试函数只能验证得到签名。具体签名的的验证，要在验证函数检验。
	//expectedSign := `{"R":"BK03a0c29598+JxGVw09z1PfA48iKifeXOx1n6/se7rtuWpJTY99m8/1gW9PFlBx4EO9X4wQ0BXL77tpCt1dDSQ=","S":"o5wOPG8pG2tQBXmPbEZEUCROnqAqJ4r8kFcRVOvXItwxY3XTHbbNVXm6e9BEGVQxDWZrFynaiDGpYoFtab4isQ=="}`
	//if string(aggregationSign) != expectedSign {
	//	t.Errorf("aggregationSign is %v\n expectedSign is %v\n", aggregationSign, expectedSign)
	//}
}

func TestAggregationVerify(t *testing.T) {
	var pks []*ecdsa.PrivateKey
	pk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pks = append(pks, pk1)
	pks = append(pks, pk2)
	message := []byte("drive your car by yourself")
	aggregationSign, err := AggregationSign(pks, message)
	if err != nil {
		fmt.Printf("got error: %s\n", err)
	}
	fmt.Printf("pk1 %v\n", pk1)
	fmt.Printf("pk2 %v\n", pk2)
	fmt.Printf("message %s\n", string(message))
	fmt.Printf("aggregation sign %s\n", aggregationSign)
	//fmt.Printf("aggregation sign len = %d\n", len(aggregationSign))

	var pubKeys []*ecdsa.PublicKey
	pubKeys = append(pubKeys, &pk1.PublicKey)
	pubKeys = append(pubKeys, &pk2.PublicKey)
	verifyResult, err := AggregationVerify(pubKeys, aggregationSign, message)
	if err != nil {
		fmt.Printf("got err: %s\n", err)
	}
	fmt.Printf("verifyResult: %v\n", verifyResult)
	if !verifyResult {
		t.Errorf("Verify failed\n")
	}

}
