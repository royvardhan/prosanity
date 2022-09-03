package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var hash = flag.String("tx", "0x0d689ae5df735d40dc82974eb6c9436980ed265a52bed51e0d798d10bae4f43c", "tx hash")

func main() {
	flag.Parse()
	rpcClient, err := rpc.DialHTTPWithClient("https://cloudflare-eth.com/", http.DefaultClient)
	if err != nil {
		panic(err)
	}
	client := ethclient.NewClient(rpcClient)
	tx, _, err := client.TransactionByHash(context.Background(), common.HexToHash(*hash))
	if err != nil {
		panic(err)
	}
	publicKey, err := GetTxPublicKey(tx)
	if err != nil {
		panic(err)
	}
	fmt.Println("address:", crypto.PubkeyToAddress(*publicKey))
	fmt.Println("public key:", hexutil.Encode(crypto.FromECDSAPub(publicKey)))
}

func GetTxPublicKey(tx *types.Transaction) (*ecdsa.PublicKey, error) {
	V, R, S := tx.RawSignatureValues()
	switch tx.Type() {
	case types.LegacyTxType:
		if tx.Protected() {
			V = new(big.Int).Sub(V, new(big.Int).Mul(big.NewInt(2), tx.ChainId()))
			V.Sub(V, big.NewInt(8))
		}
	case types.AccessListTxType:
		// AL txs are defined to use 0 and 1 as their recovery
		// id, add 27 to become equivalent to unprotected Homestead signatures.
		V = new(big.Int).Add(V, big.NewInt(27))
	case types.DynamicFeeTxType:
		V = new(big.Int).Add(V, big.NewInt(27))
	default:
		return nil, types.ErrTxTypeNotSupported
	}

	if V.BitLen() > 8 {
		return nil, types.ErrInvalidSig
	}
	v := byte(V.Uint64() - 27)
	if !crypto.ValidateSignatureValues(v, R, S, true) {
		return nil, types.ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = v

	signer := types.NewLondonSigner(tx.ChainId())
	hash := signer.Hash(tx)
	publicKey, err := crypto.SigToPub(hash[:], sig)
	if err != nil {
		return nil, err
	}
	return publicKey, err
}
