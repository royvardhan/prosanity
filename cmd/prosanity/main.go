package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SmithUnity/prosanity"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/tucnak/telebot"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

var (
	flagStoreDir       = flag.String("dir", "seeds", "seed store directory")
	flagReadStart      = flag.Int("start", 0, "seed read start")
	flagReadCount      = flag.Int("count", 1, "seed read count")
	flagTelegramToken  = flag.String("token", "", "telegram bot token")
	flagTelegramChatID = flag.String("id", "", "telegram chat id")
	flagPubkey         = flag.String("pubkey", "", "preset crack pubkey")
	flagStartBatch     = flag.Int("start-batch", 0, "start batch")
	flagMaxBatch       = flag.Int("max-batch", 2048, "max batch")
)

var (
	pubkeySeedMap map[uint64]uint32
	pubkeyMutex   sync.Mutex
	curve         = crypto.S256().(*secp256k1.BitCurve)
	idDiffX       *big.Int
	idDiffY       *big.Int
)

func main() {
	flag.Parse()

	wd, _ := os.Getwd()
	fmt.Println("work directory:", wd)
	fmt.Println("telegram token:", *flagTelegramToken)
	fmt.Println("telegram chat id:", *flagTelegramChatID)

	var mapSize int
	switch {
	case *flagReadCount == 16:
		mapSize = 1 << 32 // memory > 120GB
	case *flagReadCount >= 2:
		mapSize = 1 << 29 // memory > 40GB
	default:
		mapSize = 1 << 28 // memory > 20GB
	}
	pubkeySeedMap = make(map[uint64]uint32, mapSize)
	idDiffX, idDiffY = curve.ScalarBaseMult(prosanity.IDDiffK())
	idDiffY.Neg(idDiffY)

	// read seed files
	start := time.Now()
	fmt.Println("loading seed files")
	readSeedFiles()
	fmt.Println("loaded seed files", time.Since(start))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	taskCh := make(chan struct{})

	go func() {
		if *flagPubkey != "" {
			crackPubkey(*flagPubkey, taskCh)
			os.Exit(0)
		}
		for {
			fmt.Print("Enter Public Key: ")
			var s string
			_, err := fmt.Scanln(&s)
			if err != nil {
				fmt.Println("read pubkey error:", err)
				continue
			}
			s = strings.TrimSpace(s)
			switch s {
			case "q", "exit":
				os.Exit(0)
			case "":
				continue
			}
			select {
			case <-taskCh:
			default:
				close(taskCh)
				taskCh = make(chan struct{})
			}
			crackPubkey(s, taskCh)
		}
	}()
	for range sig {
		os.Exit(1)
	}
}

func crackPubkey(s string, ch chan struct{}) {
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	pubKeyBytes, err := hexutil.Decode(s)
	if err != nil {
		fmt.Println("hex decode pubkey error:", err)
		return
	}
	pubkey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		fmt.Println("failed to unmarshal public key:", err)
		return
	}
	fmt.Println("target public key:", hexutil.Encode(crypto.FromECDSAPub(pubkey)))
	address := crypto.PubkeyToAddress(*pubkey)
	fmt.Println("target address:", address)

	maxID := uint64(16384 * 255)
	numCPU := runtime.NumCPU()
	perCpuIDs := maxID / uint64(numCPU)
	maxBatch := uint64(*flagMaxBatch)
	p := mpb.New()
	defer p.Shutdown()
	bar := p.AddBar(int64(maxBatch),
		mpb.PrependDecorators(
			decor.Name("batch"),
		),
		mpb.AppendDecorators(decor.Counters(0, "% d/% d")),
	)
	bar.IncrInt64(int64(*flagStartBatch))
	for batch := uint64(*flagStartBatch); batch < maxBatch; batch++ {
		var wg sync.WaitGroup
		wg.Add(numCPU)
		for i := 0; i < runtime.NumCPU(); i++ {
			idStart := perCpuIDs * uint64(i)
			idEnd := perCpuIDs * uint64(i+1)
			go batchCheckSeed(pubkey, batch, idStart, idEnd, &wg, ch)
		}
		wg.Wait()
		select {
		case <-ch:
			fmt.Println("task finished")
			os.Exit(1)
		default:
		}
		bar.Increment()
	}
	fmt.Println("max batch reached")
}

func batchCheckSeed(pubkey *ecdsa.PublicKey, batch uint64, idStart, idEnd uint64, wg *sync.WaitGroup, ch chan struct{}) {
	defer wg.Done()

	diffK := prosanity.GenDiffK(batch, idStart)
	dx, dy := curve.ScalarBaseMult(diffK)
	X, Y := curve.Add(pubkey.X, pubkey.Y, dx, dy.Neg(dy))
	for id := idStart; id <= idEnd; id++ {
		if seed, ok := pubkeySeedMap[X.Uint64()]; ok {
			if recoverPrivateKey(pubkey, seed, batch, id) {
				fmt.Println("Found private key components! seed:", seed, "batch:", batch, "id:", id)
				select {
				case <-ch:
				default:
					close(ch)
				}
				return
			}
		}
		X, Y = curve.Add(X, Y, idDiffX, idDiffY)
	}
}

func readSeedFiles() {
	seedBatchSize := prosanity.TotalSeedCount / 16
	var wg sync.WaitGroup
	processGroup := mpb.New(mpb.WithWaitGroup(&wg))
	wg.Add(*flagReadCount)
	for i := 0; i < *flagReadCount; i++ {
		start := (*flagReadStart + i) * seedBatchSize
		end := (*flagReadStart+i+1)*seedBatchSize - 1
		bar := processGroup.AddBar(int64(seedBatchSize),
			mpb.PrependDecorators(
				// simple name decorator
				decor.Name(fmt.Sprintf("seed-%08x-%08x.bin", start, end)),
			),
			mpb.AppendDecorators(
				// decor.DSyncWidth bit enables column width synchronization
				decor.Percentage(decor.WCSyncWidth),
			),
		)
		go readSeedFile(start, end, &wg, bar)
	}
	wg.Wait()
	processGroup.Shutdown()
}

func readSeedFile(start, end int, wg *sync.WaitGroup, bar *mpb.Bar) {
	defer wg.Done()

	seed := start
	filename := path.Join(*flagStoreDir, fmt.Sprintf("seed-%08x-%08x.bin", start, end))

	stat, err := os.Stat(filename)
	if err != nil {
		panic(err)
	}

	count := int64(end-start) + 1
	size := stat.Size()
	if size != count*8 {
		panic(fmt.Sprintf("%s file size is %d, expected %d", filename, size, count*8))
	}

	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	batchSize := 0x10000
	buf := make([]byte, batchSize*8)
	var n int
	for {
		n, err = f.Read(buf[:])
		if err != nil {
			if errors.Is(err, io.EOF) {
				if seed != end+1 {
					panic(filename + " is not reach ending")
				}
				return
			}
			panic(fmt.Sprintf("%s read error: %s", filename, err.Error()))
		}
		pubkeyMutex.Lock()
		for i := 0; i < n; i += 8 {
			pubKey := binary.BigEndian.Uint64(buf[i : i+8])
			pubkeySeedMap[pubKey] = uint32(seed)
			seed++
		}
		pubkeyMutex.Unlock()
		if seed%batchSize == 0 {
			bar.IncrInt64(int64(batchSize))
		}
	}
}

func recoverPrivateKey(targetPublicKey *ecdsa.PublicKey, seed uint32, batch, globalID uint64) bool {
	k := prosanity.PrivateKRecover(seed, batch, globalID)
	privateKey, err := crypto.ToECDSA(k)
	if err != nil {
		panic(err)
	}
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	targetAddress := crypto.PubkeyToAddress(*targetPublicKey)
	if address != targetAddress {
		return false
	}
	fmt.Println("recovered private key:", hexutil.Encode(k))
	fmt.Println("recovered address:", address)
	if *flagTelegramToken != "" && *flagTelegramChatID != "" {
		sendtelegram(fmt.Sprintf("address: %s\nprivate key: %s",
			crypto.PubkeyToAddress(privateKey.PublicKey),
			hexutil.Encode(k),
		))
	}
	return true
}

type ChatID string

func (id ChatID) Recipient() string {
	return string(id)
}

func sendtelegram(msg string) {
	tg, err := telebot.NewBot(telebot.Settings{
		Token: *flagTelegramToken,
	})
	if err != nil {
		fmt.Println("new bot error:", err)
		return
	}
	_, err = tg.Send(ChatID(*flagTelegramChatID), msg)
	if err != nil {
		fmt.Println("send telegram error:", err)
		return
	}
}
