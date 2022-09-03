package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/SmithUnity/prosanity"
)

var storeDir = flag.String("dir", "seeds", "seed store directory")

func main() {
	flag.Parse()

	fmt.Println(os.Getwd())

	err := os.MkdirAll(*storeDir, 0755)
	if err != nil {
		panic(err)
	}
	cpuCount := 16

	start := time.Now()
	perCPUCount := prosanity.TotalSeedCount / cpuCount
	var wg sync.WaitGroup
	for i := 0; i < cpuCount; i++ {
		go genSeedPublicKeysPerCpu(i, i*perCPUCount, (i+1)*perCPUCount-1, &wg)
	}
	time.Sleep(time.Second)
	wg.Wait()
	fmt.Println("done", time.Since(start))
}

func genSeedPublicKeysPerCpu(cpuIndex, start, end int, wg *sync.WaitGroup) {
	wg.Add(1)

	seed := start
	filename := path.Join(*storeDir, fmt.Sprintf("seed-%08x-%08x.bin", start, end))

	stat, err := os.Stat(filename)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
	} else {
		size := stat.Size()
		if size%8 != 0 {
			panic(fmt.Sprint(filename, "file size is", size))
		}
		seed += int(size / 8)
	}

	f, err := os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	count := uint64(end - start)
	buf := make([]byte, 0, 0x10000*8)
	for ; seed <= end; seed++ {
		key := prosanity.PublicKeyFromSeed(uint32(seed))
		buf = binary.BigEndian.AppendUint64(buf, key)
		if seed%0x10000 == 0 {
			index := seed - start
			fmt.Printf("CPU%d %d/%d %d%%%%\n", cpuIndex, index, count, uint64(index)*1000/count)
			_, err = f.Write(buf[:])
			if err != nil {
				panic(err)
			}
			buf = buf[:0]
		}
	}
	_, err = f.Write(buf[:])
	if err != nil {
		panic(err)
	}
	wg.Done()
}
