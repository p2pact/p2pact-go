package p2pact

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// trainDict trains a zstd dictionary of up to size bytes: the content by fastCover, the
// algorithm of `zstd --train` (facebook/zstd, lib/dictBuilder/fastcover.c), its entropy tables
// by klauspost/compress over all samples. Like zstd, it tries several segment and d-mer sizes
// on train and keeps the content that compresses test best.
func trainDict(train, test [][]byte, size int) ([]byte, error) {
	if len(train) < 4 || len(test) < 2 {
		return nil, errors.New("too few samples")
	}
	samples := append(append([][]byte(nil), train...), test...)
	test = capBytes(test, 128<<10)
	var params [][2]int
	for _, d := range []int{6, 8} {
		for _, k := range []int{64, 128, 256, 512, 1024, 2000} {
			params = append(params, [2]int{d, k})
		}
	}
	// the tries are compared by their content alone; the tables are built for the best
	contents := make([][]byte, len(params))
	costs := make([]int, len(params))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, p := range params {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			contents[i] = coverContent(train, size, p[0], p[1])
			costs[i] = rawDictCost(contents[i], test)
		}()
	}
	wg.Wait()
	best := -1
	for i, c := range contents {
		if len(c) >= 8 && (best < 0 || costs[i] < costs[best]) {
			best = i
		}
	}
	if best < 0 {
		return nil, errors.New("no repeated content")
	}
	id := binary.BigEndian.Uint32(randBytes(4))%(1<<31-1<<15) + 1<<15 // not a reserved id
	return zstd.BuildDict(zstd.BuildDictOptions{ID: id, Contents: capBytes(samples, 256<<10),
		History: contents[best], Offsets: [3]int{1, 4, 8}, CompatV155: true})
}

// capBytes returns the first samples that fit in n bytes (at least one).
func capBytes(samples [][]byte, n int) [][]byte {
	for i, s := range samples {
		if n -= len(s); n < 0 {
			return samples[:max(i, 1)]
		}
	}
	return samples
}

// rawDictCost is how many bytes the samples take compressed with content as a dictionary.
func rawDictCost(content []byte, samples [][]byte) int {
	if len(content) < 8 {
		return 1 << 62
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderDictRaw(1, content), zstd.WithEncoderCRC(false),
		zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return 1 << 62
	}
	defer enc.Close()
	cost := 0
	var buf []byte
	for _, s := range samples {
		buf = enc.EncodeAll(s, buf[:0])
		cost += min(len(buf), len(s))
	}
	return cost
}

const coverHashLog = 20

// coverContent picks the dictionary content: the samples are cut into epochs, and from each in
// turn the segment of k bytes whose distinct d-mers are most frequent over all samples is
// taken; its d-mers then count zero, so the next segments bring something new. The best
// segments go last: the closer to the data, the cheaper a reference.
func coverContent(samples [][]byte, size, d, k int) []byte {
	var all []byte
	for _, s := range samples {
		all = append(all, s...)
	}
	if len(all) < d+k {
		return nil
	}
	all = append(all, make([]byte, 8)...)[:len(all)] // a d-mer near the end reads 8 bytes
	hash := func(p int) uint32 {
		v := binary.LittleEndian.Uint64(all[p : p+8 : p+8])
		if d == 6 {
			return uint32(((v << 16) * 227718039650203) >> (64 - coverHashLog))
		}
		return uint32((v * 0xCF1BBCDCB7A56463) >> (64 - coverHashLog))
	}
	// frequency of each d-mer over all samples (as zstd: none in a sample's last 8 bytes)
	freqs := make([]uint32, 1<<coverHashLog)
	at := 0
	for _, s := range samples {
		for p := 0; p+max(d, 8) <= len(s); p++ {
			freqs[hash(at+p)]++
		}
		at += len(s)
	}
	nbDmers := len(all) - d + 1
	// epochs, as zstd: about four passes over the dictionary, at least 10 segments per epoch
	num := max(1, size/k/4)
	esize := nbDmers / num
	if esize < 10*k {
		esize = min(10*k, nbDmers)
		num = nbDmers / esize
	}
	inSeg := make([]uint16, 1<<coverHashLog)
	dict := make([]byte, size)
	tail := size
	zeroRun := 0
	for epoch := 0; tail > 0; epoch = (epoch + 1) % num {
		begin := epoch * esize
		sb, se, score := coverSegment(hash, freqs, inSeg, begin, begin+esize, d, k)
		if score == 0 {
			if zeroRun++; zeroRun >= 10 {
				break
			}
			continue
		}
		zeroRun = 0
		n := min(se-sb+d-1, tail)
		if n < d {
			break
		}
		tail -= n
		copy(dict[tail:], all[sb:sb+n])
	}
	return dict[tail:]
}

// coverSegment slides a window of k bytes over [begin, end): its score is the sum of the
// frequencies of its distinct d-mers. It returns the best window trimmed of d-mers that count
// nothing, and zeroes the frequencies of what it took.
func coverSegment(hash func(int) uint32, freqs []uint32, inSeg []uint16, begin, end, d, k int) (int, int, uint64) {
	dmersInK := k - d + 1
	var bestB, bestE int
	var best, score uint64
	b, e := begin, begin
	for e < end {
		i := hash(e)
		if inSeg[i] == 0 {
			score += uint64(freqs[i])
		}
		inSeg[i]++
		e++
		if e-b == dmersInK+1 {
			j := hash(b)
			if inSeg[j]--; inSeg[j] == 0 {
				score -= uint64(freqs[j])
			}
			b++
		}
		if score > best {
			bestB, bestE, best = b, e, score
		}
	}
	for ; b < e; b++ {
		inSeg[hash(b)]--
	}
	if best == 0 {
		return 0, 0, 0
	}
	nb, ne := bestE, bestE
	for p := bestB; p < bestE; p++ {
		if freqs[hash(p)] != 0 {
			if nb == bestE {
				nb = p
			}
			ne = p + 1
		}
	}
	for p := nb; p < ne; p++ {
		freqs[hash(p)] = 0
	}
	return nb, ne, best
}
