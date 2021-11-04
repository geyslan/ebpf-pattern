package main

// #cgo CFLAGS: -I${SRCDIR}/
// #include "shared.h"
import "C"

import (
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	lbpf "github.com/kubearmor/libbpf"
)

// Constants
const MaxPatternLen = int(C.MAX_PATTERN_LEN)
const MaxPatternBlockLen = int(C.MAX_PATTERN_BLOCK_LEN)
const MaxPatternBlocks = int(C.MAX_PATTERN_BLOCKS)

// PatternBlockElement Structure
type PatternBlockElement struct {
	Key   PatternBlockKey
	Value PatternBlockValue
}

// PatternBlockKey Structure
type PatternBlockKey struct {
	PatternBlock [MaxPatternBlockLen]byte
}

// PatternBlockValue Structure
type PatternBlockValue struct {
	Mask  uint32
	Index uint16
}

// PatternElement Structure
type PatternElement struct {
	Key   PatternKey
	Value PatternValue
}

// PatternKey Structure
type PatternKey struct {
	PidNS               uint32
	MntNS               uint32
	PatternBlockIndexes [MaxPatternBlocks]uint16
}

// PatternValue Structure
type PatternValue struct {
	Raw uint16
}

// SetKey Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetKey(patternBlock string) {
	copy(pbe.Key.PatternBlock[:MaxPatternBlockLen], patternBlock)
	pbe.Key.PatternBlock[MaxPatternBlockLen-1] = 0
}

// SetValue Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetValue(mask uint32, index uint16) {
	pbe.Value.Mask = mask
	pbe.Value.Index = index
}

// SetFoundValue Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetFoundValue(value []byte) {
	pbe.Value.Mask = uint32(getInt(value[0:4]))
	pbe.Value.Index = uint16(getInt(value[4:6]))
}

// KeyPointer Function (PatternBlockElement)
func (pbe *PatternBlockElement) KeyPointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pbe.Key)
}

// ValuePointer Function (PatternBlockElement)
func (pbe *PatternBlockElement) ValuePointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pbe.Value)
}

// MapName Function (PatternBlockElement)
func (pbe *PatternBlockElement) MapName() string {
	return "pattern_block_map"
}

// // SetKey Function (PatternElement)
// func (pme *PatternElement) SetKey(pattern string) {
// 	copy(pme.Key.Pattern[:PatternMaxLen], pattern)
// 	pme.Key.Pattern[PatternMaxLen-1] = 0
// }

// // SetValue Function (PatternElement)
// func (pme *PatternElement) SetValue(length, blocks uint8, starsMask, qmarksMask uint64) {
// 	pme.Value.Length = length
// 	pme.Value.Blocks = blocks
// 	pme.Value.StarsMask = starsMask
// 	pme.Value.QMarksMask = qmarksMask
// }

// // SetFoundValue Function (PatternElement)
// func (pme *PatternElement) SetFoundValue(value []byte) {
// 	pme.Value.Length = value[0]
// 	pme.Value.Blocks = value[1]
// 	pme.Value.StarsMask = getInt(value[2:10])
// 	pme.Value.QMarksMask = getInt(value[10:18])
// }

// // KeyPointer Function (PatternElement)
// func (pme *PatternElement) KeyPointer() unsafe.Pointer {
// 	// #nosec
// 	return unsafe.Pointer(&pme.Key)
// }

// // ValuePointer Function (PatternElement)
// func (pme *PatternElement) ValuePointer() unsafe.Pointer {
// 	// #nosec
// 	return unsafe.Pointer(&pme.Value)
// }

// // MapName Function (PatternElement)
// func (pme *PatternElement) MapName() string {
// 	return "pattern_map"
// }

func getInt(s []byte) uint64 {
	var res uint64

	for _, b := range s {
		res <<= 8
		res |= uint64(b)
	}

	return res
}

func ExitIfErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getPatternProperties(pattern string) (blocks int, stars, qmarks uint64) {
	var lastRune rune

	if pattern == "" {
		return 0, 0, 0
	}

	if pattern[0] != '/' {
		blocks++
	}

	for _, s := range pattern {
		if s == lastRune {
			continue
		} else if s == '/' {
			blocks++
		} else if s == '*' {
			stars |= uint64(1 << (blocks - 1))
		} else if s == '?' {
			qmarks |= uint64(1 << (blocks - 1))
		}

		lastRune = s
	}

	if pattern[len(pattern)-1] == '/' {
		blocks--
	}

	if blocks > 64 {
		return 0, 0, 0
	}

	return blocks, stars, qmarks
}

func getPatternBlockKeys(pattern string) []PatternBlockKey {
	if pattern == "" {
		return nil
	}

	var blockIndexes []int
	var lastRune rune
	var result []PatternBlockKey

	if pattern[0] != '/' {
		blockIndexes = append(blockIndexes, 0)
	}

	for i, r := range pattern {
		if r == lastRune {
			continue
		}
		if r == '/' {
			blockIndexes = append(blockIndexes, i)
		}
	}

	if pattern[len(pattern)-1] != '/' {
		blockIndexes = append(blockIndexes, len(pattern))
	}

	for i := 0; i < len(blockIndexes)-1; i++ {
		var pbe PatternBlockElement
		begin := blockIndexes[i]
		end := blockIndexes[i+1]

		pbe.SetKey(pattern[begin:end])
		result = append(result, pbe.Key)
	}

	return result
}

func main() {
	var err error
	var o *lbpf.KABPFObject
	var pbmap *lbpf.KABPFMap

	o, err = lbpf.OpenObjectFromFile("ebpf-pattern.bpf.o")
	ExitIfErr(err)

	err = o.Load()
	ExitIfErr(err)
	defer o.Close()

	pbmap, err = o.FindMapByName("pattern_block_map")
	ExitIfErr(err)

	err = pbmap.Pin("/sys/fs/bpf/" + pbmap.Name())
	ExitIfErr(err)
	defer pbmap.Unpin(pbmap.PinPath())

	// pattern := "/1****/2/////3????sh/4/5/6/7****///8/9????/10/11***/"
	pattern := "/usr/bin/??sh"

	res := getPatternBlockKeys(pattern)

	for _, r := range res {
		var patternBlockElem PatternBlockElement

		patternBlockElem.Key = r
		err = pbmap.UpdateElement(&patternBlockElem)
		ExitIfErr(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
	}()
	fmt.Printf("\n-> Do the map tests\n")
	fmt.Printf("\n-> Caught sig %v!\n** Thanks for venturing into this design! **", <-c)
}
