package main

// #cgo CFLAGS: -I${SRCDIR}/
// #include "shared.h"
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	lbpf "github.com/kubearmor/libbpf"
)

// Constants
const (
	MaxPatternLen      = int(C.MAX_PATTERN_LEN)
	MaxPatternBlockLen = int(C.MAX_PATTERN_BLOCK_LEN)
	MaxPatternBlocks   = int(C.MAX_PATTERN_BLOCKS)
)

const (
	WildRawMask  uint8 = 0
	WildStarMask       = 1 << (iota - 1)
	WildQMarkMask
)

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
	Flags uint32
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
	PatternBlockOffsets [MaxPatternBlocks]uint16
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
func (pbe *PatternBlockElement) SetValue(flags uint32, index uint16) {
	pbe.Value.Flags = flags
	pbe.Value.Index = index
}

// SetFoundValue Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetFoundValue(value []byte) {
	pbe.Value.Flags = uint32(getInt(value[0:4]))
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

// maskPatternBlockFlags Function
func maskPatternBlockFlags(length uint8, pkind uint8, refCount uint16) uint32 {
	return (uint32(length) << 24) | (uint32(pkind) << 16) | uint32(refCount)
}

// getPatternBlockValue Function
func getPatternBlockValue(patternBlock string) (*PatternBlockValue, error) {
	if patternBlock == "" {
		return nil, errors.New("pattern block cannot be nil")
	}

	if len(patternBlock) > MaxPatternBlockLen-1 {
		return nil, fmt.Errorf("pattern block length must be less than %v", MaxPatternBlockLen)
	}

	var plen uint8
	var pkind uint8

	plen = uint8(len(patternBlock))
	pkind = WildRawMask

	if strings.Contains(patternBlock, "*") {
		pkind |= WildStarMask
	}
	if strings.Contains(patternBlock, "?") {
		pkind |= WildQMarkMask
	}

	return &PatternBlockValue{
		Flags: maskPatternBlockFlags(plen, pkind, 0),
		Index: 0,
	}, nil
}

// getInt Function
func getInt(s []byte) uint64 {
	var result uint64

	for _, b := range s {
		result <<= 8
		result |= uint64(b)
	}

	return result
}

// ExitIfErr Function
func ExitIfErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		runtime.Goexit()
	}
}

// getPatternBlocks Function
func getPatternBlocks(pattern string) ([]string, error) {
	if pattern == "" {
		return nil, errors.New("pattern cannot be nil")
	}

	if len(pattern) > MaxPatternLen-1 {
		return nil, fmt.Errorf("pattern length must be less than %v", MaxPatternLen)
	}

	var blockOffsets []int
	var prevByte byte
	var result []string

	if pattern[0] != '/' {
		blockOffsets = append(blockOffsets, 0)
	}

	for i := 0; i < len(pattern); i++ {
		if pattern[i] == prevByte {
			continue
		}
		if pattern[i] == '/' {
			blockOffsets = append(blockOffsets, i)
		}
	}
	blockOffsets = append(blockOffsets, len(pattern))

	for i := 0; i < len(blockOffsets)-1; i++ {
		begin := blockOffsets[i]
		end := blockOffsets[i+1]

		if (end - begin) > (MaxPatternBlockLen - 1) {
			return nil, fmt.Errorf("pattern block length must be less than %v", MaxPatternBlockLen)
		}

		result = append(result, pattern[begin:end])
	}

	return result, nil
}

// getPatternBlockElems Function
func getPatternBlockElems(patternBlocks []string) ([]PatternBlockElement, error) {
	if patternBlocks == nil {
		return nil, errors.New("patternBlocks cannot be nil")
	}

	var result []PatternBlockElement
	var err error

	for _, pb := range patternBlocks {
		var pbe PatternBlockElement
		var pbv *PatternBlockValue

		pbe.SetKey(pb)

		if pbv, err = getPatternBlockValue(pb); err != nil {
			return nil, err
		}

		pbe.Value = *pbv

		result = append(result, pbe)
	}

	return result, nil
}

// patternClean Function
func patternClean(pattern string) string {
	if pattern == "" {
		return ""
	}

	var result bytes.Buffer
	var prevByte byte

	// remove adjacent stars
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '*' && pattern[i] == prevByte {
			continue
		}
		prevByte = pattern[i]

		result.WriteByte(pattern[i])
	}

	return filepath.Clean(result.String())
}

// updatePatternBlockElement Function
func updatePatternBlockElement(pbmap *lbpf.KABPFMap, elem PatternBlockElement) error {
	return pbmap.UpdateElement(&elem)
}

func main() {
	var err error
	var o *lbpf.KABPFObject
	var pbmap *lbpf.KABPFMap

	defer os.Exit(0)

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

	dirtyPattern := "/2345678901/*****/bin////??sh/l?s*"
	cleanedPattern := patternClean(dirtyPattern)
	fmt.Println("---")
	fmt.Println("dirty pattern:  ", dirtyPattern)
	fmt.Println("cleaned pattern:", cleanedPattern)

	patternBlocks, err := getPatternBlocks(cleanedPattern)
	ExitIfErr(err)
	pbElems, err := getPatternBlockElems(patternBlocks)
	ExitIfErr(err)

	for i, pbe := range pbElems {
		pbe.Value.Index = uint16(i)
		err = updatePatternBlockElement(pbmap, pbe)
		ExitIfErr(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
	}()
	fmt.Printf("\n-> Read the maps from the tale\n")
	fmt.Printf("\n-> Caught Eru Ilúvatar %v!\n\n** Thanks for venturing into this design! **", <-c)
}
