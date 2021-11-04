package main

// #cgo CFLAGS: -I${SRCDIR}/
// #include "shared.h"
import "C"

import (
	"fmt"
	"math"
	"os"
	"unsafe"

	lbpf "github.com/kubearmor/libbpf"
)

// PatternMaxLen constant
const PatternMaxLen = int(C.MAX_PATTERN_LEN)

// PatternElement Structure
type PatternElement struct {
	Key   PatternKey
	Value PatternValue
}

// PatternMapKey Structure
type PatternKey struct {
	Pattern [PatternMaxLen]byte
}

// PatternMapValue Structure
type PatternValue struct {
	Length     uint8
	Blocks     uint8
	StarsMask  uint64
	QMarksMask uint64
}

// SetKey Function (PatternElement)
func (pme *PatternElement) SetKey(pattern string) {
	copy(pme.Key.Pattern[:PatternMaxLen], pattern)
	pme.Key.Pattern[PatternMaxLen-1] = 0
}

// SetValue Function (PatternElement)
func (pme *PatternElement) SetValue(length, blocks uint8, starsMask, qmarksMask uint64) {
	pme.Value.Length = length
	pme.Value.Blocks = blocks
	pme.Value.StarsMask = starsMask
	pme.Value.QMarksMask = qmarksMask
}

// SetFoundValue Function (PatternElement)
func (pme *PatternElement) SetFoundValue(value []byte) {
	pme.Value.Length = value[0]
	pme.Value.Blocks = value[1]
	pme.Value.StarsMask = getInt(value[2:10])
	pme.Value.QMarksMask = getInt(value[10:18])
}

// KeyPointer Function (PatternElement)
func (pme *PatternElement) KeyPointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pme.Key)
}

// ValuePointer Function (PatternElement)
func (pme *PatternElement) ValuePointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pme.Value)
}

// MapName Function (PatternElement)
func (pme *PatternElement) MapName() string {
	return "pattern_map"
}

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

func CalculatePatternValue(pattern string) *PatternValue {
	patternLen := len(pattern)

	if patternLen > math.MaxUint8 || patternLen > int(C.MAX_PATTERN_LEN) {
		return nil
	}

	patternBlocks, patternStarsMask, patternQMarksMask := getPatternProperties(pattern)
	if patternBlocks == 0 {
		return nil
	}

	return &PatternValue{
		Length:     uint8(patternLen),
		Blocks:     uint8(patternBlocks),
		StarsMask:  uint64(patternStarsMask),
		QMarksMask: uint64(patternQMarksMask),
	}
}

func main() {
	var err error
	var o *lbpf.KABPFObject
	var m *lbpf.KABPFMap

	o, err = lbpf.OpenObjectFromFile("ebpf-pattern.bpf.o")
	ExitIfErr(err)

	err = o.Load()
	ExitIfErr(err)
	defer o.Close()

	m, err = o.FindMapByName("pattern_map")
	ExitIfErr(err)

	err = m.Pin("/sys/fs/bpf/" + m.Name())
	ExitIfErr(err)
	defer m.Unpin(m.Name())

	var patternElem PatternElement

	pattern := "/1****/2/////3????sh/4/5/6/7****///8/9????/10/11***/"

	var pv *PatternValue

	pv = CalculatePatternValue(pattern)

	patternElem.SetKey(pattern)
	patternElem.SetValue(pv.Length, pv.Blocks, pv.StarsMask, pv.QMarksMask)
	err = m.UpdateElement(&patternElem)
	ExitIfErr(err)

	for {
		//
	}
}
