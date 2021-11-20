package main

// #cgo CFLAGS: -I${SRCDIR}/
// #include "shared.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
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

var (
	patternBlockIndex uint32
)

// PatternBlockMap [patternBlock]index
var PatternBlockMap map[string]uint32

// ---

// PatternBlockElement Structure
type PatternBlockElement struct {
	Key   PatternBlockKey
	Value PatternBlockValue
}

// PatternBlockKey Structure
type PatternBlockKey struct {
	Index uint32
}

// PatternBlockValue Structure
type PatternBlockValue struct {
	PatternBlock [MaxPatternBlockLen]byte
	Flags        uint32
}

// SetKey Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetKey(index uint32) {
	pbe.Key.Index = index
}

// SetValue Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetValue(patternBlock string, flags uint32) {
	pbe.Value.PatternBlock = getPatternBlock(patternBlock)
	pbe.Value.Flags = flags
}

// SetFoundValue Function (PatternBlockElement)
func (pbe *PatternBlockElement) SetFoundValue(value []byte) {
	pbe.Value.PatternBlock = getPatternBlock(string(value[0:MaxPatternBlockLen]))
	pbe.Value.Flags = binary.LittleEndian.Uint32(value[MaxPatternBlockLen : MaxPatternBlockLen+4])
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

// ---- PatternElement ----

// PatternElement Structure
type PatternElement struct {
	Key   PatternKey
	Value PatternValue
}

// PatternKey Structure
type PatternKey struct {
	PidNS               uint32
	MntNS               uint32
	PatternBlockIndexes [MaxPatternBlocks]uint32
}

// PatternValue Structure
type PatternValue struct {
	Flags uint16
}

// SetKey Function (PatternElement)
func (pe *PatternElement) SetKey(pidNS, mntNS uint32, blockOffsets [MaxPatternBlocks]uint32) {
	pe.Key.PidNS = pidNS
	pe.Key.MntNS = mntNS
	pe.Key.PatternBlockIndexes = blockOffsets
}

// SetValue Function (PatternElement)
func (pe *PatternElement) SetValue(flags uint16) {
	pe.Value.Flags = flags
}

// SetFoundValue Function (PatternElement)
func (pe *PatternElement) SetFoundValue(value []byte) {
	pe.Value.Flags = binary.LittleEndian.Uint16(value)
}

// KeyPointer Function (PatternElement)
func (pe *PatternElement) KeyPointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pe.Key)
}

// ValuePointer Function (PatternElement)
func (pe *PatternElement) ValuePointer() unsafe.Pointer {
	// #nosec
	return unsafe.Pointer(&pe.Value)
}

// MapName Function (PatternElement)
func (pe *PatternElement) MapName() string {
	return "pattern_map"
}

// getPatternBlockFlags Function
func getPatternBlockFlags(length uint8, kind uint8, refCount uint16) uint32 {
	return (uint32(length) << 24) | (uint32(kind) << 16) | uint32(refCount)
}

func getPatternBlockRefCountFlag(flags uint32) uint16 {
	return uint16(flags)
}

func incPatternBlockRefCountFlag(flags uint32) (uint32, error) {
	if getPatternBlockRefCountFlag(flags) == math.MaxUint16 {
		return math.MaxUint16, fmt.Errorf("max reference count: %v", math.MaxUint16)
	}

	return flags + 1, nil
}

func decPatternBlockRefCountFlag(flags uint32) (uint32, error) {
	if getPatternBlockRefCountFlag(flags) == 0 {
		return 0, errors.New("min reference count: 0")
	}

	return flags - 1, nil
}

func getPatternBlock(patternBlock string) [MaxPatternBlockLen]byte {
	var pb [MaxPatternBlockLen]byte

	copy(pb[:MaxPatternBlockLen], patternBlock)
	pb[MaxPatternBlockLen-1] = 0

	return pb
}

// calcPatternBlockValue Function
func calcPatternBlockValue(patternBlock string) (*PatternBlockValue, error) {
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
		PatternBlock: getPatternBlock(patternBlock),
		Flags:        getPatternBlockFlags(plen, pkind, 1),
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
		fmt.Fprintln(os.Stderr, "ERROR:", err.Error())
		fmt.Fprintf(os.Stderr, "\n- Instead of throwing the ring, you threw yourself into the Mount Doom.")
		fmt.Fprintf(os.Stderr, "\n- If you are a Maiar, try again.\n")
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

// buildAndUpdatePatternBlockElems Function
func buildAndUpdatePatternBlockElems(pbmap *lbpf.KABPFMap, pBlocks []string) ([]PatternBlockElement, error) {
	if pBlocks == nil {
		return nil, errors.New("pBlocks cannot be nil")
	}

	var result []PatternBlockElement
	var val []byte
	var err error

	if PatternBlockMap == nil {
		PatternBlockMap = make(map[string]uint32)
	}

	for _, pb := range pBlocks {
		var pbe PatternBlockElement
		var pbv *PatternBlockValue

		if index, found := PatternBlockMap[pb]; found {
			pbe.Key.Index = index
			val, _ = pbmap.LookupElement(&pbe)
			if val != nil {
				flags, err := incPatternBlockRefCountFlag(pbe.Value.Flags)
				ExitIfErr(err)
				pbe.Value.Flags = flags

				err = updatePatternBlockElement(pbmap, pbe)
				ExitIfErr(err)
			}
		} else {
			if pbv, err = calcPatternBlockValue(pb); err != nil {
				return nil, err
			}
			pbe.Key.Index = getPatternBlockAvailableIndex()
			pbe.Value = *pbv

			err = updatePatternBlockElement(pbmap, pbe)
			ExitIfErr(err)
			incPatternBlockAvailableIndex()

			PatternBlockMap[pb] = pbe.Key.Index
		}

		result = append(result, pbe)
	}

	return result, nil
}

func buildAndUpdatePatternElem(pmap *lbpf.KABPFMap, pBlocksElems []PatternBlockElement) (*PatternElement, error) {
	if pBlocksElems == nil {
		return nil, errors.New("pBlocksElems cannot be nil")
	}

	if len(pBlocksElems) > MaxPatternBlocks {
		return nil, fmt.Errorf("pattern must has up to %v blocks", MaxPatternBlocks)
	}

	var pe PatternElement
	var err error

	output, _ := exec.Command("readlink", "/proc/self/ns/pid").Output()
	fmt.Sscanf(string(output), "pid:[%d]\n", &pe.Key.PidNS)
	output, _ = exec.Command("readlink", "/proc/self/ns/mnt").Output()
	fmt.Sscanf(string(output), "mnt:[%d]\n", &pe.Key.MntNS)

	for i, pbe := range pBlocksElems {
		pe.Key.PatternBlockIndexes[i] = pbe.Key.Index
	}

	pe.Value.Flags = uint16(len(pBlocksElems))

	if err = pmap.UpdateElement(&pe); err != nil {
		return nil, err
	}

	return &pe, nil
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

// getPatternBlockAvailableIndex Function
func getPatternBlockAvailableIndex() uint32 {
	return patternBlockIndex + 1
}

// incPatternBlockAvailableIndex Function
func incPatternBlockAvailableIndex() {
	patternBlockIndex++
}

func insertPattern(pbmap, pmap *lbpf.KABPFMap, pattern string) {
	cleanedPattern := patternClean(pattern)
	fmt.Println("---")
	fmt.Println("dirty pattern:  ", pattern)
	fmt.Println("cleaned pattern:", cleanedPattern)
	fmt.Println("---")

	pBlocks, err := getPatternBlocks(cleanedPattern)
	ExitIfErr(err)
	pbElems, err := buildAndUpdatePatternBlockElems(pbmap, pBlocks)
	ExitIfErr(err)

	_, err = buildAndUpdatePatternElem(pmap, pbElems)
	ExitIfErr(err)
}

func main() {
	var err error
	var o *lbpf.KABPFObject
	var pbmap *lbpf.KABPFMap
	var pmap *lbpf.KABPFMap
	var prog *lbpf.KABPFProgram

	defer os.Exit(0)

	o, err = lbpf.OpenObjectFromFile("ebpf-pattern.bpf.o")
	ExitIfErr(err)

	err = o.Load()
	ExitIfErr(err)
	defer o.Close()

	prog, err = o.FindProgramByName("sched_process_exec")
	ExitIfErr(err)

	_, err = prog.AttachTracepoint("sched", "sched_process_exec")
	ExitIfErr(err)

	pbmap, err = o.FindMapByName("pattern_block_map")
	ExitIfErr(err)

	err = pbmap.Pin("/sys/fs/bpf/" + pbmap.Name())
	ExitIfErr(err)
	defer pbmap.Unpin(pbmap.PinPath())

	pmap, err = o.FindMapByName("pattern_map")
	ExitIfErr(err)

	err = pmap.Pin("/sys/fs/bpf/" + pmap.Name())
	ExitIfErr(err)
	defer pmap.Unpin(pmap.PinPath())

	insertPattern(pbmap, pmap, "/???/bin///**sh")
	insertPattern(pbmap, pmap, "////***r/bin/??sh")
	insertPattern(pbmap, pmap, "////???/??n/ls")
	//insertPattern(pbmap, pmap, "/1/2/3/4/5/6/7/8/9/0/1/2")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
	}()
	fmt.Printf("\n- Sam, don't you think we should check some map?\n")
	fmt.Printf("\n- Caught Eru Ilúvatar %v!\n\n** Thanks for venturing into this design! **", <-c)
}
