// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "shared.h"

struct pattern_block_key {
	char pattern_block[MAX_PATTERN_BLOCK_LEN];
};

struct pattern_block_value {
	u32 mask; /* (length << 24) | (raw << 16) | (u16) ref_count */
	u16 index;
};

struct pattern_key {
	u32 pidns;
	u32 mntns;
	u16 pattern_block_indexes[MAX_PATTERN_BLOCKS];
};

struct pattern_value {
	u16 raw;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pattern_block_key);
	__type(value, struct pattern_block_value);
	__uint(max_entries, __UINT16_MAX__);
} pattern_block_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pattern_key);
	__type(value, struct pattern_value);
	__uint(max_entries, __UINT16_MAX__);
} pattern_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
