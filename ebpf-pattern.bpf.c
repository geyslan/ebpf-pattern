// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "shared.h"

struct pattern_key {
	char pattern[MAX_PATTERN_LEN];
};

struct pattern_value {
	u8  length;
	u8  blocks;
	u64 stars;
	u64 qmarks;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct pattern_key);
	__type(value, struct pattern_value);
	__uint(max_entries, 1 << 10);
} pattern_map SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
