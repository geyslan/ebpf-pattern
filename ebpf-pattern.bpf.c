// SPDX-License-Identifier: GPL-2.0
// Copyright 2021 Authors of KubeArmor

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "shared.h"

/* === */

struct pattern_block_key {
	char pattern_block[MAX_PATTERN_BLOCK_LEN];
};

struct pattern_block_value {
	u32 flags; /* (length << 24) | (kind << 16) | (u16) refcount */
	u32 index; /* limited to refcount (u16), it's u32 just for alignment */
};

struct pattern_key {
	u32 pidns;
	u32 mntns;
	u32 pattern_block_indexes[MAX_PATTERN_BLOCKS];
};

struct pattern_value {
	u16 flags;
};

/* current_task structure */
struct current_task {
	u32 pid_ns;
	u32 mnt_ns;
	u32 pid;
	u32 tid;

	char comm[TASK_COMM_LEN];

	char filename[MAX_FILENAME_LEN];
	u32  filename_hash;
};

/* === */

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

/* === */

#define get_dynamic_array(entry, field) \
	((void *) entry + (entry->__data_loc_##field & 0xffff))

/* task_get_host_pid returns current task host pid */
static u32
task_get_host_pid(void)
{
	return (u32) bpf_get_current_pid_tgid();
}

/* task_get_pid_ns returns current task pidns */
static u32
task_get_pid_ns(struct task_struct *task)
{
	if (!task)
		task = (struct task_struct *) bpf_get_current_task();

	return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns).inum;
}

/* task_get_mnt_ns returns current task mntns */
static u32
task_get_mnt_ns(struct task_struct *task)
{
	if (!task)
		task = (struct task_struct *) bpf_get_current_task();

	return BPF_CORE_READ(task, nsproxy, mnt_ns, ns).inum;
}

/* task_get_filename fills dst with task filename */
static long
task_get_filename(char *dst, size_t maxlen,
		  const struct trace_event_raw_sched_process_exec *ctx)
{
	if (!dst || !ctx || !maxlen)
		return -1;

	return bpf_core_read_str(dst, maxlen, get_dynamic_array(ctx, filename));
}

/* task_get_ids fills ctask with task ids */
static inline void
task_get_ids(struct current_task *ctask)
{
	if (!ctask)
		return;

	struct task_struct *task =
		(struct task_struct *) bpf_get_current_task();

	ctask->pid_ns = task_get_pid_ns(task);
	ctask->mnt_ns = task_get_mnt_ns(task);

	u64 id = bpf_get_current_pid_tgid();

	ctask->pid = id >> 32;
	ctask->tid = (u32) id;
}

/* callback_ctx struct is used as check_hash_elem handler input/output */
struct callback_ctx {
	const char *filename;
	struct pattern_value *pvalue;
};

/* check_hash_elem is the handler required by bpf_for_each_map_elem iterator */
static
u64 check_hash_elem(struct bpf_map *map,
		    struct pattern_key *key, struct pattern_value *val,
		    struct callback_ctx *data)
{
	if (!key || !val || !data)
		return 0;

	// if (match(key->pattern, data->filename)) {
	// 	data->pvalue->pattern_id = val->pattern_id;
	// 	return 1; // stop the iteration
	// }

	for (int i = 0; i < MAX_PATTERN_BLOCKS; i++)
		bpf_printk("block %u\n", key->pattern_block_indexes[i]);


	return 0;
}

/* task_auditable checks if task must be audited */
static bool
task_auditable(const struct current_task *ctask)
{
	if (!ctask)
		return false;

	/* pblocks = get_pattern_blocks(ctask->filename); */
/* 	for (int i = 0; i < MAX_PATTERN_BLOCKS; i++) {
		pbvalue = bpf_map_lookup_elem(&pattern_map, pblocks[i]);

		if (!pbvalue) {
			// 
		}
		// do stuff
	} */

	struct pattern_value pvalue = {
		.flags = 0,
	};
	struct callback_ctx data = {
		.filename = (const char *) &(ctask->filename),
		.pvalue	  = &pvalue,
	};

	// https://lwn.net/Articles/846504/
	long elem_num = bpf_for_each_map_elem(&pattern_map,
					      check_hash_elem, &data, 0);
	if (elem_num < 0)
		return false;

	//pattern_id = data.pvalue->pattern_id;

	return true;



	// struct pattern_key    pkey;
	// struct pattern_value *palue;

	// pkey.pidns

	// 	fnkey.hash = ctask->filename_hash;
	// fnvalue		   = bpf_map_lookup_elem(&ka_ea_filename_map, &fnkey);
	// if (!fnvalue)
	// 	return false;

	// struct process_spec_key pskey = {
	// 	.pid_ns	       = ctask->pid_ns,
	// 	.mnt_ns	       = ctask->mnt_ns,
	// 	.filename_hash = ctask->filename_hash,
	// };

	// return !!bpf_map_lookup_elem(&ka_ea_process_spec_map, &pskey);
}

/* === */

SEC("tp/sched/sched_process_exec")
int
sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct current_task ctask = {};

	if (task_get_filename(ctask.filename, sizeof(ctask.filename), ctx) < 0)
		return 0;

	// ctask.filename_hash = jenkins_hash(
	// 	ctask.filename, strnlen(ctask.filename, MAX_FILENAME_LEN), 0);
	// if (!ctask.filename_hash)
	// 	return 0;

	if (bpf_get_current_comm(&ctask.comm, sizeof(ctask.comm)) < 0)
		return 0;

	task_get_ids(&ctask);

	if (!task_auditable(&ctask))
		return 0;

	// if (task_set_for_audit(&ctask) < 0)
	// 	bpf_printk("[ka-ea-process]: failure setting %s (%u) for audit",
	// 		   ctask.filename, ctask.pid);
	// else
	// 	bpf_printk("[ka-ea-process]: %s (%u) set for audit",
	// 		   ctask.filename, ctask.pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
