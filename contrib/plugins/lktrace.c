/*
 * Copyright (C) 2024, Shi Lei <shi_lei@massclouds.com>
 * Copyright (C) 2025, Chaoqun Zheng <1667510710@qq.com>
 *
 * A VMI trace tool for analysing kernel.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define LK_TRACE_MAGIC 0xABCD
#define LK_TRACE_PAYLOAD_MAGIC 0xDCBA

#define __NR_getcwd     17
#define __NR_ioctl      29
#define __NR_unlinkat   35
#define __NR_faccessat  48
#define __NR_chdir      49
#define __NR_openat     56
#define __NR_read       63
#define __NR_write      64
#define __NR_writev     66
#define __NR_fstatat    79
#define __NR_fstat      80
#define __NR_exit       93
#define __NR_rt_sigaction 134
#define __NR_rt_sigprocmask 135

#define __NR_set_tid_address 96
#define __NR_set_robust_list 99

#define __NR_uname      160
#define __NR_brk        214
#define __NR_execve     221
#define __NR_mmap       222
#define __NR_mprotect   226
#define __NR_prlimit64  261
#define __NR_getrandom  278

typedef struct {
    uint16_t magic;
    uint16_t headsize;
    uint32_t totalsize;
    uint64_t inout;
    uint64_t cause;
    uint64_t epc;
    uint64_t tval;
    uint64_t cur_priv;
    uint64_t ax[8];
    uint64_t usp;
    uint64_t stack[8];
    uint64_t orig_a0;
    uint64_t satp;
    uint64_t tp;
    uint64_t sscratch;
} trace_event_t;

typedef struct {
    uint16_t magic;
    uint16_t index;
    uint32_t size;
} trace_payload_t;

/* tracing file */
static FILE *trace_file = NULL;
static const char *trace_filename_default = "lk_trace.data";

/*
 * tracing control flags
 * Default choice is tracing all.
 */
static bool trace_syscall = true;
static bool trace_pagefault = true;

/* per-vcpu saved info */
typedef struct {
    trace_event_t evt;
    GArray *cpu_regs;
    uint64_t saved_last_scause;
    uint64_t saved_last_sepc;
    uint64_t saved_last_a0;
    bool is_tracing_ecall;
    bool is_tracing_sret;
} vcpu_data_t;

static struct qemu_plugin_scoreboard *vcpu_scoreboard;

/* copy from QEMU's target/riscv/cpu_bits.h */
#define get_field(reg, mask) (((reg) & \
                 (uint64_t)(mask)) / ((mask) & ~((mask) << 1)))
#define set_field(reg, mask, val) (((reg) & ~(uint64_t)(mask)) | \
                 (((uint64_t)(val) * ((mask) & ~((mask) << 1))) & \
                 (uint64_t)(mask)))
#define MSTATUS_SPP         0x00000100

/* RISC-V ABI */
enum {
    RISCV_SP = 2,
    RISCV_TP = 4,
    RISCV_A0 = 10,
    /* A1 ~ A7 : 11 ~ 17 */
    RISCV_PC = 32,
    RISCV_SSCARTCH = 74,
    RISCV_SEPC = 75,
    RISCV_SCAUSE = 76,
    RISCV_STVAL = 77,
    RISCV_SATP = 79,
    RISCV_MSTATUS = 89,
};

enum {
    RISCV_EXCP_U_ECALL = 8,
    RISCV_EXCP_INST_PAGE_FAULT = 0xc,
    RISCV_EXCP_LOAD_PAGE_FAULT = 0xd,
    RISCV_EXCP_STORE_PAGE_FAULT = 0xf,
};

static void lk_trace_init(trace_event_t *evt)
{
    memset(evt, 0, sizeof(trace_event_t));
    evt->magic = LK_TRACE_MAGIC;
    evt->headsize = sizeof(trace_event_t);
    evt->totalsize = evt->headsize;
}

static FILE *lk_trace_trylock(void)
{
    g_assert(trace_file != NULL);
    flockfile(trace_file);
    return trace_file;
}

static void lk_trace_unlock(FILE *f)
{
    if (!f) {
        return;
    }
    fflush(f);
    funlockfile(f);
}

static long lk_trace_head(FILE *f)
{
    if (!f) {
        return 0;
    }
    long offset = ftell(f);
    fseek(f, sizeof(trace_event_t), SEEK_CUR);
    return offset;
}

static void lk_trace_payload(uint16_t index, trace_event_t *evt,
                             const void *buf, size_t size, FILE *f)
{
    if (!f) {
        return;
    }
    trace_payload_t p;
    p.magic = LK_TRACE_PAYLOAD_MAGIC;
    p.index = index;
    p.size = size;

    fwrite(&p, sizeof(p), 1, f);
    fwrite(buf, 1, size, f);
    evt->totalsize += sizeof(p) + size;
}

static void lk_trace_submit(long offset, const trace_event_t *evt, FILE *f)
{
    if (!f) {
        return;
    }
    long saved_offset = ftell(f);
    fseek(f, offset, SEEK_SET);
    fwrite(evt, sizeof(trace_event_t), 1, f);
    fseek(f, saved_offset, SEEK_SET);
}

static struct qemu_plugin_register *
find_register_by_index(GArray *regs, size_t index)
{
    qemu_plugin_reg_descriptor *desc = &g_array_index(
                            regs, qemu_plugin_reg_descriptor, index);
    return desc->handle;
}

static uint64_t get_register_value_by_index(GArray *regs, size_t index)
{
    struct qemu_plugin_register *reg_handle = find_register_by_index(regs, index);
    GByteArray *buf = g_byte_array_new();
    int sz = qemu_plugin_read_register(reg_handle, buf);
    uint64_t value;

    g_assert(sz == 8);  /* rv64 isa */
    memcpy(&value, buf->data, sz);
    g_byte_array_free(buf, TRUE);
    return value;
}

static void read_memory_vaddr(uint64_t vaddr, uint8_t *data, size_t len)
{
    GByteArray *buf = g_byte_array_new();

    if (qemu_plugin_read_memory_vaddr(vaddr, buf, len)) {
        size_t actual_len = buf->len;
        g_assert(actual_len == len);
        memcpy(data, buf->data, actual_len);
    }
}

static void formalize_str(uint8_t *data, size_t size)
{
    uint8_t *end = memchr(data, '\0', size);

    if (end == NULL) {
        end = data + size;
        end[-1] = '\0';
    }
}

static void handle_path(int index, trace_event_t *evt, FILE *f)
{
    uint8_t data[64];

    if (index == 0 && evt->inout == 1) {
        read_memory_vaddr(evt->orig_a0, data, sizeof(data));
    } else {
        read_memory_vaddr(evt->ax[index], data, sizeof(data));
    }
    formalize_str(data, sizeof(data));
    lk_trace_payload(index, evt, data, sizeof(data), f);
}

static void do_openat(trace_event_t *evt, FILE *f)
{
    handle_path(1, evt, f);
}

static void do_faccessat(trace_event_t *evt, FILE *f)
{
    handle_path(1, evt, f);
}

static void do_fstatat_out(trace_event_t *evt, FILE *f)
{
    /* sizeof(struct stat) = 128 bytes */
    uint8_t data[128];

    if (evt->ax[0] == 0) {
        read_memory_vaddr(evt->ax[2], data, sizeof(data));
        lk_trace_payload(2, evt, data, sizeof(data), f);
    }
}

static void do_fstat_out(trace_event_t *evt, FILE *f)
{
    uint8_t data[128];

    if (evt->ax[0] == 0) {
        read_memory_vaddr(evt->ax[1], data, sizeof(data));
        lk_trace_payload(1, evt, data, sizeof(data), f);
    }
}

static void do_uname(trace_event_t *evt, FILE *f)
{
    /* sizeof(struct new_utsname) = 390, 8-bytes-alignment */
    uint8_t data[392];

    if (evt->ax[0] == 0) {
        read_memory_vaddr(evt->orig_a0, data, sizeof(data));
        lk_trace_payload(0, evt, data, sizeof(data), f);
    }
}

static void handle_string_at_heap(int index, uint64_t size,
                                  trace_event_t *evt, FILE *f)
{
    g_autofree uint8_t *data = g_try_malloc0(size * sizeof(uint8_t));
    if (data == NULL) {
        fprintf(stderr, "lktrace: g_try_malloc0 failed\n");
        return;
    }

    read_memory_vaddr(evt->ax[1], data, sizeof(uint8_t) * size);
    formalize_str(data, sizeof(uint8_t) * size);
    lk_trace_payload(index, evt, data, sizeof(uint8_t) * size, f);
}

static void do_write_event(trace_event_t *evt, FILE *f)
{
    if (evt->orig_a0 == 1 || evt->orig_a0 == 2) {
        uint64_t actual_write_size = evt->ax[0] + 1;
        handle_string_at_heap(1, actual_write_size, evt, f);
    }
}

static void do_read_event(trace_event_t *evt, FILE *f)
{
    if (evt->orig_a0 == 0) {
        uint64_t actual_read_size = evt->ax[0] + 1;
        handle_string_at_heap(1, actual_read_size, evt, f);
    }
}

static void do_execve(trace_event_t *evt, FILE *f)
{
    uint8_t data[64]; /* just reserve 64 bytes */
    char *const argv;
    char *const envp;
    uint64_t argc = 0;
    uint64_t envc = 0;

    handle_path(0, evt, f);

    read_memory_vaddr(evt->ax[1], (uint8_t *)&argv, sizeof(char *));
    while (argv != NULL) {
        argc += 1;
        read_memory_vaddr((uint64_t)argv, data, sizeof(data));
        formalize_str(data, sizeof(data));
        lk_trace_payload(1, evt, data, sizeof(data), f);
        read_memory_vaddr(evt->ax[1] + argc * sizeof(char *),
                          (uint8_t *)&argv, sizeof(char *));
    }

    read_memory_vaddr(evt->ax[2], (uint8_t *)&envp, sizeof(char *));
    while (envp != NULL) {
        envc += 1;
        read_memory_vaddr((uint64_t)envp, data, sizeof(data));
        formalize_str(data, sizeof(data));
        lk_trace_payload(2, evt, data, sizeof(data), f);
        read_memory_vaddr(evt->ax[2] + envc * sizeof(char *),
                          (uint8_t *)&envp, sizeof(char *));
    }
}

static void do_rt_sigaction(trace_event_t *evt, FILE *f)
{
    uint8_t data[24];

    if (evt->ax[0] == 0) {
        if (evt->ax[1] != 0) {
            read_memory_vaddr(evt->ax[1], data, sizeof(data));
            lk_trace_payload(1, evt, data, sizeof(data), f);
        }
    }
}

static void do_rt_sigprocmask(trace_event_t *evt, FILE *f)
{
    uint64_t data;

    if (evt->ax[0] == 0) {
        if (evt->ax[1] != 0) {
            read_memory_vaddr(evt->ax[1], (uint8_t *)&data, sizeof(data));
            lk_trace_payload(1, evt, &data, sizeof(data), f);
        }
        if (evt->ax[2] != 0) {
            read_memory_vaddr(evt->ax[2], (uint8_t *)&data, sizeof(data));
            lk_trace_payload(2, evt, &data, sizeof(data), f);
        }
    }
}

static void handle_payload_in(trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7]) {
    case __NR_execve:
        do_execve(evt, f);
        break;
    default:
        break;
    }
}

static void handle_payload_out(trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7]) {
    case __NR_openat:
        do_openat(evt, f);
        break;
    case __NR_uname:
        do_uname(evt, f);
        break;
    case __NR_faccessat:
        do_faccessat(evt, f);
        break;
    case __NR_read:
        do_read_event(evt, f);
        break;
    case __NR_write:
        do_write_event(evt, f);
        break;
    case __NR_rt_sigaction:
        do_rt_sigaction(evt, f);
        break;
    case __NR_rt_sigprocmask:
        do_rt_sigprocmask(evt, f);
        break;
    case __NR_unlinkat:
        handle_path(1, evt, f);
        break;
    case __NR_fstatat:
        handle_path(1, evt, f);
        do_fstatat_out(evt, f);
        break;
    case __NR_fstat:
        do_fstat_out(evt, f);
        break;
    case __NR_getcwd:
        handle_path(0, evt, f);
        break;
    case __NR_chdir:
        handle_path(0, evt, f);
        break;
    default:
        break;
    }
}

static void insn_exec_ecall_cb(unsigned int vcpu_idx, void *userdata)
{
    uint64_t priv = qemu_plugin_get_priv(vcpu_idx);
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);

    if (priv != 0) return;

    lk_trace_init(&data->evt);

    for (size_t i = 0; i < 8; ++i) {
        data->evt.ax[i] = get_register_value_by_index(data->cpu_regs, RISCV_A0 + i);
    }
    data->evt.usp = get_register_value_by_index(data->cpu_regs, RISCV_SP);
    data->evt.tp = get_register_value_by_index(data->cpu_regs, RISCV_TP);
    data->evt.satp = get_register_value_by_index(data->cpu_regs, RISCV_SATP);
    data->evt.sscratch = get_register_value_by_index(data->cpu_regs, RISCV_SSCARTCH);
    data->evt.inout = 0;
    data->evt.cause = RISCV_EXCP_U_ECALL;
    data->evt.epc = get_register_value_by_index(data->cpu_regs, RISCV_PC);

    if (data->evt.ax[7] != __NR_exit) {
        data->saved_last_scause = RISCV_EXCP_U_ECALL;
        data->saved_last_a0 = data->evt.ax[0];
    }

    FILE *f = lk_trace_trylock();
    long offset = lk_trace_head(f);
    handle_payload_in(&data->evt, f);
    lk_trace_submit(offset, &data->evt, f);
    lk_trace_unlock(f);

    data->is_tracing_ecall = true;
}

static void insn_exec_sret_cb(unsigned int vcpu_idx, void *userdata)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);
    uint64_t mstatus = get_register_value_by_index(data->cpu_regs, RISCV_MSTATUS);
    uint64_t prev_priv = get_field(mstatus, MSTATUS_SPP);
    if (prev_priv != 0 || !data->saved_last_scause) {
        return;
    }

    lk_trace_init(&data->evt);

    for (size_t i = 0; i < 8; ++i) {
        data->evt.ax[i] = get_register_value_by_index(data->cpu_regs, RISCV_A0 + i);
    }
    data->evt.usp = get_register_value_by_index(data->cpu_regs, RISCV_SP);
    data->evt.tp = get_register_value_by_index(data->cpu_regs, RISCV_TP);
    data->evt.satp = get_register_value_by_index(data->cpu_regs, RISCV_SATP);
    data->evt.sscratch = get_register_value_by_index(data->cpu_regs, RISCV_SSCARTCH);
    data->evt.inout = 1;
    data->evt.cause = data->saved_last_scause;
    data->evt.epc = get_register_value_by_index(data->cpu_regs, RISCV_SEPC);
    data->evt.orig_a0 = data->saved_last_a0;

    data->saved_last_scause = 0;
    data->saved_last_a0 = 0;

    data->is_tracing_sret = true;
}

static void insn_exec_general_cb(unsigned int vcpu_idx, void *userdata)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);

    /* There should only one event being traced at the same time */
    g_assert(!(data->is_tracing_ecall
            && data->is_tracing_sret));

    if (data->is_tracing_ecall) {
        /* 
         * Nothing to do:
         * the content read for `handle_payload_in` is
         * done in the insn_exec callback.
         */
        data->is_tracing_ecall = false;
    } else if (data->is_tracing_sret) {
        FILE *f = lk_trace_trylock();
        long offset = lk_trace_head(f);
        handle_payload_out(&data->evt, f);
        lk_trace_submit(offset, &data->evt, f);
        lk_trace_unlock(f);
        data->is_tracing_sret = false;
    }
}

static void vcpu_mem_rw_cb(unsigned int vcpu_idx, qemu_plugin_meminfo_t info,
                          uint64_t vaddr, void *userdata)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);

    uint64_t sepc = get_register_value_by_index(data->cpu_regs, RISCV_SEPC);
    /* Each page fault only be printed once. */
    if (data->saved_last_sepc == sepc) {
        return;
    }

    uint64_t scause = get_register_value_by_index(data->cpu_regs, RISCV_SCAUSE);
    if (scause == RISCV_EXCP_INST_PAGE_FAULT ||
        scause == RISCV_EXCP_LOAD_PAGE_FAULT ||
        scause == RISCV_EXCP_STORE_PAGE_FAULT)
    {
        lk_trace_init(&data->evt);
        data->evt.epc = sepc;
        data->evt.cause = scause;
        data->evt.tval = get_register_value_by_index(data->cpu_regs, RISCV_STVAL);
        data->evt.cur_priv = qemu_plugin_get_priv(vcpu_idx);
        FILE *f = lk_trace_trylock();
        long offset = lk_trace_head(f);
        lk_trace_submit(offset, &data->evt, f);
        lk_trace_unlock(f);

        data->saved_last_sepc = sepc;
    }
}

/*
 * translation callback: scan TB for specific instruction
 * encodings and attach exec callbacks
 */
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < n; ++i) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint32_t insn_code;
        qemu_plugin_insn_data(insn, &insn_code, sizeof(insn_code));

        switch (insn_code) {
        case 0x00000073:  /* ecall */
            if (trace_syscall) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_ecall_cb,
                                                       QEMU_PLUGIN_CB_R_REGS, NULL);
            }
            break;
        case 0x10200073:  /* sret */
            if (trace_syscall) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_sret_cb,
                                                       QEMU_PLUGIN_CB_R_REGS, NULL);
            }
            break;
        default:
            qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_general_cb,
                                                   QEMU_PLUGIN_CB_R_REGS, NULL);
            break;
        }

        /* Register memory access callback to trace page fault */
        if (trace_pagefault) {
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_rw_cb,
                                             QEMU_PLUGIN_CB_R_REGS,
                                             QEMU_PLUGIN_MEM_RW, NULL);
        }
    }
}

/* vcpu init callback: get register list */
static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_idx)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);
    data->cpu_regs = qemu_plugin_get_registers();
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (trace_file) {
        fclose(trace_file);
    }
    qemu_plugin_scoreboard_free(vcpu_scoreboard);
}

/* qemu plugin entry */
QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id,
                    const qemu_info_t *info,
                    int argc, char *argv[])
{
    char *fn = g_strdup(trace_filename_default);
    int opt_errors = 0;

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strv_length(tokens) != 2) {
            fprintf(stderr, "Invalid parameter format: %s\n", opt);
            fprintf(stderr, "Expected: name=value\n");
            opt_errors++;
            continue;
        }

        char *name = tokens[0];
        char *value = tokens[1];

        if (g_strcmp0(name, "trace-syscall") == 0) {
            if (!qemu_plugin_bool_parse(name, value, &trace_syscall)) {
                fprintf(stderr, "Boolean parsing failed for %s\n", opt);
                opt_errors++;
            }
        } else if (g_strcmp0(name, "trace-pagefault") == 0) {
            if (!qemu_plugin_bool_parse(name, value, &trace_pagefault)) {
                fprintf(stderr, "Boolean parsing failed for %s\n", opt);
                opt_errors++;
            }
        } else if (g_strcmp0(name, "log-file") == 0) {
            g_free(fn);
            fn = g_strdup(value);
        } else {
            fprintf(stderr, "Unknown parameter: %s\n", name);
            opt_errors++;
        }
    }

    trace_file = fopen(fn, "w");
    if (!trace_file) {
        fprintf(stderr, "lktrace: failed to open %s\n", fn);
        return 0;
    }

    vcpu_scoreboard = qemu_plugin_scoreboard_new(sizeof(vcpu_data_t));

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return opt_errors;
}
