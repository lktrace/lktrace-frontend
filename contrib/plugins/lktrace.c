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

/* per-vcpu saved info */
#define MAX_VCPU 32
static GArray *cpu_regs[MAX_VCPU];
static uint64_t saved_last_scause[MAX_VCPU];
static uint64_t saved_last_a0[MAX_VCPU];
static trace_event_t evts[MAX_VCPU];
static bool is_tracing_ecall[MAX_VCPU];
static bool is_tracing_sret[MAX_VCPU];

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
    RISCV_SATP = 79,
    RISCV_MSTATUS = 89,
};

enum {
    RISCV_EXCP_U_ECALL = 8,
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
    if (f) {
        fflush(f);
        funlockfile(f);
    }
}

static long lk_trace_head(FILE *f)
{
    long offset;

    if (f) {
        offset = ftell(f);
        fseek(f, sizeof(trace_event_t), SEEK_CUR);
        return offset;
    }
    return 0;
}

static void lk_trace_payload(uint16_t index, trace_event_t *evt,
                             const void *buf, size_t size, FILE *f)
{
    trace_payload_t p;

    if (f) {
        p.magic = LK_TRACE_PAYLOAD_MAGIC;
        p.index = index;
        p.size = size;

        fwrite(&p, sizeof(p), 1, f);
        fwrite(buf, 1, size, f);
        evt->totalsize += sizeof(p) + size;
    }
}

static void lk_trace_submit(long offset, const trace_event_t *evt, FILE *f)
{
    long saved_offset;

    if (f) {
        saved_offset = ftell(f);
        fseek(f, offset, SEEK_SET);
        fwrite(evt, sizeof(trace_event_t), 1, f);
        fseek(f, saved_offset, SEEK_SET);
    }
}

static struct qemu_plugin_register *
find_register_by_index(GArray *regs, size_t index)
{
    qemu_plugin_reg_descriptor *desc;

    desc = &g_array_index(regs, qemu_plugin_reg_descriptor, index);
    return desc->handle;
}

static uint64_t get_register_value_by_index(GArray *regs, size_t index)
{
    struct qemu_plugin_register *reg_handle;
    GByteArray *buf;
    int sz;
    uint64_t value;

    reg_handle = find_register_by_index(regs, index);
    buf = g_byte_array_new();
    sz = qemu_plugin_read_register(reg_handle, buf);
    g_assert(sz == 8);  /* rv64 isa */
    memcpy(&value, buf->data, sz);
    g_byte_array_free(buf, TRUE);
    return value;
}

static void read_memory_vaddr(uint64_t vaddr, uint8_t *data, size_t len)
{
    GByteArray *buf;
    size_t actual_len;

    buf = g_byte_array_new();
    if (qemu_plugin_read_memory_vaddr(vaddr, buf, len)) {
        actual_len = buf->len;
        g_assert(actual_len == len);
        memcpy(data, buf->data, actual_len);
    } else {
    }
}

static void formalize_str(uint8_t *data, size_t size)
{
    uint8_t *end;

    end = memchr(data, '\0', size);
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
    g_autofree uint8_t *data;

    data = g_try_malloc0(size * sizeof(uint8_t));
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
    uint64_t actual_write_size;

    if (evt->orig_a0 == 1 || evt->orig_a0 == 2) {
        actual_write_size = evt->ax[0] + 1;
        handle_string_at_heap(1, actual_write_size, evt, f);
    }
}

static void do_read_event(trace_event_t *evt, FILE *f)
{
    uint64_t actual_read_size;

    if (evt->orig_a0 == 0) {
        actual_read_size = evt->ax[0] + 1;
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
    size_t i;
    uint64_t priv = qemu_plugin_get_priv(vcpu_idx);
    trace_event_t *evt = &evts[vcpu_idx];

    if (priv != 0) return;

    lk_trace_init(evt);

    for (i = 0; i < 8; ++i) {
        evt->ax[i] = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_A0 + i);
    }
    evt->usp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SP);
    evt->tp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_TP);
    evt->satp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SATP);
    evt->sscratch = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SSCARTCH);
    evt->inout = 0;
    evt->cause = RISCV_EXCP_U_ECALL;
    evt->epc = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_PC);

    if (evt->ax[7] != __NR_exit) {
        saved_last_scause[vcpu_idx] = RISCV_EXCP_U_ECALL;
        saved_last_a0[vcpu_idx] = evt->ax[0];
    }

    is_tracing_ecall[vcpu_idx] = true;
}

static void insn_exec_sret_cb(unsigned int vcpu_idx, void *userdata)
{
    size_t i;
    uint64_t mstatus, prev_priv;
    trace_event_t *evt = &evts[vcpu_idx];

    mstatus = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_MSTATUS);
    prev_priv = get_field(mstatus, MSTATUS_SPP);
    if (prev_priv != 0 || !saved_last_scause[vcpu_idx]) {
        return;
    }

    lk_trace_init(evt);

    for (i = 0; i < 8; ++i) {
        evt->ax[i] = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_A0 + i);
    }
    evt->usp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SP);
    evt->tp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_TP);
    evt->satp = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SATP);
    evt->sscratch = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SSCARTCH);
    evt->inout = 1;
    evt->cause = saved_last_scause[vcpu_idx];
    evt->epc = get_register_value_by_index(cpu_regs[vcpu_idx], RISCV_SEPC);
    evt->orig_a0 = saved_last_a0[vcpu_idx];

    saved_last_scause[vcpu_idx] = 0;
    saved_last_a0[vcpu_idx] = 0;

    is_tracing_sret[vcpu_idx] = true;
}

static void insn_exec_general_cb(unsigned int vcpu_idx, void *userdata)
{
    FILE *f;
    long offset;
    trace_event_t *evt = &evts[vcpu_idx];

    /* There should only one event be tracing at the same time */
    g_assert(!(is_tracing_ecall[vcpu_idx]
            && is_tracing_sret[vcpu_idx]));

    if (is_tracing_ecall[vcpu_idx]) {
        f = lk_trace_trylock();
        offset = lk_trace_head(f);
        handle_payload_in(evt, f);
        lk_trace_submit(offset, evt, f);
        lk_trace_unlock(f);
    } else if (is_tracing_sret[vcpu_idx]) {
        f = lk_trace_trylock();
        offset = lk_trace_head(f);
        handle_payload_out(evt, f);
        lk_trace_submit(offset, evt, f);
        lk_trace_unlock(f);
    }

    is_tracing_ecall[vcpu_idx] = false;
    is_tracing_sret[vcpu_idx] = false;
}

/*
 * translation callback: scan TB for specific instruction
 * encodings and attach exec callbacks
 */
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t i;
    size_t n = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *insn;
    uint32_t insn_code;

    for (i = 0; i < n; ++i) {
        insn = qemu_plugin_tb_get_insn(tb, i);
        qemu_plugin_insn_data(insn, &insn_code, sizeof(insn_code));

        switch (insn_code) {
        case 0x00000073:  /* ecall */
            qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_ecall_cb,
                                                   QEMU_PLUGIN_CB_R_REGS, NULL);
            break;
        case 0x10200073:  /* sret */
            qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_sret_cb,
                                                   QEMU_PLUGIN_CB_R_REGS, NULL);
            break;
        default:
            qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_general_cb,
                                                   QEMU_PLUGIN_CB_R_REGS, NULL);
            break;
        }
    }
}

/* vcpu init callback: get register list */
static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_idx)
{
    cpu_regs[vcpu_idx] = qemu_plugin_get_registers();
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    size_t i;

    if (trace_file) {
        fclose(trace_file);
    }
    for (i = 0; i < MAX_VCPU; ++i) {
        if (cpu_regs[i] != NULL) {
            g_free(cpu_regs[i]);
        }
    }
}

/* qemu plugin entry */
QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id,
                    const qemu_info_t *info,
                    int argc, char *argv[])
{
    size_t i;
    const char *fn = getenv("LK_TRACE_FILE");
    if (!fn) {
        fn = trace_filename_default;
    }

    trace_file = fopen(fn, "w");
    if (!trace_file) {
        fprintf(stderr, "lktrace: failed to open %s\n", fn);
        return 0;
    }

    memset(saved_last_scause, 0, sizeof(saved_last_scause));
    memset(saved_last_a0, 0, sizeof(saved_last_a0));

    for (i = 0; i < MAX_VCPU; ++i) {
        is_tracing_ecall[i] = false;
        is_tracing_sret[i] = false;
    }

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
