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
#include <lktrace.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* tracing file */
static FILE *trace_file = NULL;
static const char *trace_filename_default = "lk_trace.data";

/*
 * tracing control flags
 * Default choice is tracing all.
 */
static bool trace_syscall = true;
static bool trace_pagefault = true;

/*
 * global debug info
 * FIXME: May be not accurate when smp > 1.
 */
static char *cur_insn_disas = NULL;
static int cur_syscall_id = -1;

static struct qemu_plugin_scoreboard *vcpu_scoreboard;

void lk_trace_init(trace_event_t *evt)
{
    memset(evt, 0, sizeof(trace_event_t));
    evt->magic = LK_TRACE_MAGIC;
    evt->headsize = sizeof(trace_event_t);
    evt->totalsize = evt->headsize;
}

FILE *lk_trace_trylock(void)
{
    g_assert(trace_file != NULL);
    flockfile(trace_file);
    return trace_file;
}

void lk_trace_unlock(FILE *f)
{
    if (!f) {
        return;
    }
    fflush(f);
    funlockfile(f);
}

long lk_trace_head(FILE *f)
{
    if (!f) {
        return 0;
    }
    long offset = ftell(f);
    fseek(f, sizeof(trace_event_t), SEEK_CUR);
    return offset;
}

void lk_trace_payload(uint16_t index, trace_event_t *evt,
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

void lk_trace_submit(long offset, const trace_event_t *evt, FILE *f)
{
    if (!f) {
        return;
    }
    long saved_offset = ftell(f);
    fseek(f, offset, SEEK_SET);
    fwrite(evt, sizeof(trace_event_t), 1, f);
    fseek(f, saved_offset, SEEK_SET);
}

uint64_t get_register_value_by_index(GArray *regs, size_t index)
{
    qemu_plugin_reg_descriptor *desc = &g_array_index(
                        regs, qemu_plugin_reg_descriptor, index);
    struct qemu_plugin_register *reg_handle = desc->handle;
    GByteArray *buf = g_byte_array_new();
    int sz = qemu_plugin_read_register(reg_handle, buf);
    uint64_t value;

    g_assert(sz == 8);  /* rv64 isa */
    memcpy(&value, buf->data, sz);
    g_byte_array_free(buf, TRUE);
    return value;
}

void set_register_value_by_index(GArray *regs, size_t index, uint64_t value)
{
    qemu_plugin_reg_descriptor *desc = &g_array_index(
                        regs, qemu_plugin_reg_descriptor, index);
    struct qemu_plugin_register *reg_handle = desc->handle;
    GByteArray *buf = g_byte_array_new();
    g_byte_array_set_size(buf, 8);
    memcpy(buf->data, &value, 8);
    int sz = qemu_plugin_write_register(reg_handle, buf);

    g_assert(sz == 8);
    g_byte_array_free(buf, TRUE);
}

void read_memory_vaddr(uint64_t vaddr, uint8_t *data, size_t len)
{
    GByteArray *buf = g_byte_array_new();

    if (qemu_plugin_read_memory_vaddr(vaddr, buf, len)) {
        size_t actual_len = buf->len;
        g_assert(actual_len == len);
        memcpy(data, buf->data, actual_len);
    } else {
        fprintf(stderr, "%s: failed to read memory at %lx\n", __func__, vaddr);
        fprintf(stderr, "=== current instruction: %s\n", cur_insn_disas);
        fprintf(stderr, "=== current syscall id: %d\n", cur_syscall_id);
    }
}

static void trace_page_fault(vcpu_data_t *data, unsigned int vcpu_idx)
{
    uint64_t stval = get_register_value_by_index(data->cpu_regs, RISCV_STVAL);
    /* Each page fault only be printed once. */
    if (data->saved_last_stval == stval) {
        return;
    }

    uint64_t scause = get_register_value_by_index(data->cpu_regs, RISCV_SCAUSE);
    if (scause == RISCV_EXCP_INST_PAGE_FAULT ||
        scause == RISCV_EXCP_LOAD_PAGE_FAULT ||
        scause == RISCV_EXCP_STORE_PAGE_FAULT) {
        lk_trace_init(&data->evt);
        data->evt.tval = stval;
        data->evt.cause = scause;
        data->evt.epc = get_register_value_by_index(data->cpu_regs, RISCV_SEPC);
        data->evt.cur_priv = qemu_plugin_get_priv(vcpu_idx);
        FILE *f = lk_trace_trylock();
        long offset = lk_trace_head(f);
        lk_trace_submit(offset, &data->evt, f);
        lk_trace_unlock(f);

        data->saved_last_stval = stval;
    }
}

static void insn_exec_ecall_cb(unsigned int vcpu_idx, void *userdata)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);

    uint64_t priv = qemu_plugin_get_priv(vcpu_idx);
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

    cur_syscall_id = data->evt.ax[7];

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

    FILE *f = lk_trace_trylock();
    long offset = lk_trace_head(f);
    mstatus = set_field(mstatus, MSTATUS_SUM, 1);
    /* Modify sum-bit of mstatus for reading user memory in S-mode. */
    set_register_value_by_index(data->cpu_regs, RISCV_MSTATUS, mstatus);
    handle_payload_out(&data->evt, f);
    mstatus = set_field(mstatus, MSTATUS_SUM, 0);
    set_register_value_by_index(data->cpu_regs, RISCV_MSTATUS, mstatus);
    lk_trace_submit(offset, &data->evt, f);
    lk_trace_unlock(f);

    data->is_tracing_sret = true;
}

static void insn_exec_general_cb(unsigned int vcpu_idx, void *userdata)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);

    /* FIXME: should we free memory pointed by `cur_insn_disas` before set ? */
    cur_insn_disas = userdata;

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
        /* Nothing to do */
        data->is_tracing_sret = false;
    }

    /*
     * Page fault tracing should below the syscall tracing,
     * because sret tracing as a atomic procedure, is splited
     * into two code blocks for now.
     */
    if (trace_pagefault) {
        trace_page_fault(data, vcpu_idx);
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
        char *s = qemu_plugin_insn_disas(insn);

        /* Register general callback for all instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_general_cb,
                                               QEMU_PLUGIN_CB_R_REGS, s);

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
                                                       QEMU_PLUGIN_CB_RW_REGS, NULL);
            }
            break;
        default:
            break;
        }
    }
}

/* vcpu init callback: get register list */
static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_idx)
{
    vcpu_data_t *data = qemu_plugin_scoreboard_find(vcpu_scoreboard, vcpu_idx);
    data->cpu_regs = qemu_plugin_get_registers();
    data->saved_last_scause = 0;
    data->saved_last_stval = 0;
    data->saved_last_a0 = 0;
    data->is_tracing_ecall = false;
    data->is_tracing_sret = false;
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

    for (size_t i = 0; i < argc; ++i) {
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
