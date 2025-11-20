/*
 * Copyright (C) 2024, Shi Lei <shi_lei@massclouds.com>
 * Copyright (C) 2025, Chaoqun Zheng <1667510710@qq.com>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#ifndef LKTRACE_H
#define LKTRACE_H

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

/* per-vcpu saved info */
typedef struct {
    trace_event_t evt;
    GArray *cpu_regs;
    uint64_t saved_last_scause;
    uint64_t saved_last_stval;
    uint64_t saved_last_a0;
    bool is_tracing_ecall;
    bool is_tracing_sret;
} vcpu_data_t;

/* module symbol struct */
typedef struct {
    char *name;
    uint64_t addr;
} module_symbol_t;

/* copy from QEMU's target/riscv/cpu_bits.h */
#define get_field(reg, mask) (((reg) & \
                 (uint64_t)(mask)) / ((mask) & ~((mask) << 1)))
#define set_field(reg, mask, val) (((reg) & ~(uint64_t)(mask)) | \
                 (((uint64_t)(val) * ((mask) & ~((mask) << 1))) & \
                 (uint64_t)(mask)))
#define MSTATUS_SPP         0x00000100
#define MSTATUS_SUM         0x00040000

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
    RISCV_EXCP_U_ECALL = 0x8,
    RISCV_EXCP_INST_PAGE_FAULT = 0xc,
    RISCV_EXCP_LOAD_PAGE_FAULT = 0xd,
    RISCV_EXCP_STORE_PAGE_FAULT = 0xf,
};

/* syscall.c */
void handle_payload_in(trace_event_t *evt, FILE *f);
void handle_payload_out(trace_event_t *evt, FILE *f);

/* lktrace.c */
void lk_trace_init(trace_event_t *evt);
FILE *lk_trace_trylock(void);
void lk_trace_unlock(FILE *f);
long lk_trace_head(FILE *f);
void lk_trace_payload(uint16_t index, trace_event_t *evt,
                      const void *buf, size_t size, FILE *f);
void lk_trace_submit(long offset, const trace_event_t *evt, FILE *f);
uint64_t get_register_value_by_index(GArray *regs, size_t index);
void set_register_value_by_index(GArray *regs, size_t index, uint64_t value);
void read_memory_vaddr(uint64_t vaddr, uint8_t *data, size_t len);

/* module.c */
extern FILE *system_map_file;
extern GArray *traced_symbols;
extern char *trace_module_name;
int load_traced_symbols_from_system_map(const char *module_name, FILE *mapfile);
void free_traced_symbols(void);

static inline void formalize_str(uint8_t *data, size_t size)
{
    uint8_t *end = memchr(data, '\0', size);

    if (end == NULL) {
        end = data + size;
        end[-1] = '\0';
    }
}

#endif  /* LKTRACE_H */