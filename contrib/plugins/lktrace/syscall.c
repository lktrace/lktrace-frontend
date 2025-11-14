/*
 * Copyright (C) 2024, Shi Lei <shi_lei@massclouds.com>
 * Copyright (C) 2025, Chaoqun Zheng <1667510710@qq.com>
 *
 * Syscall payload handler of lktrace.
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

void handle_payload_in(trace_event_t *evt, FILE *f)
{
    switch (evt->ax[7]) {
    case __NR_execve:
        do_execve(evt, f);
        break;
    default:
        break;
    }
}

void handle_payload_out(trace_event_t *evt, FILE *f)
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