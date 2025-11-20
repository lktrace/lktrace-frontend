/*
 * Copyright (C) 2024, Shi Lei <shi_lei@massclouds.com>
 * Copyright (C) 2025, Chaoqun Zheng <1667510710@qq.com>
 *
 * Module handler of lktrace.
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

/* System.map file */
FILE *system_map_file = NULL;
GArray *traced_symbols = NULL;
char *trace_module_name = NULL;

static char *strip_symbol_name(char *s)
{
    char *e = s + strlen(s);
    while (e > s && e[-1] == ' ') {
        *--e = '\0';
    }
    return s;
}

int load_traced_symbols_from_system_map(const char *module_name, FILE *mapfile)
{
    if (!module_name || !mapfile) {
        return 0;
    }

    rewind(mapfile);

    if (traced_symbols) {
        free_traced_symbols();
    }
    traced_symbols = g_array_new(FALSE, FALSE, sizeof(module_symbol_t));

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, mapfile)) != -1) {
        /*
         * System.map line format:
         * ffffffff80c1d1c0 D ext4_file_operations
         */
        char addr_str[32];
        char type;
        char name_buf[256];
        int n = sscanf(line, "%31s %c %255s", addr_str, &type, name_buf);
        if (n == 3) {
            if (strstr(name_buf, module_name) != NULL) {
                module_symbol_t sym;
                sym.name = g_strdup(strip_symbol_name(name_buf));
                sym.addr = (uint64_t)strtoull(addr_str, NULL, 16);
                g_array_append_val(traced_symbols, sym);
            }
        }
    }
    g_free(line);

    return (int)traced_symbols->len;
}

void free_traced_symbols(void)
{
    if (!traced_symbols) {
        return;
    }
    for (size_t i = 0; i < traced_symbols->len; ++i) {
        module_symbol_t *s = &g_array_index(traced_symbols, module_symbol_t, i);
        g_free(s->name);
    }
    g_array_free(traced_symbols, TRUE);
    traced_symbols = NULL;
}
