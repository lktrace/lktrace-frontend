#ifndef PLUGINS_ARCH_HOOKS_H
#define PLUGINS_ARCH_HOOKS_H

#include "qemu/plugin.h"

typedef struct {
    uint64_t (*get_priv)(unsigned int vcpu_index);
} QEMUPluginArchOps;

extern QEMUPluginArchOps qemu_plugin_arch_ops;

#endif

