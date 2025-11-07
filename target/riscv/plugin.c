#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "cpu.h"
#include "plugins/arch-hooks.h"

static uint64_t riscv_get_priv(unsigned int vcpu_index)
{
    CPUState *cs = qemu_get_cpu(vcpu_index);
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    return env->priv;
}

static void __attribute__((constructor)) register_riscv_plugin_ops(void)
{
    qemu_plugin_arch_ops.get_priv = riscv_get_priv;
}

