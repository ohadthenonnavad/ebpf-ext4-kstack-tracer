#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xd272d446, "__fentry__" },
	{ 0xe8213e80, "_printk" },
	{ 0x5a844b26, "__x86_indirect_thunk_r14" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0x448a179e, "lookup_address" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xa62b1cc9, "kmalloc_caches" },
	{ 0xd1f07d8f, "__kmalloc_cache_noprof" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0x43a349ca, "strlen" },
	{ 0x2435d559, "strncmp" },
	{ 0xc368a5e1, "param_ops_int" },
	{ 0xc368a5e1, "param_ops_ulong" },
	{ 0xab006604, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xd272d446,
	0xe8213e80,
	0x5a844b26,
	0xd272d446,
	0x448a179e,
	0xd272d446,
	0xe4de56b4,
	0xbd03ed67,
	0xa62b1cc9,
	0xd1f07d8f,
	0xcb8b6ec6,
	0x43a349ca,
	0x2435d559,
	0xc368a5e1,
	0xc368a5e1,
	0xab006604,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"__fentry__\0"
	"_printk\0"
	"__x86_indirect_thunk_r14\0"
	"__x86_return_thunk\0"
	"lookup_address\0"
	"__stack_chk_fail\0"
	"__ubsan_handle_load_invalid_value\0"
	"random_kmalloc_seed\0"
	"kmalloc_caches\0"
	"__kmalloc_cache_noprof\0"
	"kfree\0"
	"strlen\0"
	"strncmp\0"
	"param_ops_int\0"
	"param_ops_ulong\0"
	"module_layout\0"
;

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "85EF5C320D836236225E27A");
