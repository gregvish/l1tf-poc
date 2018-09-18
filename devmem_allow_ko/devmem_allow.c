#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>


typedef void (*text_poke_t)(void *addr, unsigned char *data, unsigned long len);


static int __init mod_init(void)
{
    void *func = (void *) kallsyms_lookup_name("devmem_is_allowed");
    text_poke_t text_poke = (text_poke_t) kallsyms_lookup_name("text_poke");

    if (func == NULL || text_poke == NULL) {
        printk(KERN_INFO "No devmem_is_allowed or text_poke\n");
        return 0;
    }

    /* Replace devmem_is_allowed func with:
          6a 01    pushq  $0x1
          58       pop    %rax
          c3       retq
    */
    text_poke((void *)func, "\x6a\x01\x58\xc3", 4);

    printk(KERN_INFO "Patched out devmem_is_allowed\n");

    return 0;
}


static void __exit mod_exit(void)
{
    printk(KERN_INFO "Didn't bother cleaning up :(\n");
}


module_init(mod_init)
module_exit(mod_exit)

MODULE_LICENSE("GPL");
