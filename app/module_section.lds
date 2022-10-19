SECTIONS
{
    . = ALIGN(64);
    __module_start__ = .;
    .module_section : { *(.module_section) }
    __module_end__ = .;
}
INSERT AFTER .rodata