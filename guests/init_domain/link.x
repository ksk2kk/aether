ENTRY(_start)

SECTIONS {
  . = 0x8000;
  .text : {
    *(.text.entry)
    *(.text .text.*)
  }
  .rodata : {
    *(.rodata .rodata.*)
  }
  .data : {
    *(.data .data.*)
  }
  .bss : {
    *(.bss .bss.*)
  }
  /DISCARD/ : {
    *(.eh_frame)
    *(.eh_frame_hdr)
    *(.gcc_except_table)
    *(.note*)
    *(.comment*)
  }
}