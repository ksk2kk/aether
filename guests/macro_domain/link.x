ENTRY(_start)

SECTIONS {
  . = 0x8000;
  .text : {
    *(.text .text.*)
  }
  /DISCARD/ : {
    *(.eh_frame)
    *(.eh_frame_hdr)
    *(.gcc_except_table)
    *(.note*)
    *(.comment*)
  }
}