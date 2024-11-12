/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_COMMON_H__

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
/* 将内存或者IMM加载到A寄存器（运算寄存器）。看样子，这个是cBPF中才会使用的东西，
 * 仅支持BPF_ABS，BPF_IND喝BPF_IMM三种模式。
 */
#define		BPF_LD		0x00
/* 将内存加载到任意的寄存器。看样子，它没有IMM模式，如果是IMM的话就需要使用BPF_LD */
#define		BPF_LDX		0x01
/* 将A中的数据存储到指定的地址 */
#define		BPF_ST		0x02
/* 将任意寄存器中的数据存储到指定的地址 */
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */
/* 这些是ld指令中会使用到的一些东西 */
#define BPF_MODE(code)  ((code) & 0xe0)
/* 将立即数加载到目标寄存器中 */
#define		BPF_IMM		0x00
/* 按照绝对偏移的方式来加载数据 */
#define		BPF_ABS		0x20
/* 按照相对偏移的方式来加载数据 */
#define		BPF_IND		0x40
/* 将指定内存加载到寄存器（无符号），相对于BPF_MEMSX有符号 */
#define		BPF_MEM		0x60
/* 下面两个是cBPF中才会使用的东西 */
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80 /* 取负数操作 */
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
/* PC += offset if dst & src */
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
/* 指令中源操作数的类型，K代表是32位的立即数，X代表来自寄存器。这两个一般是ALU指令
 * 中使用的东西。
 */
#define		BPF_K		0x00
#define		BPF_X		0x08

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#endif /* _UAPI__LINUX_BPF_COMMON_H__ */
