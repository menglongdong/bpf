/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2014  Steven Rostedt, Red Hat Inc
 */

#include <linux/export.h>
#include <linux/cfi_types.h>
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/ptrace.h>
#include <asm/ftrace.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/frame.h>

	.code64
	.section .text, "ax"

#ifdef CONFIG_FRAME_POINTER
/* Save parent and function stack frames (rip and rbp) */
#  define MCOUNT_FRAME_SIZE	(8+16*2)
#else
/* No need to save a stack frame */
# define MCOUNT_FRAME_SIZE	0
#endif /* CONFIG_FRAME_POINTER */

/* Size of stack used to save mcount regs in save_mcount_regs */
#define MCOUNT_REG_SIZE		(FRAME_SIZE + MCOUNT_FRAME_SIZE)

/*
 * gcc -pg option adds a call to 'mcount' in most functions.
 * When -mfentry is used, the call is to 'fentry' and not 'mcount'
 * and is done before the function's stack frame is set up.
 * They both require a set of regs to be saved before calling
 * any C code and restored before returning back to the function.
 *
 * On boot up, all these calls are converted into nops. When tracing
 * is enabled, the call can jump to either ftrace_caller or
 * ftrace_regs_caller. Callbacks (tracing functions) that require
 * ftrace_regs_caller (like kprobes) need to have pt_regs passed to
 * it. For this reason, the size of the pt_regs structure will be
 * allocated on the stack and the required mcount registers will
 * be saved in the locations that pt_regs has them in.
 */

/*
 * @added: the amount of stack added before calling this
 *
 * After this is called, the following registers contain:
 *
 *  %rdi - holds the address that called the trampoline
 *  %rsi - holds the parent function (traced function's return address)
 *  %rdx - holds the original %rbp
 */
.macro save_mcount_regs added=0

#ifdef CONFIG_FRAME_POINTER
	/* Save the original rbp */
	pushq %rbp

	/*
	 * Stack traces will stop at the ftrace trampoline if the frame pointer
	 * is not set up properly. If fentry is used, we need to save a frame
	 * pointer for the parent as well as the function traced, because the
	 * fentry is called before the stack frame is set up, where as mcount
	 * is called afterward.
	 */

	/* Save the parent pointer (skip orig rbp and our return address) */
	pushq \added+8*2(%rsp)
	pushq %rbp
	movq %rsp, %rbp
	/* Save the return address (now skip orig rbp, rbp and parent) */
	pushq \added+8*3(%rsp)
	pushq %rbp
	movq %rsp, %rbp
#endif /* CONFIG_FRAME_POINTER */

	/*
	 * We add enough stack to save all regs.
	 */
	/* 开辟pt_regs的空间，保存所有需要保存的寄存器，清空origin_rax内容 */
	subq $(FRAME_SIZE), %rsp
	movq %rax, RAX(%rsp)
	movq %rcx, RCX(%rsp)
	movq %rdx, RDX(%rsp)
	movq %rsi, RSI(%rsp)
	movq %rdi, RDI(%rsp)
	movq %r8, R8(%rsp)
	movq %r9, R9(%rsp)
	movq $0, ORIG_RAX(%rsp)
	/*
	 * Save the original RBP. Even though the mcount ABI does not
	 * require this, it helps out callers.
	 */
#ifdef CONFIG_FRAME_POINTER
	movq MCOUNT_REG_SIZE-8(%rsp), %rdx
#else
	movq %rbp, %rdx
#endif
	movq %rdx, RBP(%rsp)

	/* Copy the parent address into %rsi (second parameter) */
	/* 将目标函数的调用者（caller）的地址保存到rsi寄存器（第二个参数）中 */
	movq MCOUNT_REG_SIZE+8+\added(%rsp), %rsi

	 /* Move RIP to its proper location */
	/* 将栈中原始的rip信息拷贝到pt_regs中 */
	movq MCOUNT_REG_SIZE+\added(%rsp), %rdi
	movq %rdi, RIP(%rsp)

	/*
	 * Now %rdi (the first parameter) has the return address of
	 * where ftrace_call returns. But the callbacks expect the
	 * address of the call itself.
	 */
	/* 将rdi（第一个参数）的值修正为函数（目标函数）逻辑上的地址 */
	subq $MCOUNT_INSN_SIZE, %rdi
	.endm

.macro restore_mcount_regs save=0

	/* ftrace_regs_caller or frame pointers require this */
	movq RBP(%rsp), %rbp

	movq R9(%rsp), %r9
	movq R8(%rsp), %r8
	movq RDI(%rsp), %rdi
	movq RSI(%rsp), %rsi
	movq RDX(%rsp), %rdx
	movq RCX(%rsp), %rcx
	movq RAX(%rsp), %rax

	addq $MCOUNT_REG_SIZE-\save, %rsp

	.endm

SYM_TYPED_FUNC_START(ftrace_stub)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_TYPED_FUNC_START(ftrace_stub_graph)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_graph)
#endif

#ifdef CONFIG_DYNAMIC_FTRACE

SYM_FUNC_START(__fentry__)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)

/* C代码版本的可以在Documentation/trace/ftrace-design.rst中看到 */
SYM_FUNC_START(ftrace_caller)
	ANNOTATE_NOENDBR
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

	CALL_DEPTH_ACCOUNT

	/* Stack - skipping return address of ftrace_caller */
	leaq MCOUNT_REG_SIZE+8(%rsp), %rcx
	movq %rcx, RSP(%rsp)

SYM_INNER_LABEL(ftrace_caller_op_ptr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter */
	/* 这个指令也是会在runtime被替换的 */
	movq function_trace_op(%rip), %rdx

	/* regs go into 4th parameter */
	leaq (%rsp), %rcx

	/* Only ops with REGS flag set should have CS register set */
	movq $0, CS(%rsp)

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_call, SYM_L_GLOBAL)
	/* 这个宏像是一个编译器注释宏，注释这个函数不能被trace，以及没有endbr */
	ANNOTATE_NOENDBR
	/* 这个代码更像是会被替换的代码，即会被替换成对应的目标函数。 */
	call ftrace_stub

	/* Handlers can change the RIP */
	movq RIP(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	restore_mcount_regs

	/*
	 * The code up to this label is copied into trampolines so
	 * think twice before adding any new code or changing the
	 * layout here.
	 */
SYM_INNER_LABEL(ftrace_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET
SYM_FUNC_END(ftrace_caller);
STACK_FRAME_NON_STANDARD_FP(ftrace_caller)

/* 基于regs的TRAMPOLINE。这种trampoline不会被直接使用，而是会在注册ftrace_ops的时候
 * 为每个ops动态创建一个trampoline，并将这个trampoline里的一些信息修正为这个ops上的
 * 信息。当某个函数上存在多个ops的时候，就会启用ftrace_ops_list这个callback。这是一种
 * fallback的低效的处理方式，因为它会编译所有的ops，并比对当前的函数的ip和每个ops对应的
 * ip_hash，在命中的时候再执行对应的ops。
 */
SYM_FUNC_START(ftrace_regs_caller)
	ANNOTATE_NOENDBR
	/* 这一段是保存一些ftrace本身的信息 */
	/* Save the current flags before any operations that can change them */
	pushfq

	/* added 8 bytes to save flags */
	/* 将寄存器中按照ptrace-abi.h中的格式保存到栈中。这里的8代表着，当前栈帧
	 * 中的数据，这个宏需要这个信息来拿到返回地址的值。
	 *
	 * 当前栈帧的状态为：
	 *   rip	-	8，caller的下一条指令的地址
	 *   ------------------------------------
	 *   rip	-	8，目标函数地址+4
	 *   flag	-	8
	 *   pt_regs	-	FRAME_SIZE（168）
	 */
	save_mcount_regs 8
	/* save_mcount_regs fills in first two parameters */

	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
	/* 这个宏像是一个编译器注释宏，注释这个函数不能被trace，以及没有endbr */
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter */
	/* 把callback对应的ftrace_ops放到第三个传参寄存器中。这个指令也是会在runtime
	 * 被替换的。
	 */
	movq function_trace_op(%rip), %rdx

	/* 将寄存器中的值按照pt_regs的格式保存到栈中，rsp是pt_regs的起始地址。
	 * 这一端是做调用ops前的准备工作，把各种参数都准备好，然后调用ops。这里
	 * 保存的是那些callee不需要保存的寄存器。
	 */
	/* Save the rest of pt_regs */
	movq %r15, R15(%rsp)
	movq %r14, R14(%rsp)
	movq %r13, R13(%rsp)
	movq %r12, R12(%rsp)
	movq %r11, R11(%rsp)
	movq %r10, R10(%rsp)
	movq %rbx, RBX(%rsp)
	/* 把我们push到栈里的寄存器flags保存到pt_regs中 */
	movq MCOUNT_REG_SIZE(%rsp), %rcx
	movq %rcx, EFLAGS(%rsp)
	/* 把内核Kernel segments保存到pt_regs中的SS字段中（常量，有啥用？） */
	movq $__KERNEL_DS, %rcx
	movq %rcx, SS(%rsp)
	movq $__KERNEL_CS, %rcx
	/* 类似SS */
	movq %rcx, CS(%rsp)
	/* Stack - skipping return address and flags */
	/* 把caller的地址放到了pt_regs的rsp寄存器中 */
	leaq MCOUNT_REG_SIZE+8*2(%rsp), %rcx
	movq %rcx, RSP(%rsp)

	ENCODE_FRAME_POINTER

	/* regs go into 4th parameter */
	/* 把pt_regs放到第四个传参寄存器中 */
	leaq (%rsp), %rcx

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_regs_call, SYM_L_GLOBAL)
	/* 这一段是真正的要调用ops函数的地方 */
	ANNOTATE_NOENDBR
	/* 这里的ftrace_stub会被动态地修改为真正的callback对应的处理函数，上面的
	 * 那四个参数会被传递给这个callback函数。
	 */
	call ftrace_stub

	/* Copy flags back to SS, to restore them */
	movq EFLAGS(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	/* Handlers can change the RIP */
	/* 经过处理后，将pt_regs中的rip保存下来，放到当前栈帧的return ip的位置。
	 * 通过这种方式，可以实现当前handler处理完成后，直接跳转到目标指令的作
	 * 用，从而可以跳过origin函数。这也是热补丁的实现方式，即可以在callback
	 * 中来设置要返回的地址，不基于direct call的方式来实现origin call。
	 */
	movq RIP(%rsp), %rax
	/* 把pt_regs中的rip存到了栈底的rip的位置。这里，MCOUNT_REG_SIZE+8的偏移
	 * 就是它的位置。
	 *
	 * 这里也是function graph实现的地方，通过将这里的
	 */
	movq %rax, MCOUNT_REG_SIZE+8(%rsp)

	/* restore the rest of pt_regs */
	movq R15(%rsp), %r15
	movq R14(%rsp), %r14
	movq R13(%rsp), %r13
	movq R12(%rsp), %r12
	movq R10(%rsp), %r10
	movq RBX(%rsp), %rbx

	movq ORIG_RAX(%rsp), %rax
	/* 这里的MCOUNT_REG_SIZE-8是最后一个寄存器的位置，也就是SS寄存器（干啥的？）。
	 * 这里把origin_rax保存到了ss里面。
	 */
	movq %rax, MCOUNT_REG_SIZE-8(%rsp)

	/* 如果ORIG_RAX寄存器里面有值，那么就进行跳转，并调用其中的值作为函数。 */
	 
	testq	%rax, %rax
SYM_INNER_LABEL(ftrace_regs_caller_jmp, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jnz	1f

	/* 这里是不进行direct call的地方，这里会进行寄存器的恢复，然后直接返回。 */
	restore_mcount_regs
	/* Restore flags */
	popfq

	/*
	 * The trampoline will add the return.
	 */
SYM_INNER_LABEL(ftrace_regs_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET

	/* 这里进入 direct call 路径。 */
1:
	testb	$1, %al
	jz	2f
	andq $0xfffffffffffffffe, %rax
	movq %rax, MCOUNT_REG_SIZE+8(%rsp)
	restore_mcount_regs
	/* Restore flags */
	popfq
	RET
	/* Swap the flags with orig_rax */
2:	movq MCOUNT_REG_SIZE(%rsp), %rdi
	movq %rdi, MCOUNT_REG_SIZE-8(%rsp)
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	/* 恢复寄存器的状态。这里恢复的时候，会保留最后一个寄存器，使其留在栈中。下面的popfq
	 * 实际上弹出的是我们上面修整过的flags，构造的rip并不会被弹出。
	 */
	restore_mcount_regs 8
	/* Restore flags */
	popfq
	UNWIND_HINT_FUNC

	/*
	 * The above left an extra return value on the stack; effectively
	 * doing a tail-call without using a register. This PUSH;RET
	 * pattern unbalances the RSB, inject a pointless CALL to rebalance.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	CALL .Ldo_rebalance
	int3
.Ldo_rebalance:
	/* 这个代码应该是跳过当前的栈帧，然后直接jump到目标函数开始执行。可是为什么
	 * 这里没有看到jump的指令呢？
	 */
	add $8, %rsp
	/* 经过上面的add之后，现在的栈的情况是：
	 *   rip	-	8，caller的下一条指令的地址
	 *   ------------------------------------
	 *   rip	-	8，目标函数地址+4
	 *   rip	-	8，direct call的地址
	 *
	 * 所以这里return的话，会直接跳到direct call的地方，且栈的情况和直接在目标函数
	 * 的fentry处调用direct call函数是相同的效果。
	 */
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH

SYM_FUNC_END(ftrace_regs_caller)
STACK_FRAME_NON_STANDARD_FP(ftrace_regs_caller)

SYM_FUNC_START(ftrace_stub_direct_tramp)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_direct_tramp)

#else /* ! CONFIG_DYNAMIC_FTRACE */

/* 不支持动态ftrace的情况下，默认的ftrace的处理函数。可以看出来，这里会直接调用
 * 全局的ftrace_trace_function函数
 */
SYM_FUNC_START(__fentry__)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT

	cmpq $ftrace_stub, ftrace_trace_function
	jnz trace
	RET

trace:
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

	/*
	 * When DYNAMIC_FTRACE is not defined, ARCH_SUPPORTS_FTRACE_OPS is not
	 * set (see include/asm/ftrace.h and include/linux/ftrace.h).  Only the
	 * ip and parent ip are used and the list function is called when
	 * function tracing is enabled.
	 */
	movq ftrace_trace_function, %r8
	CALL_NOSPEC r8
	restore_mcount_regs

	jmp ftrace_stub
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)
STACK_FRAME_NON_STANDARD_FP(__fentry__)

#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_CODE_START(return_to_handler)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR

	/* Store original rsp for pt_regs.sp value. */
	movq %rsp, %rdi

	/* Restore return_to_handler value that got eaten by previous ret instruction. */
	subq $8, %rsp
	UNWIND_HINT_FUNC

	/* Save ftrace_regs for function exit context  */
	subq $(FRAME_SIZE), %rsp

	movq %rax, RAX(%rsp)
	movq %rdx, RDX(%rsp)
	movq %rbp, RBP(%rsp)
	movq %rdi, RSP(%rsp)
	movq %rsp, %rdi

	call ftrace_return_to_handler

	movq %rax, %rdi
	movq RDX(%rsp), %rdx
	movq RAX(%rsp), %rax

	addq $(FRAME_SIZE) + 8, %rsp

	/*
	 * Jump back to the old return address. This cannot be JMP_NOSPEC rdi
	 * since IBT would demand that contain ENDBR, which simply isn't so for
	 * return addresses. Use a retpoline here to keep the RSB balanced.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	call .Ldo_rop
	int3
.Ldo_rop:
	mov %rdi, (%rsp)
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH
SYM_CODE_END(return_to_handler)
#endif
