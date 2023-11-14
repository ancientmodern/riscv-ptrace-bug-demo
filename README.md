# Patch Applied 🎉 RISC-V Ptrace/Signal Bug Demo

**🚀 Update: This patch has been applied to the RISC-V Linux kernel, which is my first one! Check out the details in the [commit page](https://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git/commit/?id=ce4f78f1b53d).**

Welcome to this demo of a kernel bug affecting ptrace in the Linux kernel <= 6.6 on RISC-V, resulting in different bahavior compared with x86 and arm64. This README shows the reproduction and analysis of this issue, where a blocking syscall such as `read()` doesn't restart properly after being interrupted by ptrace.

## Reproducing the Bug
Follow the steps below to replicate this issue:
1. Initialize pipes and use `vfork()` and `execl()` to start a victim process. This process will run a couple of simple system calls - `read()`, `write()`, and `getsid()`.
2. In the parent process, execute `PTRACE_SEIZE` followed by `PTRACE_INTERRUPT` to pause the victim process (you can find this in the `interrupt_task()` subfunction).
3. Inject `ebreak` (`brk` on arm64 and `int3` on x86_64) and restart the victim process. This includes several steps:
   1. Backup the original registers and instruction at `new_pc` using `PTRACE_GETREGSET` and `PTRACE_PEEKDATA`.
   2. Set `pc` to `new_pc` and modify some other regs to disrupt the system call restart condition. Inject an ebreak instruction at `new_pc` using `PTRACE_SETREGSET` and `PTRACE_POKEDATA`.
   3. Execute `ebreak` in the victim with `PTRACE_CONT`, which should then give control back to the tracer.
   4. Wait for the victim to finish its execution.
   5. Restores `pc`, the other registers and instruction at `new_pc` using `PTRACE_SETREGSET` and `PTRACE_POKEDATA`.
4. Resume the victim process using `PTRACE_DETACH` (you can find this in `resume_task()`).
5. Kick the victim process again. You should now see a difference in behavior: On RISC-V, the `read()` syscall ends with errno 512 `ERESTARTSYS` which shouldn't appear in user space. In contrast, on x86_64 and arm64, the `read()` system call restarts and finishes successfully.

## Bug Analysis
The crux of this issue lies within `arch/${arch}/kernel/signal.c`, in the `arch_do_signal_or_restart()` (RISC-V and x86) and `do_signal()` (arm64) methods. While these functions serve the same objective, their names vary slightly across architectures.

In the RISC-V implementation:
1. The tracee is initially blocked in `syscall_handler()`. When `PTRACE_INTERRUPT` is activated, the process returns with `a0 == -512` and traverses `syscall_exit_to_user_mode()`, `__syscall_exit_to_user_mode_work()`, `exit_to_user_mode_prepare()`, `exit_to_user_mode_loop()`, and finally `arch_do_signal_or_restart()`.
2. It first enters `get_signal()`. Due to the setup of `PTRACE_INTERRUPT` (primarily the `JOBCTL_TRAP_MASK` flag), it goes through `do_jobctl_trap()`, `ptrace_do_notify()`, and finally halts in `ptrace_stop()`, allowing the tracer to inspect and manipulate it.
3. Here, the tracer performs step 3 from the reproduction process, checkpoints all user-space regs, mainly `a0`, `a7`, and `pc`. However, the `cause` register, being in supervisor mode, cannot be accessed via ptrace. As a result of `ebreak`, `cause` transitions from `EXC_SYSCALL` to `EXC_BREAKPOINT`. The tracee will halt again after executing `ebreak`, at which point further examination or actions may take place. In this case, we simply restore all elements and resume the tracee using `PTRACE_DETACH`.
4. The change of `cause` disrupts the system call restart condition. Upon re-exceution, the system call restart process in `arch_do_signal_or_restart()` is bypassed, and the return value and errno are set to `ERESTARTSYS`. According to [`include/linux/errno.h`](https://elixir.bootlin.com/linux/latest/source/include/linux/errno.h#L14), this should never be seen by user programs.
   
Let's contrast this with the x86 and arm64 architectures, where the system call can be restarted correctly:
- In x86, the syscall restart condition is evaluated using `regs->orig_ax != -1`, where `orig_ax` is exposed to user space and will be checkpointed & restored using ptrace. Therefore, the syscall restart condition remains intact.
- Arm64 operates differently. The syscall restart condition is evaluated using `regs->syscallno != NO_SYSCALL`, also a kernel space register. However, arm64 applies a unique `do_signal()` structure: it attempts to restart the syscall before `get_signal()`, then reverts this decision if it's unsuitable to restart after `get_signal()`. This design allows the syscall to restart prior to being trapped and modified in `ptrace_stop()`.

## Related Kernel Patch
Link: https://patchwork.kernel.org/project/linux-riscv/patch/20230803224458.4156006-1-ancientmodern4@gmail.com/

```diff
From 3ba4e3f69597d38b83b60943c3d35f892364d878 Mon Sep 17 00:00:00 2001
From: Haorong Lu <ancientmodern4@gmail.com>
Date: Thu, 3 Aug 2023 14:51:00 -0700
Subject: [PATCH] riscv: signal: handle syscall restart before get_signal

In the current riscv implementation, blocking syscalls like read() may
not correctly restart after being interrupted by ptrace. This problem
arises when the syscall restart process in arch_do_signal_or_restart()
is bypassed due to changes to the regs->cause register, such as an
ebreak instruction.

Steps to reproduce:
1. Interrupt the tracee process with PTRACE_SEIZE & PTRACE_INTERRUPT.
2. Backup original registers and instruction at new_pc.
3. Change pc to new_pc, and inject an instruction (like ebreak) to this
   address.
4. Resume with PTRACE_CONT and wait for the process to stop again after
   executing ebreak.
5. Restore original registers and instructions, and detach from the
   tracee process.
6. Now the read() syscall in tracee will return -1 with errno set to
   ERESTARTSYS.

Specifically, during an interrupt, the regs->cause changes from
EXC_SYSCALL to EXC_BREAKPOINT due to the injected ebreak, which is
inaccessible via ptrace so we cannot restore it. This alteration breaks
the syscall restart condition and ends the read() syscall with an
ERESTARTSYS error. According to include/linux/errno.h, it should never
be seen by user programs. X86 can avoid this issue as it checks the
syscall condition using a register (orig_ax) exposed to user space.
Arm64 handles syscall restart before calling get_signal, where it could
be paused and inspected by ptrace/debugger.

This patch adjusts the riscv implementation to arm64 style, which also
checks syscall using a kernel register (syscallno). It ensures the
syscall restart process is not bypassed when changes to the cause
register occur, providing more consistent behavior across various
architectures.

For a simplified reproduction program, feel free to visit:
https://github.com/ancientmodern/riscv-ptrace-bug-demo.

Signed-off-by: Haorong Lu <ancientmodern4@gmail.com>
---
 arch/riscv/kernel/signal.c | 85 +++++++++++++++++++++-----------------
 1 file changed, 46 insertions(+), 39 deletions(-)

diff --git a/arch/riscv/kernel/signal.c b/arch/riscv/kernel/signal.c
index 180d951d3624..d2d7169048ea 100644
--- a/arch/riscv/kernel/signal.c
+++ b/arch/riscv/kernel/signal.c
@@ -391,30 +391,6 @@ static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
 	sigset_t *oldset = sigmask_to_save();
 	int ret;
 
-	/* Are we from a system call? */
-	if (regs->cause == EXC_SYSCALL) {
-		/* Avoid additional syscall restarting via ret_from_exception */
-		regs->cause = -1UL;
-		/* If so, check system call restarting.. */
-		switch (regs->a0) {
-		case -ERESTART_RESTARTBLOCK:
-		case -ERESTARTNOHAND:
-			regs->a0 = -EINTR;
-			break;
-
-		case -ERESTARTSYS:
-			if (!(ksig->ka.sa.sa_flags & SA_RESTART)) {
-				regs->a0 = -EINTR;
-				break;
-			}
-			fallthrough;
-		case -ERESTARTNOINTR:
-                        regs->a0 = regs->orig_a0;
-			regs->epc -= 0x4;
-			break;
-		}
-	}
-
 	rseq_signal_deliver(ksig, regs);
 
 	/* Set up the stack frame */
@@ -428,35 +404,66 @@ static void handle_signal(struct ksignal *ksig, struct pt_regs *regs)
 
 void arch_do_signal_or_restart(struct pt_regs *regs)
 {
+	unsigned long continue_addr = 0, restart_addr = 0;
+	int retval = 0;
 	struct ksignal ksig;
+	bool syscall = (regs->cause == EXC_SYSCALL);
 
-	if (get_signal(&ksig)) {
-		/* Actually deliver the signal */
-		handle_signal(&ksig, regs);
-		return;
-	}
+	/* If we were from a system call, check for system call restarting */
+	if (syscall) {
+		continue_addr = regs->epc;
+		restart_addr = continue_addr - 4;
+		retval = regs->a0;
 
-	/* Did we come from a system call? */
-	if (regs->cause == EXC_SYSCALL) {
 		/* Avoid additional syscall restarting via ret_from_exception */
 		regs->cause = -1UL;
 
-		/* Restart the system call - no handlers present */
-		switch (regs->a0) {
+		/*
+		 * Prepare for system call restart. We do this here so that a
+		 * debugger will see the already changed PC.
+		 */
+		switch (retval) {
 		case -ERESTARTNOHAND:
 		case -ERESTARTSYS:
 		case -ERESTARTNOINTR:
-                        regs->a0 = regs->orig_a0;
-			regs->epc -= 0x4;
-			break;
 		case -ERESTART_RESTARTBLOCK:
-                        regs->a0 = regs->orig_a0;
-			regs->a7 = __NR_restart_syscall;
-			regs->epc -= 0x4;
+			regs->a0 = regs->orig_a0;
+			regs->epc = restart_addr;
 			break;
 		}
 	}
 
+	/*
+	 * Get the signal to deliver. When running under ptrace, at this point
+	 * the debugger may change all of our registers.
+	 */
+	if (get_signal(&ksig)) {
+		/*
+		 * Depending on the signal settings, we may need to revert the
+		 * decision to restart the system call, but skip this if a
+		 * debugger has chosen to restart at a different PC.
+		 */
+		if (regs->epc == restart_addr &&
+		    (retval == -ERESTARTNOHAND ||
+		     retval == -ERESTART_RESTARTBLOCK ||
+		     (retval == -ERESTARTSYS &&
+		      !(ksig.ka.sa.sa_flags & SA_RESTART)))) {
+			regs->a0 = -EINTR;
+			regs->epc = continue_addr;
+		}
+
+		/* Actually deliver the signal */
+		handle_signal(&ksig, regs);
+		return;
+	}
+
+	/*
+	 * Handle restarting a different system call. As above, if a debugger
+	 * has chosen to restart at a different PC, ignore the restart.
+	 */
+	if (syscall && regs->epc == restart_addr && retval == -ERESTART_RESTARTBLOCK)
+		regs->a7 = __NR_restart_syscall;
+
 	/*
 	 * If there is no signal to deliver, we just put the saved
 	 * sigmask back.
-- 
2.41.0
```
