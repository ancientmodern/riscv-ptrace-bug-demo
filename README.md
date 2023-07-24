# RISC-V Ptrace/Signal Bug Demo

Welcome to this demo of a kernel bug (?) affecting ptrace in the Linux 6.4 kernel on RISC-V, resulting in different bahavior compared with x86 and arm64. This README shows the reproduction and analysis of this issue, where a blocking syscall such as `read()` doesn't restart properly after being interrupted by ptrace.

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
TODO