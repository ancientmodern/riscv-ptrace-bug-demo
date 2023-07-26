#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <linux/elf.h>
#include <asm/ptrace.h>
#include <errno.h>
#include <assert.h>

static inline int check(int fd, int val)
{
	int v = 0;

	if (read(fd, &v, sizeof(v)) != sizeof(v)) {
		fprintf(stderr, "Error: read failed\n");
	}
	printf("Check: %d, want %d\n", v, val);
	return v == val;
}

int interrupt_task(int pid)
{
	int ret;

	ret = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
	if (ret) {
		fprintf(stderr, "Error: unable to interrupt task: %d (%s)\n", pid, strerror(errno));
		return ret;
	}

	ret = ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Error: SEIZE %d: can't interrupt task: %s\n", pid, strerror(errno));
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL))
			fprintf(stderr, "Error: unable to detach from %d\n", pid);
	}

	return ret;
}

int resume_task(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		fprintf(stderr, "Error: unable to detach from %d\n", pid);
		return -1;
	}

	return 0;
}

/*
 * Find first executable VMA that would fit the initial
 * syscall injection.
 */
static unsigned long find_executable_area(int pid)
{
	char aux[128];
	FILE *f;
	unsigned long ret = -1;

	sprintf(aux, "/proc/%d/maps", pid);
	f = fopen(aux, "r");
	if (!f)
		goto out;

	while (fgets(aux, sizeof(aux), f)) {
		unsigned long start, end;
		char *f;

		start = strtoul(aux, &f, 16);
		end = strtoul(f + 1, &f, 16);

		/* f now points at " rwx" (yes, with space) part */
		if (f[3] == 'x') {
			assert(end - start >= 4096);
			ret = start;
			break;
		}
	}

	fclose(f);
out:
	return ret;
}

#ifdef ARCH_x86_64

typedef struct user_regs_struct {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
} user_regs_struct_t;
#define CODE_BREAK 0xCCCCCCCCUL

#elif defined(ARCH_aarch64)

typedef struct user_pt_regs user_regs_struct_t;
#define CODE_BREAK 0xd4200000UL

#elif defined(ARCH_riscv64)

typedef struct user_regs_struct user_regs_struct_t;
#define CODE_BREAK 0x00100073UL

#endif

int ptrace_get_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);

	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

int ptrace_set_regs(int pid, user_regs_struct_t *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(user_regs_struct_t);

	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

/*
* This function performs five key steps:
* 	1. Backs up the original registers and instruction at new_pc using GETREGSET and PEEKDATA
* 	2. Sets new registers (in this case, pc, a0, a7) and injects an `ebreak` at new_pc using SETREGSET and POKEDATA
*	3. Executes `ebreak` in the victim with PTRACE_CONT, which then returns control to the tracer
*	4. The tracer waits until the victim has finished execution
*	5. Restores the original registers and instruction at new_pc using SETREGSET and POKEDATA
*/
int inject_ebreak_and_restore_state(int pid)
{
	int ret, status;
	unsigned long new_pc = find_executable_area(pid), code_orig;
	user_regs_struct_t orig_regs, regs;

	printf("\tCheckpoint original regs and instruction, new_pc = %lu\n", new_pc);
	ret = ptrace_get_regs(pid, &regs);
	ret = ptrace_get_regs(pid, &orig_regs);
	code_orig = ptrace(PTRACE_PEEKDATA, pid, new_pc, NULL);
	printf("\tPTRACE_PEEKDATA return value: %d, errno is: %s\n", ret, strerror(errno));

	printf("\tSet new regs (pc, a0) and ebreak\n");
#ifdef ARCH_x86_64
	regs.ip = new_pc;
	regs.ax = 0;
#elif defined(ARCH_aarch64)
	regs.pc = new_pc;
	regs.regs[0] = 0;
#elif defined(ARCH_riscv64)
	regs.pc = new_pc;
	regs.a0 = 0;
#endif

	ret = ptrace_set_regs(pid, &regs);
	ret = ptrace(PTRACE_POKEDATA, pid, new_pc, CODE_BREAK);
	printf("\tPTRACE_POKEDATA return value: %d, errno is: %s\n", ret, strerror(errno));

	printf("\tRunning PTRACE_CONT in task %d\n", pid);
	ret = ptrace(PTRACE_CONT, pid, NULL, NULL);
	printf("\tPTRACE_CONT return value: %d, errno is: %s\n", ret, strerror(errno));

	ret = wait4(pid, &status, __WALL, NULL);

	printf("\tRestore original regs and instruction\n");
	ret = ptrace_set_regs(pid, &orig_regs);
	ret = ptrace(PTRACE_POKEDATA, pid, new_pc, (void *)code_orig);
	printf("\tPTRACE_POKEDATA return value: %d, errno is: %s\n", ret, strerror(errno));

	return ret;
}

int main(int argc, char **argv)
{
	int p_in[2], p_out[2], p_err[2], pid, i, pass = 1, sid, ret;

	/*
	 * Prepare IO-s and fork the victim binary
	 */
	if (pipe(p_in) || pipe(p_out) || pipe(p_err)) {
		perror("Can't make pipe");
		return -1;
	}

	pid = vfork();
	if (pid == 0) {
		close(p_in[1]);
		dup2(p_in[0], 0);
		close(p_in[0]);
		close(p_out[0]);
		dup2(p_out[1], 1);
		close(p_out[1]);
		close(p_err[0]);
		dup2(p_err[1], 2);
		close(p_err[1]);
		execl("./victim", "victim", NULL);
		exit(1);
	}

	close(p_in[0]);
	close(p_out[1]);
	close(p_err[1]);
	sid = getsid(0);

	/*
	 * Kick the victim once
	 */
	i = 0;
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i)) {
		fprintf(stderr, "write to pipe failed\n");
		return -1;
	}

	printf("First kick: Checking the victim sid to be %d\n", sid);
	pass = check(p_out[0], sid);
	if (!pass)
		return 1;
	printf("First kick: PASS\n");

	/*
	 * Use ptrace to seize and interrupt the victim
	 */
	printf("\nInterrupting task %d\n", pid);
	ret = interrupt_task(pid);
	printf("Interrupt_task return value: %d, errno is: %s\n", ret, strerror(errno));

	/*
	 * Do some bad things in the victim process
	 */
	ret = inject_ebreak_and_restore_state(pid);

	/*
	 * Use ptrace to detach the victim
	 */
	printf("Resuming task %d\n", pid);
	ret = resume_task(pid);
	printf("Resume_task return value: %d, errno is: %s\n", ret, strerror(errno));

	/*
	 * Kick the victim again to check if it's good after resuming
	 */
	if (write(p_in[1], &i, sizeof(i)) != sizeof(i)) {
		fprintf(stderr, "write to pipe failed\n");
		return -1;
	}

	/*
	 * Stop the victim and check the intrusion went well
	 */
	printf("\nClosing victim stdin\n");
	close(p_in[1]);
	printf("Waiting for victim to die\n");
	wait(NULL);

	printf("Final kick: Checking the victim sid still to be %d\n", sid);
	pass = check(p_out[0], sid);

	if (pass)
		printf("All PASS\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
