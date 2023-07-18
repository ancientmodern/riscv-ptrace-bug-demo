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

static inline int chk(int fd, int val)
{
	int v = 0;

	if (read(fd, &v, sizeof(v)) != sizeof(v)) {
		fprintf(stderr, "Error: read failed\n");
	}
	printf("%d, want %d\n", v, val);
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

int ptrace_get_regs(int pid, struct user_regs_struct *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(struct user_regs_struct);

	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

int ptrace_set_regs(int pid, struct user_regs_struct *regs)
{
	struct iovec iov;

	iov.iov_base = regs;
	iov.iov_len = sizeof(struct user_regs_struct);

	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

#define CODE_EBREAK 0x00100073UL

int magic(int pid)
{
	int ret, status;
	unsigned long new_pc = 0x10000UL, code_orig;
	struct user_regs_struct orig_regs, regs;

	printf("\tCheckpoint original regs and instruction\n");
	ret = ptrace_get_regs(pid, &regs);
	ret = ptrace_get_regs(pid, &orig_regs);
	code_orig = ptrace(PTRACE_PEEKDATA, pid, new_pc, NULL);
	printf("\tPTRACE_PEEKDATA return value: %d, errno is: %s\n", ret, strerror(errno));

	printf("\tSet new regs (pc, a0, a7) and ebreak\n");
	regs.pc = new_pc;
	regs.a7 = __NR_getpid;
	regs.a0 = 0;
	ret = ptrace_set_regs(pid, &regs);
	ret = ptrace(PTRACE_POKEDATA, pid, new_pc, CODE_EBREAK);
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

	printf("First kick: Checking the victim session to be %d\n", sid);
	pass = chk(p_out[0], sid);
	if (!pass)
		return 1;

	printf("\nInterrupting task %d\n", pid);
	ret = interrupt_task(pid);
	printf("Interrupt_task return value: %d, errno is: %s\n", ret, strerror(errno));

	ret = magic(pid);

	printf("Resuming task %d\n", pid);
	ret = resume_task(pid);
	printf("Resume_task return value: %d, errno is: %s\n", ret, strerror(errno));

	/*
	 * Kick the victim again so it tells new session
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

	printf("Final kick: Checking the new session to be %d\n", sid);
	pass = chk(p_out[0], sid);

	if (pass)
		printf("All OK\n");
	else
		printf("Something went WRONG\n");

	return 0;
}
