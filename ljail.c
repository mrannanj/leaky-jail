#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>
#include <x86_64-linux-gnu/sys/ucontext.h>

extern char **environ;

static const char* cn[300];

#define MAX_PATH 256

static const char* ok_path[] = {
	"/lib/x86_64-linux-gnu/libc.so.6",
	"/etc/ld.so.cache",
	NULL
};

static char* child_prog_name;

void usage(char* name)
{
	printf("usage: %s <program>\n", name);
	exit(1);
}

void die(const char* s)
{
	perror(s);
	exit(EXIT_FAILURE);
}

void init_cn()
{
	size_t i;
	for (i = 0; i < sizeof(cn)/sizeof(cn[0]); ++i) {
		cn[i] = "unknown";
	}
	cn[231] = "exit_group";
	cn[158] = "arch_prctl";
	cn[60] = "exit";
	cn[59] = "execve";
	cn[21] = "access";
	cn[15] = "rt_sigreturn";
	cn[12] = "brk";
	cn[11] = "munmap";
	cn[10] = "mprotect";
	cn[9] = "mmap";
	cn[5] = "fstat";
	cn[3] = "close";
	cn[2] = "open";
	cn[1] = "write";
	cn[0] = "read";
}

int read_child_string(char* buf, int len, pid_t pid, char* s) {
	int i = 0;
	char *p = buf;
	for (i = 0; i < len; ++i) {
		buf[i] = ptrace(PTRACE_PEEKDATA, pid, s++, NULL);
	}
	buf[i] = '\0';
	return i;
}

int check_path(pid_t pid, char* s)
{
	int i;
	char buf[MAX_PATH];

	int len = read_child_string(buf, sizeof(buf), pid, s);
	if (strncmp(child_prog_name, buf, len) == 0) return 1;

	for (i = 0; ok_path[i]; ++i) {
		if (strncmp(ok_path[i], buf, len) == 0) return 1;
	}
	return 0;
}

int check_open_flags(long f) {
	return 0 == (f & ~(O_CLOEXEC | O_RDONLY));
}

void drop_rights()
{
	prctl(PR_SET_NO_NEW_PRIVS, 1);
	prctl(PR_SET_DUMPABLE, 0);
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);

	seccomp_rule_add(ctx, SCMP_ACT_TRACE(231), SCMP_SYS(exit_group), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(158), SCMP_SYS(arch_prctl), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(60), SCMP_SYS(exit), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(59), SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(21), SCMP_SYS(access), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(15), SCMP_SYS(rt_sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(12), SCMP_SYS(brk), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(11), SCMP_SYS(munmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(10), SCMP_SYS(mprotect), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(9), SCMP_SYS(mmap), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(5), SCMP_SYS(fstat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(3), SCMP_SYS(close), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(2), SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(write), 0);
	seccomp_rule_add(ctx, SCMP_ACT_TRACE(0), SCMP_SYS(read), 0);

	seccomp_load(ctx);
	seccomp_release(ctx);
}

void set_limits()
{
	struct rlimit rl;
	rl.rlim_cur = rl.rlim_max = 1;
	setrlimit(RLIMIT_CPU, &rl);
}

void child() {
	int efd = open(child_prog_name, O_CLOEXEC | O_RDONLY);
	if (efd == -1) die("open");

	set_limits();
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) die("ptrace");
	kill(getpid(), SIGSTOP);
	drop_rights();

	char* const e_argv[] = { child_prog_name, NULL };
	fexecve(efd, e_argv, environ);
	perror("fexecve");
}

int parent(pid_t child)
{
	int st;
	waitpid(child, &st, __WALL);

	if (!WSTOPSIG(st)) return 1;
	ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP);
	ptrace(PTRACE_CONT, child, NULL, NULL);

	while(1) {
		long a[6] = { 0, 0, 0, 0, 0, 0 };
		long ret = 0, c = 0;
		st = 0;

		waitpid(child, &st, 0);
		if (WIFEXITED(st)) return 0;
		if (WIFSIGNALED(st)) {
			if (WTERMSIG(st) == SIGKILL) {
				printf("TLE\n");
			} else {
				printf("ERROR\n");
			}
			return 1;
		}
		c = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
		ret = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
		a[0] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI);
		a[1] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSI);
		a[2] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDX);
		a[3] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RCX);
		a[4] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*R8);
		a[5] = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*R9);
		if (c == 2) {
			if (!check_path(child, (char*)a[0])
				|| !check_open_flags(a[1]))
			{
				ptrace(PTRACE_POKEUSER, child,
					sizeof(long)*ORIG_RAX, -1);
			}
		}
		ptrace(PTRACE_CONT, child, NULL, NULL);
	}
}

int main(int argc, char** argv)
{
	int exit_value = 0;
	pid_t pid = 0;

	if (argc < 2) usage(argv[0]);
	child_prog_name = argv[1];
	
	init_cn();

	pid = fork();
	if (pid == -1) {
		die("fork");
	} else if (pid == 0) {
		child();
	} else {
		exit_value = parent(pid);
	}

	return exit_value;
}
