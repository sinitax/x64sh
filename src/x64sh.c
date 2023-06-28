#define _GNU_SOURCE

#include "xed-util.h"
#include <bits/types/siginfo_t.h>
#define XED_ENCODER

#include "bestline.h"
#include "xed-encode.h"
#include "xed-encoder-hl.h"
#include "xed-examples-util.h"
#include "xed-asmparse.h"
#define XED_ASMPARSE_H
#include "xed-asmparse-main.h"

#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static struct {
	pid_t pid;
	struct user_regs_struct regs;
	size_t rip_initial;
} tracee = { -1, { 0 }, 0 };

static uint8_t *mem = NULL;
static size_t memsize = 0x1000;

static bool inplace = false;

static void
__attribute__((noreturn))
__attribute__((format(printf, 1, 2)))
die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("x64sh: ", stderr);
	vfprintf(stderr, fmt, ap);
	if (*fmt && fmt[strlen(fmt)-1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	} else {
		fputc('\n', stderr);
	}
	va_end(ap);

	exit(1);
}

static void
__attribute__((noreturn))
unreachable(void)
{
	fputs("x64sh: reached unreachable\n", stderr);
	abort();
}

static const char *
ptrace_info(enum __ptrace_request req, pid_t pid)
{
	switch (req) {
	case PTRACE_TRACEME:
		return "TRACEME";
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		return "PEEKDATA";
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		return "POKEDATA";
	case PTRACE_CONT:
		return "CONT";
	case PTRACE_ATTACH:
		return "ATTACH";
	case PTRACE_SINGLESTEP:
		return "SINGLESTEP";
	default:
		return "...";
	}
}

static long
ptrace_chk(enum __ptrace_request req, pid_t pid, void *addr, void *data)
{
	long ret;

	errno = 0;
	ret = ptrace(req, pid, addr, data);
	if (errno) die("ptrace(%s):", ptrace_info(req, pid));

	return ret;
}

static void
waitstop(pid_t pid)
{
	int status, ret;

	do {
		ret = waitpid(pid, &status, 0);
		if (ret < 0 && errno != EINTR)
			die("waitstop:");
	} while (!WIFSTOPPED(status) && !WIFEXITED(status) && !WIFSIGNALED(status));

	if (WIFEXITED(status)) die("waitstop: child died");
	if (WIFSIGNALED(status)) die("waitstop: child killed");
}

static void
run(void)
{
	union {
		xed_uint8_t bytes[16]; /* XED_MAX_INSTRUCTION_BYTES+1 */
		uint16_t words[8];
	} buf;
	xed_enc_line_parsed_t *enc_line;
	xed_uint_t i, len;
	siginfo_t siginfo;
	char *line;

	if (tracee.pid < 0) {
		mem = mmap(NULL, memsize, PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (mem == MAP_FAILED) die("mmap(%lu):", memsize);

		tracee.pid = fork();
		if (tracee.pid < 0) die("fork:");

		if (!tracee.pid) {
			ptrace_chk(PTRACE_TRACEME, 0, NULL, NULL);
			raise(SIGSTOP);
			unreachable();
		}
		waitstop(tracee.pid);

		ptrace_chk(PTRACE_GETREGS, tracee.pid, NULL, &tracee.regs);
		tracee.regs.rip = (uintptr_t) mem;
		ptrace_chk(PTRACE_SETREGS, tracee.pid, NULL, &tracee.regs);
	} else {
		/* TODO: if -m map region into target process and set rip */

		ptrace_chk(PTRACE_ATTACH, tracee.pid, NULL, NULL);
		waitstop(tracee.pid);

		ptrace_chk(PTRACE_GETREGS, tracee.pid, NULL, &tracee.regs);
	}

	tracee.rip_initial = tracee.regs.rip;
	len = 0;

	while ((line = bestlineWithHistory("$ ", "x64sh"))) {
		enc_line = asp_get_xed_enc_node();
		enc_line->mode = 64;
		enc_line->input = strdup(line);
		if (!enc_line->input) die("strdup:");

		if (*line) {
			asp_parse_line(enc_line);

			asp_print_parsed_line(enc_line);

			for (i = 0; i < 8; i++)
				buf.words[i] = (uint16_t)
					ptrace_chk(PTRACE_PEEKTEXT, tracee.pid,
					(void *) tracee.regs.rip + 2 * i, NULL);

			len = xed_asmparse_encode(enc_line, buf.bytes, 16);
			if (!len) goto next;
		} else {
			enc_line = NULL;
			if (!len) goto next;
		}

		for (i = 0; i < 8; i++) {
			ptrace_chk(PTRACE_POKETEXT, tracee.pid,
				(void *) tracee.regs.rip + 2 * i,
				(void *) (uintptr_t) buf.words[i]);
		}

		printf("MEM: ");
		for (i = 0; i < 16; i++)
			printf("%02x", buf.bytes[i]);
		printf("\n");

		printf("stepping..");
		fflush(stdout);
		ptrace_chk(PTRACE_SINGLESTEP, tracee.pid, NULL, NULL);
		waitstop(tracee.pid);
		printf("done\n");

		memset(&siginfo, 0, sizeof(siginfo_t));
		ptrace_chk(PTRACE_GETSIGINFO, tracee.pid, NULL, &siginfo);
		if (siginfo.si_signo != SIGTRAP)
			printf("SIGNAL: SIG%s (%s)\n", sigabbrev_np(siginfo.si_signo), strsignal(siginfo.si_signo));

		ptrace_chk(PTRACE_GETREGS, tracee.pid, NULL, &tracee.regs);

		if (inplace) {
			tracee.regs.rip = tracee.rip_initial;
			ptrace_chk(PTRACE_SETREGS, tracee.pid, NULL, &tracee.regs);
		}

		printf("RIP: %016llx\n", tracee.regs.rip);
		printf("RAX: %016llx    R8:  %016llx\n", tracee.regs.rax, tracee.regs.r8);
		printf("RBX: %016llx    R9:  %016llx\n", tracee.regs.rbx, tracee.regs.r9);
		printf("RCX: %016llx    R10: %016llx\n", tracee.regs.rcx, tracee.regs.r10);
		printf("RDX: %016llx    R11: %016llx\n", tracee.regs.rdx, tracee.regs.r11);
		printf("RDI: %016llx    R12: %016llx\n", tracee.regs.rdi, tracee.regs.r12);
		printf("RSI: %016llx    R13: %016llx\n", tracee.regs.rsi, tracee.regs.r13);
		printf("RBP: %016llx    R14: %016llx\n", tracee.regs.rbp, tracee.regs.r14);
		printf("RSP: %016llx    R15: %016llx\n", tracee.regs.rsp, tracee.regs.r15);

next:
		if (enc_line) asp_delete_xed_enc_line_parsed_t(enc_line);
		free(line);
	}
}

int
main(int argc, char **argv)
{
	char **arg, *end;

	for (arg = argv + 1; *arg; arg++) {
		if (!strcmp(*arg, "-h") || !strcmp(*arg, "--help")) {
			printf("Usage: x64sh [-h] [-i] [-p PID] [-m SIZE]\n");
			return 0;
		} else if (!strcmp(*arg, "-p")) {
			tracee.pid = (pid_t) strtol(*++arg, &end, 10);
			if (!end || *end) die("bad -p arg '%s'", *arg);
		} else if (!strcmp(*arg, "-i")) {
			inplace = true;
		} else if (!strcmp(*arg, "-q")) {
			asp_set_verbosity(0);
		} else if (!strcmp(*arg, "-v")) {
			asp_set_verbosity(1);
		} else if (!strcmp(*arg, "-vv")) {
			asp_set_verbosity(2);
		} else if (!strcmp(*arg, "-m")) {
			memsize = strtoull(*++arg, &end, 10);
			if (!end || *end) die("bad -m arg '%s'", *arg);
		} else {
			die("invalid arg '%s'", *arg);
		}
	}

	xed_asmparse_setup();

	run();

	if (mem) munmap(mem, memsize);
}
