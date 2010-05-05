#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Bug in gcc prevents from using CPP_DEMANGLE in pure "C" */
#if !defined(__cplusplus) && !defined(NO_CPP_DEMANGLE)
#define NO_CPP_DEMANGLE
#endif

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <dlfcn.h>
#include <execinfo.h>
#ifndef NO_CPP_DEMANGLE
#include <cxxabi.h>
#ifdef __cplusplus
/* use __cxa_demangle instead of stdc, might get names of functions too */
using __cxxabiv1::__cxa_demangle;
#endif
#endif

#ifdef HAS_ULSLIB
#include "uls/logger.h"
#define sigsegv_outp(x)         sigsegv_outp(,gx)
#else
#define sigsegv_outp(x, ...)    fprintf(stderr, x "\n", ##__VA_ARGS__)
#endif

#if defined(REG_RIP)
# define SIGSEGV_STACK_IA64
# define REGFORMAT "%016lx"
#elif defined(REG_EIP)
# define SIGSEGV_STACK_X86
# define REGFORMAT "%08x"
#else
# define SIGSEGV_STACK_ARM
# define REGFORMAT "%x"
#endif

static void signal_segv(int signum, siginfo_t* info, void*ptr) {
	static const char *si_codes[3] = {"", "SEGV_MAPERR", "SEGV_ACCERR"};

	int i, f = 0;
	ucontext_t *ucontext = (ucontext_t*)ptr;
	Dl_info dlinfo;
	void **bp = 0;
	void *ip = 0;

	sigsegv_outp("Segmentation Fault!");
	sigsegv_outp("info.si_signo = %d", signum);
	sigsegv_outp("info.si_errno = %d", info->si_errno);
	sigsegv_outp("info.si_code  = %d (%s)", info->si_code, si_codes[info->si_code]);
	sigsegv_outp("info.si_addr  = %p", info->si_addr);
#ifdef SIGSEGV_STACK_ARM
	/* sigcontext_t on ARM:
		unsigned long trap_no;
	        unsigned long error_code;
        	unsigned long oldmask;
		unsigned long arm_r0;
	        ...
        	unsigned long arm_r10;
	        unsigned long arm_fp;
        	unsigned long arm_ip;
	        unsigned long arm_sp;
	        unsigned long arm_lr;
	        unsigned long arm_pc;
	        unsigned long arm_cpsr;
	        unsigned long fault_address;
	*/
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,0 , ucontext->uc_mcontext.arm_r0);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,1 , ucontext->uc_mcontext.arm_r1);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,2 , ucontext->uc_mcontext.arm_r2);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,3 , ucontext->uc_mcontext.arm_r3);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,4 , ucontext->uc_mcontext.arm_r4);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,5 , ucontext->uc_mcontext.arm_r5);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,6 , ucontext->uc_mcontext.arm_r6);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,7 , ucontext->uc_mcontext.arm_r7);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,8 , ucontext->uc_mcontext.arm_r8);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,9 , ucontext->uc_mcontext.arm_r9);
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT,10 , ucontext->uc_mcontext.arm_r10);
		sigsegv_outp("FP       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_fp);
		sigsegv_outp("IP       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_ip);
		sigsegv_outp("SP       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_sp);
		sigsegv_outp("LR       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_lr);
		sigsegv_outp("PC       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_pc);
		sigsegv_outp("CPSR       = 0x" REGFORMAT, ucontext->uc_mcontext.arm_cpsr);
		sigsegv_outp("Fault Address       = 0x" REGFORMAT, ucontext->uc_mcontext.fault_address);
		sigsegv_outp("Trap no       = 0x" REGFORMAT, ucontext->uc_mcontext.trap_no);
		sigsegv_outp("Err Code       = 0x" REGFORMAT, ucontext->uc_mcontext.error_code);
		sigsegv_outp("Old Mask       = 0x" REGFORMAT, ucontext->uc_mcontext.oldmask);
#else
	for(i = 0; i < NGREG; i++)
		sigsegv_outp("reg[%02d]       = 0x" REGFORMAT, i, ucontext->uc_mcontext.gregs[i]);
#endif

#ifndef SIGSEGV_NOSTACK
#if defined(SIGSEGV_STACK_IA64) || defined(SIGSEGV_STACK_X86)
#if defined(SIGSEGV_STACK_IA64)
	ip = (void*)ucontext->uc_mcontext.gregs[REG_RIP];
	bp = (void**)ucontext->uc_mcontext.gregs[REG_RBP];
#elif defined(SIGSEGV_STACK_X86)
	ip = (void*)ucontext->uc_mcontext.gregs[REG_EIP];
	bp = (void**)ucontext->uc_mcontext.gregs[REG_EBP];
#endif

	sigsegv_outp("Stack trace:");
	while(bp && ip) {
		if(!dladdr(ip, &dlinfo))
			break;

		const char *symname = dlinfo.dli_sname;

#ifndef NO_CPP_DEMANGLE
		int status;
		char * tmp = __cxa_demangle(symname, NULL, 0, &status);

		if (status == 0 && tmp)
			symname = tmp;
#endif

		sigsegv_outp("% 2d: %p <%s+%lu> (%s)",
				++f,
				ip,
				symname,
				(unsigned long)ip - (unsigned long)dlinfo.dli_saddr,
				dlinfo.dli_fname);

#ifndef NO_CPP_DEMANGLE
		if (tmp)
			free(tmp);
#endif

		if(dlinfo.dli_sname && !strcmp(dlinfo.dli_sname, "main"))
			break;

		ip = bp[1];
		bp = (void**)bp[0];
	}
#else
	sigsegv_outp("Stack trace (non-dedicated):");
	char **strings;
	void *bt[20];
	int sz = backtrace(bt, 20);
	strings = backtrace_symbols(bt, sz);
	for(i = 0; i < sz; ++i)
		sigsegv_outp("%s", strings[i]);
#endif
	sigsegv_outp("End of stack trace.");
#else
	sigsegv_outp("Not printing stack strace.");
#endif
	_exit (-1);
}

static void __attribute__((constructor)) setup_sigsegv() {
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = signal_segv;
	action.sa_flags = SA_SIGINFO;
	if(sigaction(SIGSEGV, &action, NULL) < 0)
		perror("sigaction");
}
