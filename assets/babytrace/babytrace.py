#!/usr/bin/python
import sys
import os
from pwn import *
from ptrace import PtraceError
from ptrace.debugger import (PtraceDebugger, Application,
							 ProcessExit, ProcessSignal, NewProcessEvent, ProcessExecution)
from ptrace.syscall import (SYSCALL_NAMES, SYSCALL_PROTOTYPES,
							FILENAME_ARGUMENTS, SOCKET_SYSCALL_NAMES)
from ptrace.func_call import FunctionCallOptions
from optparse import OptionParser
from logging import getLogger, error
from ptrace.error import PTRACE_ERRORS, writeError
from ptrace.ctypes_tools import formatAddress
import threading
import re
from signal import SIGTRAP, SIGSTOP
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

sys_restart_syscall = 0
sys_exit = 1
sys_fork = 2
sys_close = 6
sys_creat = 8
sys_link = 9
sys_unlink = 10
sys_execve = 11
sys_chdir = 12
sys_stat = 18
sys_lseek = 19
sys_getpid = 20
sys_mount = 21
sys_stime = 25
sys_ptrace = 26
sys_fstat = 28
sys_pause = 29
sys_access = 33
sys_nice = 34
sys_sync = 36
sys_kill = 37
sys_rename = 38
sys_mkdir = 39
sys_rmdir = 40
sys_dup = 41
sys_pipe = 42
sys_brk = 45
sys_setpgid = 57
sys_olduname = 59
sys_dup2 = 63
sys_old_select = 82
sys_readlink = 85
sys_old_readdir = 89
sys_old_mmap = 90
sys_munmap = 91
sys_fsync = 118
sys_mprotect = 125
sys_flock = 143
sys_readv = 145
sys_writev = 146
sys_nanosleep = 162
sys_pread64 = 180
sys_pwrite64 = 181
sys_sigaltstack = 186
sys_sendfile = 187
sys_vfork = 190
sys_mmap_pgoff = 192
sys_fcntl64 = 221
sys_tkill = 238
sys_sendfile64 = 239
sys_clock_nanosleep = 267
sys_tgkill = 270
sys_mq_open = 277
sys_mq_unlink = 278
sys_kexec_load = 283
sys_openat = 295
sys_mkdirat = 296
sys_renameat = 302
sys_linkat = 303
sys_symlinkat = 304
sys_readlinkat = 305
sys_epoll_create1 = 329
sys_dup3 = 330
sys_pipe2 = 331
sys_recvmmsg = 337

BLACKLISTSYSCALL = [sys_restart_syscall, sys_exit, sys_fork, sys_close, sys_creat, sys_link, sys_unlink, sys_execve, sys_chdir, sys_stat, sys_lseek, sys_getpid, sys_mount, sys_stime, sys_ptrace, sys_fstat, sys_pause, sys_access, sys_nice, sys_sync, sys_kill, sys_rename, sys_mkdir, sys_rmdir, sys_dup, sys_pipe, sys_brk, sys_setpgid, sys_olduname, sys_dup2, sys_old_select, sys_readlink, sys_old_readdir, sys_old_mmap, sys_munmap, sys_fsync, sys_mprotect, sys_flock, sys_readv, sys_writev, sys_nanosleep, sys_pread64, sys_pwrite64, sys_sigaltstack, sys_sendfile, sys_vfork, sys_mmap_pgoff, sys_fcntl64, sys_tkill, sys_sendfile64, sys_clock_nanosleep, sys_tgkill, sys_mq_open, sys_mq_unlink, sys_kexec_load, sys_openat, sys_mkdirat, sys_renameat, sys_linkat, sys_symlinkat, sys_readlinkat, sys_epoll_create1, sys_dup3, sys_pipe2, sys_recvmmsg]

def checkEIP(process, eip):
	
	ins = process.readBytes(eip, 2)
		
	if ins=="\x0f\x34" or ins=="\xcd\x80":
		eax = process.getreg('rax')
		log.info("eip: %#x" % eip)
		log.info("eax: %#x" % eax)
		if eax==0xb:
			log.critical("Found sys_execve")
			return False
		elif eax==0x5:
			try:
				ebx = process.getreg('rbx')
				path = process.readCString(ebx, 0x100)[0]
			except:
				return False
			if re.match(".*flag.*",path):
				log.critical("Found sys_open %s" % path)
				return False
		elif eax in BLACKLISTSYSCALL:
			log.critical("Blacklist syscall")
			return False
		return True
	return True
	

def traceProcess(pid):
	log.info("[%d] Start Trace Process" % pid)
	dbg = PtraceDebugger()
	process = dbg.addProcess(pid, False)
	while 1:
		if process.running==False:	
			break
		try:
			eip = process.getreg('rip')
			if not checkEIP(process, eip):
				# log.info("[%d] Kill Process" % pid)
				break
		except:
			break
			# log.info("[%d] Error Kill Process" % pid)
			# if process.running==False:	
				# break
		process.singleStep()
		event = process.waitEvent()
		if str(event)=="Signal SIGSEGV":
			print("Signal SIGSEGV")
			break
	
	process.terminate()
	log.info("[%d] Finish Trace Process" % pid)

shellcode = raw_input("shellcode: ")
r = process("/home/babytrace/babytrace")
t = threading.Thread(target=traceProcess, args = (r.pid,))
t.start()
r.send(shellcode)
time.sleep(5)
r.close()
