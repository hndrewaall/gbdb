from defines import *
from ctypes import cdll
from ctypes.util import find_library


# def _print_kern_err(e):
    # print "[**] Kernel error 0x%0.08x: %s\n" % (e, kern_ret_dict[e])


class KernException(Exception):
    def __init__(self, ret):
        self.ret = ret

    def __str__(self):
        return "Kernel error 0x%0.08x: %s\n" % (self.ret,
                                                kern_ret_dict[self.ret])


def kern_check(ret):
    if ret != 0:
        raise KernException(ret)


ls_kernel = cdll.LoadLibrary(find_library("ls_kernel"))
ls_kernel.restype = kern_check

spawn = cdll.LoadLibrary(find_library("spawn"))
libc = cdll.LoadLibrary(find_library("libc"))


class thread():

    def __init__(self, p):
        self.port = p


class Debugger():

    def __init__(self):
        # self.h_process            =   None
        self.pid = None
        self.task_port = None
        self.exception_port = None
        # self.debugger_active  =   False
        pass

    def cont(self):
        ls_kernel.kill(self.pid, SIGCONT)

    def kill(self):
        ls_kernel.kill(self.pid, SIGKILL)

    def stop(self):
        ls_kernel.kill(self.pid, SIGSTOP)

    def _debug_process(self, pid):

        task_port = mach_port_t()
        print "[*] Getting task port on process %d..." % pid
        ls_kernel.task_for_pid(ls_kernel.mach_task_self(), pid,
                               byref(task_port))
        print "[**] Task port: %d" % task_port.value
        self.task_port = task_port.value

        print "[*] Getting exception port on process %d..." % pid
        eport = mach_port_t()
        mask = exception_mask_t(EXC_MASK_BAD_ACCESS |
                                EXC_MASK_BAD_INSTRUCTION |
                                EXC_MASK_ARITHMETIC | EXC_MASK_SOFTWARE |
                                EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL)
        me = ls_kernel.mach_task_self()
        ls_kernel.mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE,
                                     byref(eport))
        ls_kernel.mach_port_insert_right(me, eport, eport,
                                         MACH_MSG_TYPE_MAKE_SEND)
        ls_kernel.task_set_exception_ports(task_port, mask, eport,
                                           EXCEPTION_DEFAULT |
                                           MACH_EXCEPTION_CODES,
                                           THREAD_STATE_NONE)
        print "[**] Exception port: %d" % eport.value
        self.exception_port = eport.value
        self.pid = pid

    def get_threads(self):
        thread_list = POINTER(mach_port_t)()
        thread_count = c_uint()
        port = mach_port_t(self.task_port)

        print "[*] Getting thread info for process %d..." % self.pid

        ls_kernel.task_threads(port, byref(thread_list), byref(thread_count))

        # print ("[**] There are %d threads in process %d" %
        #        (thread_count.value, self.pid))

        threads = []

        for i in range(thread_count.value):
            # print "[**] Thread %d port: %d" % (i, thread_list[i])
            threads.append(thread(thread_list[i]))

        return threads

    def get_thread_info(self, thread):
        p = mach_port_t(thread.port)
        ti = thread_basic_info()
        size = c_uint(sizeof(thread_basic_info))

        print "[*] Getting info for thread %d..." % thread.port

        ls_kernel.thread_info(p, THREAD_BASIC_INFO, byref(ti), byref(size))

        print "[**] Run state: %s" % th_state_dict[ti.run_state]
        print "[**] Suspend count: %s" % ti.suspend_count
        print "[**] Policy: %d" % ti.policy
        print "[**] Flags: 0x%0.08x" % ti.flags

    def get_task_info(self):
        task = mach_port_t(self.task_port)
        ti = mach_task_basic_info()
        size = c_uint(sizeof(mach_task_basic_info))

        ls_kernel.task_info(task, MACH_TASK_BASIC_INFO, byref(ti),
                            byref(size))

        print "[**] Suspend count: %s" % ti.suspend_count
        print "[**] Policy: %d" % ti.policy

    # def wait(self):
    #   try:
    #       print "[*] Waiting for process %d..." % self.pid
    #       ls_kernel.wait4(self.pid, None, None, None)
    #   except KeyboardInterrupt:
    #       print " [**] Interrupted!"

    def debug_wait(self):

        print "[*] Listening for events on %d..." % self.exception_port

    def task_resume(self):
        task = mach_port_t(self.task_port)
        print "[*] Resuming task %d..." % self.task_port
        ls_kernel.task_resume(task)

    def task_suspend(self):
        task = mach_port_t(self.task_port)

        print "[*] Suspending task %d..." % self.task_port

        ls_kernel.task_suspend(task)

    def attach(self, pid):
        self._debug_process(pid)

    def load(self, path_to_exe):

        # Run process and suspend it immediately

        # flags = c_short(POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGDEF
        #                 | POSIX_SPAWN_SETSIGMASK)
        flags = c_short(POSIX_SPAWN_START_SUSPENDED)
        attr = posix_spawnattr_t()

        spawn.posix_spawnattr_init(byref(attr))
        spawn.posix_spawnattr_setflags(byref(attr), flags)

        # no_signals = sigset_t()
        # all_signals = sigset_t()

        # libc.sigemptyset(byref(no_signals))
        # libc.sigfillset(byref(all_signals))
        # spawn.posix_spawnattr_setsigmask(byref(attr), byref(no_signals))
        # spawn.posix_spawnattr_setsigdefault(byref(attr), byref(all_signals

        pid = pid_t()

        spawn_ret = spawn.posix_spawn(byref(pid), path_to_exe, None,
                                      byref(attr), None, None)

        if spawn_ret != 0:
            print "[**] Error in posix_spawn: %d" % spawn_ret
            raise Exception()
        else:
            print "[*] We have successfully loaded the process!"
            print "[*] PID: %d" % pid.value

        self._debug_process(pid.value)
