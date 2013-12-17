from defines import *
from clibs import ls_kernel, spawn, libc


class Task:

    def __init__(self, p, e=None):
        self.port = p
        self.eport = e

    def info(self):
        task_port_struct = mach_port_t(self.port)
        ti = mach_task_basic_info()
        size = c_uint(sizeof(mach_task_basic_info))

        ls_kernel.task_info(task_port_struct, MACH_TASK_BASIC_INFO,
                            byref(ti), byref(size))

        print "[++] Suspend count: %s" % ti.suspend_count
        print "[++] Policy: %d" % ti.policy

    def resume(self):
        task_port_struct = mach_port_t(self.port)
        print "[*] Resuming task %d..." % self.port
        ls_kernel.task_resume(task_port_struct)

    def suspend(self):
        task_port_struct = mach_port_t(self.port)
        print "[*] Suspending task %d..." % self.port
        ls_kernel.task_suspend(task_port_struct)

    def threads(self):
        thread_list = POINTER(mach_port_t)()
        thread_count = c_uint()
        task_port_struct = mach_port_t(self.port)

        print "[*] Getting threads for task %d..." % self.port

        ls_kernel.task_threads(task_port_struct, byref(thread_list),
                               byref(thread_count))
        threads = []
        for i in range(thread_count.value):
            threads.append(Thread(thread_list[i]))

        return threads

    def attach(self):
        if self.eport is None:
            task_port_struct = mach_port_t(self.port)
            print "[*] Getting exception port on task %d..." % self.port
            eport_struct = mach_port_t()
            mask = exception_mask_t(EXC_MASK_BAD_ACCESS |
                                    EXC_MASK_BAD_INSTRUCTION |
                                    EXC_MASK_ARITHMETIC | EXC_MASK_SOFTWARE |
                                    EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL)
            me = ls_kernel.mach_task_self()
            ls_kernel.mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE,
                                         byref(eport_struct))
            ls_kernel.mach_port_insert_right(me, eport_struct, eport_struct,
                                             MACH_MSG_TYPE_MAKE_SEND)
            ls_kernel.task_set_exception_ports(task_port_struct, mask,
                                               eport_struct,
                                               EXCEPTION_DEFAULT |
                                               MACH_EXCEPTION_CODES,
                                               THREAD_STATE_NONE)
            print "[++] Exception port: %d" % eport_struct.value
            self.eport = eport_struct.value
        else:
            print ("[--] Task %d already has an exception port (%d)!"
                   % (self.port, self.eport))

    # def listen(self, timeout):
    #     if self.eport is not None:
    #         reply = macdll_reply_t()
    #         ls_kernel.mach_msg(

class Thread:

    def __init__(self, p):
        self.port = p

    def info(self):
        p = mach_port_t(self.port)
        ti = thread_basic_info()
        size = c_uint(sizeof(thread_basic_info))

        print "[*] Getting info for thread %d..." % self.port

        ls_kernel.thread_info(p, THREAD_BASIC_INFO, byref(ti), byref(size))

        print "[++] Run state: %s" % th_state_dict[ti.run_state]
        print "[++] Suspend count: %s" % ti.suspend_count
        print "[++] Policy: %d" % ti.policy
        print "[++] Flags: 0x%0.08x" % ti.flags

    def resume(self):
        thread_port_struct = mach_port_t(self.port)
        print "[*] Resuming thread %d..." % self.port
        ls_kernel.thread_resume(thread_port_struct)

    def suspend(self):
        thread_port_struct = mach_port_t(self.port)
        print "[*] Suspending thread %d..." % self.port
        ls_kernel.thread_suspend(thread_port_struct)


class TaskForPidException(Exception):

    def __init__(self, pid):
        self.pid = pid

    def __str__(self):
        return ("Task port could not be retrieved for process %d. Are you "
                "root?" % self.pid)


class Process:

    def __init__(self, pid):
        self.pid = pid
        self._task = None

    def task(self):
        if self._task is None:
            task_port_struct = mach_port_t()
            print "[*] Getting task port on process %d..." % self.pid
            ls_kernel.task_for_pid(ls_kernel.mach_task_self(), self.pid,
                                   byref(task_port_struct))
            if task_port_struct.value is not None:
                print "[++] Task port: %d" % task_port_struct.value
                self._task = Task(task_port_struct.value)
            else:
                raise TaskForPidException(self.pid)
        return self._task

    def cont(self):
        ls_kernel.kill(self.pid, SIGCONT)

    def kill(self):
        ls_kernel.kill(self.pid, SIGKILL)

    def stop(self):
        ls_kernel.kill(self.pid, SIGSTOP)


class Debugger:

    def __init__(self):
        self.process = None

    # def wait(self):
    #   try:
    #       print "[*] Waiting for process %d..." % self.pid
    #       ls_kernel.wait4(self.pid, None, None, None)
    #   except KeyboardInterrupt:
    #       print " [--] Interrupted!"

    # def debug_wait(self):
    #     print "[*] Listening for events on %d..." % self.exception_port

    def attach(self, pid):
        if self.process is None:
            self.process = Process(pid)
            self.process.task().attach()
        else:
            print ("[--] Already associated with process %d!"
                   % self.process.pid)

    def load(self, path_to_exe):
        print "[*] Loading executable \"%s\"..." % path_to_exe
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

        pid_struct = pid_t()

        spawn_ret = spawn.posix_spawn(byref(pid_struct), path_to_exe, None,
                                      byref(attr), None, None)

        print ("[++] We have successfully loaded the process! PID: %d"
               % pid_struct.value)

        self.attach(pid_struct.value)
