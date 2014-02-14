import time

from defines import *
from clibs import ls_kernel, spawn, libc, middleware_c
import middleware


def exc_to_str(exc):
    exc_dict = {1: "EXC_BAD_ACCESS",
                2: "EXC_BAD_INSTRUCTION",
                3: "EXC_ARITHMETIC",
                4: "EXC_EMULATION",
                5: "EXC_SOFTWARE",
                6: "EXC_BREAKPOINT",
                7: "EXC_SYSCALL",
                8: "EXC_MACH_SYSCALL",
                9: "EXC_RPC_ALERT",
                10: "EXC_CRASH",
                11: "EXC_RESOURCE"}
    return exc_dict[exc]


_exc_result = None


def _exc_callback():
    # print "Got exception! %s (%d)" % (exc_to_str(int(data)), data)
    global _exc_result
    get_result = middleware_c.get_result
    get_result.restype = middleware_result
    _exc_result = get_result()


def basic_handler(event):
    print event


class DebugEvent:

    def __init__(self, struct):
        self.exception_port = struct.exception_port
        self.thread = struct.thread
        self.task = struct.task
        self.exception = struct.exception
        self.code = []
        for i in range(struct.codeCnt):
            self.code.append(struct.code[i])

    def __str__(self):
        string = "Debug event:\n"
        string += "\tException: %s (%d)\n" % (exc_to_str(self.exception),
                                              self.exception)
        string += "\tCodes:"
        for code in self.code:
            string += " 0x%.16x" % code
        string += "\n"
        try:
            string += "\t       %s at 0x%.16x\n" % (ret_dict[self.code[0]],
                                           self.code[1])
        except KeyError:
            pass
        string += "\tException port: %d\n" % self.exception_port
        string += "\tTask port: %d\n" % self.task
        string += "\tThread port: %d\n" % self.thread

        return string


class Task:

    def __init__(self, p, e=None):
        self.port = p
        self.eport = e
        self.exc_handler = _exc_callback

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
        # try:
        #     while True:
        #         time.sleep(1)
        # except KeyboardInterrupt:
        #     self.suspend()

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

    def listen(self, timeout=None):
        if self.eport is not None:
            msg = macdll_msg_t()
            _timeout = 0
            if timeout is not None:
                options = MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT
                _timeout = timeout
            else:
                options = MACH_RCV_MSG | MACH_RCV_LARGE

            ret = MACH_RCV_TIMED_OUT
            ret = ls_kernel.mach_msg(byref(msg.head),
                                     options,
                                     0,
                                     sizeof(msg),
                                     mach_port_t(self.eport),
                                     _timeout,
                                     MACH_PORT_NULL)
            assert ret == MACH_MSG_SUCCESS

            reply = macdll_reply_t()
            middleware.set_callback(self.exc_handler)
            middleware_c.mach_exc_server(byref(msg), byref(reply))
            result = DebugEvent(_exc_result)
            return result


class Register:

    def __init__(self, name, val):
        self.name = name
        self.val = val

    def __str__(self):
        return "%s: %s" % (self.name, hex(self.val)[:-1])

    def __int__(self):
        return self.val


class ThreadState:

    def __init__(self, state):
        registers = [Register(tup[0], state.__getattribute__(tup[0]))
                     for tup in state._fields_]
        for reg in registers:
            setattr(self, reg.name, reg)

    def __str__(self):
        string = ""
        for reg in vars(self).values():
            string += str(reg) + "\n"
        string = string[:-1]
        return string

    def struct(self):
        state_struct = x86_thread_state64_t()
        registers = vars(self).values()
        for reg in registers:
            setattr(state_struct, reg.name, int(reg))

        return state_struct


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

    def get_state(self):
        thread = mach_port_t(self.port)
        flavor = x86_THREAD_STATE64
        state = x86_thread_state64_t()
        count = x86_THREAD_STATE64_COUNT
        ls_kernel.thread_get_state(thread, flavor, byref(state), byref(count))
        return ThreadState(state)

    def set_state(self, state):
        thread = mach_port_t(self.port)
        flavor = x86_THREAD_STATE64
        state = state.struct()
        count = x86_THREAD_STATE64_COUNT
        ls_kernel.thread_set_state(thread, flavor, byref(state), count)


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
