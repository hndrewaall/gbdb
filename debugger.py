import time
import threading
import Queue

from defines import *
from clibs import ls_kernel, spawn, libc, middleware_c
from disassemble import decode_bytes
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


exc_queue = Queue.Queue()


def _exc_callback():
    global exc_queue
    get_result = middleware_c.get_result
    get_result.restype = middleware_result
    exc_queue.put(DebugEvent(get_result()))


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


class Listener(threading.Thread):

    def __init__(self, eport, timeout=None):
        threading.Thread.__init__(self)
        self.daemon = True
        self.eport = eport
        self.timeout = timeout
        self.exc_handler = _exc_callback
        self.reply = None
        self.last_event = None

    def handle(self):
        print "[*] Handling debug event..."
        options = MACH_SEND_MSG
        _timeout = 0
        if self.timeout is not None:
            _timeout = self.timeout
            options |= MACH_RCV_TIMEOUT

        ls_kernel.mach_msg(byref(self.reply),
                           options,
                           sizeof(self.reply),
                           0,
                           MACH_PORT_NULL,
                           _timeout,
                           MACH_PORT_NULL)

    def wait(self):
        global exc_queue
        print "[*] Waiting for debug event..."
        event = exc_queue.get()
        print "[++] Got debug event!"
        self.last_event = event
        return event

    def get_result(self):
        return self.last_event

    def run(self):
        if self.eport is not None:
            msg = macdll_msg_t()
            self.reply = macdll_reply_t()
            while True:
                options = MACH_RCV_MSG | MACH_RCV_LARGE
                _timeout = 0

                if self.timeout is not None:
                    options |= MACH_RCV_TIMEOUT
                    _timeout = self.timeout
                ls_kernel.mach_msg(byref(msg.head),
                                   options,
                                   0,
                                   sizeof(msg),
                                   mach_port_t(self.eport),
                                   _timeout,
                                   MACH_PORT_NULL)

                middleware.set_callback(self.exc_handler)
                middleware_c.mach_exc_server(byref(msg), byref(self.reply))
        else:
            raise Exception


class Task:

    def __init__(self, p, process, e=None):
        self.port = p
        self.eport = e
        self.process = process
        self.old_exc_port = None
        self.breakpoints = {}
        self.listener = None

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

        # print "[*] Getting threads for task %d..." % self.port

        ls_kernel.task_threads(task_port_struct, byref(thread_list),
                               byref(thread_count))
        threads = []
        for i in range(thread_count.value):
            threads.append(Thread(thread_list[i], self))

        return threads

    def attach(self):
        if self.eport is None:
            task_port_struct = mach_port_t(self.port)
            print "[*] Getting exception port on task %d..." % self.port
            eport_struct = mach_port_t()
            mask = exception_mask_t(EXC_MASK_ALL)
            # mask = EXC_MASK_BAD_ACCESS;
            me = ls_kernel.mach_task_self()
            ls_kernel.mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE,
                                         byref(eport_struct))
            ls_kernel.mach_port_insert_right(me, eport_struct, eport_struct,
                                             MACH_MSG_TYPE_MAKE_SEND)
            old_ports = old_exc_ports_t()

            # hackity hack hack
            count = c_uint()
            count_p = pointer(count)

            ls_kernel.task_swap_exception_ports(task_port_struct, mask,
                                                eport_struct,
                                                EXCEPTION_DEFAULT |
                                                MACH_EXCEPTION_CODES,
                                                x86_THREAD_STATE,
                                                old_ports.masks,
                                                count_p,
                                                old_ports.ports,
                                                old_ports.behaviors,
                                                old_ports.flavors)
            old_ports.count = count_p.contents
            print "[++] Exception port: %d" % eport_struct.value
            self.old_exc_port = old_ports
            self.eport = eport_struct.value
        else:
            print ("[--] Task %d already has an exception port (%d)!"
                   % (self.port, self.eport))

    def detach(self):
        if self.eport is not None:
            me = ls_kernel.mach_task_self()
            task_port_struct = mach_port_t(self.port)
            ls_kernel.mach_port_deallocate(me, self.eport)

    def listen(self, timeout=None):
        listener = Listener(self.eport, timeout)
        listener.start()
        self.listener = listener

    def read_bytes(self, addr, length):
        task = mach_port_t(self.port)
        dest_addr = c_uint64()
        read_size = mach_msg_type_number_t()
        address = mach_vm_address_t(addr)
        ls_kernel.mach_vm_read(task, address, length, byref(dest_addr),
                               byref(read_size))
        byte_struct = (c_ubyte * read_size.value)()
        libc.memcpy(byte_struct, dest_addr, read_size)
        byte_array = []
        for byte in byte_struct:
            byte_array.append(byte)
        return byte_array

    def write_bytes(self, addr, bytes):
        task = mach_port_t(self.port)
        address = mach_vm_address_t(addr)
        byte_struct = (c_ubyte * len(bytes))(*bytes)
        ls_kernel.mach_vm_write(task, address, byte_struct, len(bytes))

    def print_bytes(self, addr, length):
        byte_array = self.read_bytes(addr, length)
        byte_string = ''
        for byte in byte_array:
            byte_string += '%0.02X ' % byte
        print byte_string[:-1]

    def set_bp(self, addr):
        self.breakpoints[addr] = Breakpoint(addr, self)

    def get_protection(self, addr):
        task = mach_port_t(self.port)
        address = mach_vm_offset_t(addr)
        size = mach_vm_size_t(1)
        flavor = VM_REGION_BASIC_INFO_64
        info_struct = vm_region_basic_info_64()
        size = mach_msg_type_number_t(sizeof(vm_region_basic_info_64))
        out = mach_port_t()

        ls_kernel.mach_vm_region(task, byref(address), byref(size), flavor,
                                 byref(info_struct), byref(size), byref(out))

        prot_mask = info_struct.protection
        prot_string = ''
        if prot_mask & VM_PROT_READ:
            prot_string += 'r'
        if prot_mask & VM_PROT_WRITE:
            prot_string += 'w'
        if prot_mask & VM_PROT_EXECUTE:
            prot_string += 'x'

        return prot_string

    def set_protection(self, addr, prot_string):
        task = mach_port_t(self.port)
        address = mach_vm_offset_t(addr)
        size = mach_vm_size_t(1)
        set_maximum = boolean_t(0)

        prot_mask = 0
        if 'r' in prot_string:
            prot_mask |= VM_PROT_READ
        if 'w' in prot_string:
            prot_mask |= VM_PROT_WRITE
        if 'x' in prot_string:
            prot_mask |= VM_PROT_EXECUTE
        new_protection = vm_prot_t(prot_mask)

        ls_kernel.mach_vm_protect(task, address, size, set_maximum,
                                  new_protection)


class Register:

    def __init__(self, name, val, size=64):
        self.name = name
        self.val = val
        self.size = size

    def __str__(self):
        return "%s: %s" % (self.name, hex(self.val)[:-1])

    def __int__(self):
        return self.val

    def __iadd__(self, other):
        self.val += int(other) % 2**self.size
        return self

    def __isub__(self, other):
        self.val -= int(other) % 2**self.size
        return self

    def __add__(self, other):
        return (self.val + int(other)) % 2**self.size

    def __sub__(self, other):
        return (self.val - int(other)) % 2**self.size

    def __iand__(self, other):
        self.val &= int(other) % 2**self.size
        return self

    def __ior__(self, other):
        self.val |= int(other) % 2**self.size
        return self

    def __invert__(self):
        return ~self.val % 2**self.size


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

    def __init__(self, p, task):
        self.port = p
        self.task = task

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

    def clear_signals(self):
        print "[*] Clearing POSIX signals on thread %d..." % self.port
        thread_port_struct = mach_port_t(self.port)
        ls_kernel.ptrace(PT_THUPDATE, self.task.process.pid,
                         thread_port_struct, 0)

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

    def cont(self):
        task = self.task
        listener = task.listener
        listener.wait()
        state = self.get_state()
        curr_addr = state.rip - 1

        try:
            breakpoint = self.task.breakpoints[curr_addr]
        except KeyError:
            print "No breakpoint found, continuing anyway"
            listener.handle()
            listener.wait()
            self.clear_signals()
            listener.handle()
        else:
            breakpoint.disable()
            listener.handle()
            self.suspend()
            listener.wait()
            self.clear_signals()
            listener.handle()
            state = self.get_state()
            state.rip -= 1
            self.set_state(state)
            self.enable_ss()
            self.resume()
            listener.wait()
            listener.handle()
            self.suspend()
            listener.wait()
            self.clear_signals()
            listener.handle()
            breakpoint.enable()
            self.disable_ss()
            self.resume()

    def enable_ss(self):
        print "[*] Enabling single-step on thread %d..." % self.port
        state = self.get_state()
        state.rflags |= 0x100
        self.set_state(state)

    def disable_ss(self):
        print "[*] Disabling single-step on thread %d..." % self.port
        state = self.get_state()
        state.rflags &= ~0x100
        self.set_state(state)


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
                self._task = Task(task_port_struct.value, self)
            else:
                raise TaskForPidException(self.pid)
        return self._task

    def cont(self):
        ls_kernel.kill(self.pid, SIGCONT)

    def kill(self):
        ls_kernel.kill(self.pid, SIGKILL)

    def stop(self):
        ls_kernel.kill(self.pid, SIGSTOP)

    def attach(self):
        ls_kernel.ptrace(PT_ATTACHEXC, self.pid, 0, 0)
        self.task().attach()


class Breakpoint:

    def enable(self):
        print "Enabling breakpoint at 0x%0.16X..." % self.addr
        prot = self.task.get_protection(self.addr)
        self.task.set_protection(self.addr, prot + 'w')
        self.task.write_bytes(self.addr, [0xcc])
        self.task.set_protection(self.addr, prot)

    def disable(self):
        print "Disabling breakpoint at 0x%0.16X..." % self.addr
        prot = self.task.get_protection(self.addr)
        self.task.set_protection(self.addr, prot + 'w')
        self.task.write_bytes(self.addr, [self.orig_instr])
        self.task.set_protection(self.addr, prot)

    def __init__(self, addr, task):
        self.addr = addr
        self.task = task
        self.orig_instr = task.read_bytes(addr, 1)[0]
        self.enable()

    def __del__(self):
        self.disable()


class Debugger:

    def __init__(self):
        self.process = None

    def attach(self, pid):
        if self.process is None:
            self.process = Process(pid)
            self.process.attach()
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

    def set_bp(self, addr):
        self.process.task.set_bp(addr)

    def disassemble(self, addr=None, num_bytes=20):
        task = self.process.task()
        thread = task.threads()[0]
        if addr is None:
            addr = thread.get_state().rip.val
        bytes = task.read_bytes(addr, num_bytes)
        instructions = decode_bytes(bytes)
        output = "\nDisassembling %d bytes at 0x%.08X:\n\n" % (num_bytes, addr)
        output += ("Address             Instruction"
                   "                             Bytes\n")
        output += ("--------------      ------------------------------"
                   "          ---------------\n")
        curr_addr = addr
        for inst in instructions:
            text = inst[2].upper()
            text = text.replace('0X', '0x')
            output += "0x{0:<18X}{1:<40}{2}\n".format(curr_addr,
                                                      text,
                                                      inst[3].upper())
            curr_addr += inst[1]
        print output
