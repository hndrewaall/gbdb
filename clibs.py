from ctypes import cdll
from ctypes.util import find_library
from defines import *


class KernException(Exception):

    def __init__(self, ret):
        self.ret = ret

    def __str__(self):
        string = ""
        try:
            string = "%s (%0.08x)\n" % (ret_dict[self.ret], self.ret)
        except KeyError:
            string = "Unknown error %0.08x\n" % self.ret
        return string


def kern_check(ret):
    if ret != 0:
        raise KernException(ret)
    return ret


_ls_kernel = cdll.LoadLibrary(find_library("ls_kernel"))
ls_kernel = lambda: None

# Functions we wanna check for errors
ls_kernel.task_info = _ls_kernel.task_info
ls_kernel.task_resume = _ls_kernel.task_resume
ls_kernel.task_suspend = _ls_kernel.task_suspend
ls_kernel.task_threads = _ls_kernel.task_threads
ls_kernel.mach_port_allocate = _ls_kernel.mach_port_allocate
ls_kernel.mach_port_deallocate = _ls_kernel.mach_port_deallocate
ls_kernel.mach_port_insert_right = _ls_kernel.mach_port_insert_right
ls_kernel.task_set_exception_ports = _ls_kernel.task_set_exception_ports
ls_kernel.task_swap_exception_ports = _ls_kernel.task_swap_exception_ports
ls_kernel.mach_msg = _ls_kernel.mach_msg
ls_kernel.thread_info = _ls_kernel.thread_info
ls_kernel.thread_resume = _ls_kernel.thread_resume
ls_kernel.thread_suspend = _ls_kernel.thread_suspend
ls_kernel.thread_get_state = _ls_kernel.thread_get_state
ls_kernel.thread_set_state = _ls_kernel.thread_set_state
ls_kernel.task_for_pid = _ls_kernel.task_for_pid
ls_kernel.kill = _ls_kernel.kill

for func in vars(ls_kernel).values():
    func.restype = kern_check

# Functions we don't wanna check for errors
ls_kernel.mach_task_self = _ls_kernel.mach_task_self


class SpawnException(Exception):

    def __init__(self, ret):
        self.ret = ret

    def __str__(self):
        return "Spawn error 0x%0.08x" % self.ret


def spawn_check(ret):
    if ret != 0:
        raise SpawnException(ret)


spawn = cdll.LoadLibrary(find_library("spawn"))
spawn.restype = spawn_check


libc = cdll.LoadLibrary(find_library("libc"))

middleware_c = cdll.LoadLibrary(find_library("middleware"))
