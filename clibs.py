from ctypes import cdll
from ctypes.util import find_library


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
