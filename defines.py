from ctypes import *

# sys/spawn.h
POSIX_SPAWN_SETSIGDEF       = 0x0004
POSIX_SPAWN_SETSIGMASK      = 0x0008
POSIX_SPAWN_START_SUSPENDED = 0x0080

# spawn.h
pid_t                   = c_int
posix_spawnattr_t       = c_void_p

# sys/signal.h
sigset_t                = c_uint32
SIGKILL                 = 9
SIGSTOP                 = 17
SIGCONT                 = 19

# i386/vm_types.h
natural_t = c_uint
integer_t = c_int

# mach/port.h
mach_port_t             = c_uint32

MACH_PORT_RIGHT_SEND        = 0
MACH_PORT_RIGHT_RECEIVE     = 1
MACH_PORT_RIGHT_SEND_ONCE   = 2
MACH_PORT_RIGHT_PORT_SET    = 3
MACH_PORT_RIGHT_DEAD_NAME   = 4
MACH_PORT_RIGHT_LABELH      = 5
MACH_PORT_RIGHT_NUMBER      = 6

MACH_PORT_NULL = 0


# mach/message.h

mach_msg_type_number_t = natural_t
mach_msg_bits_t = c_uint
mach_msg_size_t = natural_t
mach_msg_id_t = integer_t

class mach_msg_header_t(Structure):
    _fields_ = [("msgh_bits", mach_msg_bits_t),
                ("msgh_size", mach_msg_size_t),
                ("msgh_remote_port", mach_port_t),
                ("msgh_local_port", mach_port_t),
                ("msgh_reserved", mach_msg_size_t),
                ("msgh_id", mach_msg_id_t)]

mach_msg_option_t = integer_t
mach_msg_timeout_t = natural_t

class mach_msg_body_t(Structure):
    _fields_ = [("msgh_descriptor_count", mach_msg_size_t)]

MACH_MSG_OPTION_NONE    = 0x00000000
MACH_SEND_MSG       = 0x00000001
MACH_RCV_MSG        = 0x00000002
MACH_RCV_LARGE      = 0x00000004
MACH_RCV_LARGE_IDENTITY = 0x00000008
MACH_SEND_TIMEOUT   = 0x00000010
MACH_SEND_INTERRUPT = 0x00000040
MACH_SEND_NOTIFY    = 0x00000080
MACH_SEND_ALWAYS    = 0x00010000
MACH_SEND_TRAILER   = 0x00020000
MACH_SEND_NOIMPORTANCE  = 0x00040000
MACH_SEND_IMPORTANCE    = 0x00080000

MACH_RCV_TIMEOUT    = 0x00000100
MACH_RCV_NOTIFY     = 0x00000200
MACH_RCV_INTERRUPT  = 0x00000400
MACH_RCV_OVERWRITE  = 0x00001000

MACH_MSG_SUCCESS        = 0x00000000
MACH_MSG_MASK           = 0x00003e00
MACH_MSG_IPC_SPACE      = 0x00002000
MACH_MSG_VM_SPACE       = 0x00001000
MACH_MSG_IPC_KERNEL     = 0x00000800
MACH_MSG_VM_KERNEL      = 0x00000400

MACH_SEND_IN_PROGRESS       = 0x10000001
MACH_SEND_INVALID_DATA      = 0x10000002
MACH_SEND_INVALID_DEST      = 0x10000003
MACH_SEND_TIMED_OUT     = 0x10000004
MACH_SEND_INTERRUPTED       = 0x10000007
MACH_SEND_MSG_TOO_SMALL     = 0x10000008
MACH_SEND_INVALID_REPLY     = 0x10000009
MACH_SEND_INVALID_RIGHT     = 0x1000000a
MACH_SEND_INVALID_NOTIFY    = 0x1000000b
MACH_SEND_INVALID_MEMORY    = 0x1000000c
MACH_SEND_NO_BUFFER     = 0x1000000d
MACH_SEND_TOO_LARGE     = 0x1000000e
MACH_SEND_INVALID_TYPE      = 0x1000000f
MACH_SEND_INVALID_HEADER    = 0x10000010
MACH_SEND_INVALID_TRAILER   = 0x10000011
MACH_SEND_INVALID_RT_OOL_SIZE   = 0x10000015

MACH_RCV_IN_PROGRESS        = 0x10004001
MACH_RCV_INVALID_NAME       = 0x10004002
MACH_RCV_TIMED_OUT      = 0x10004003
MACH_RCV_TOO_LARGE      = 0x10004004
MACH_RCV_INTERRUPTED        = 0x10004005
MACH_RCV_PORT_CHANGED       = 0x10004006
MACH_RCV_INVALID_NOTIFY     = 0x10004007
MACH_RCV_INVALID_DATA       = 0x10004008
MACH_RCV_PORT_DIED      = 0x10004009
MACH_RCV_IN_SET         = 0x1000400a
MACH_RCV_HEADER_ERROR       = 0x1000400b
MACH_RCV_BODY_ERROR     = 0x1000400c
MACH_RCV_INVALID_TYPE       = 0x1000400d
MACH_RCV_SCATTER_SMALL      = 0x1000400e
MACH_RCV_INVALID_TRAILER    = 0x1000400f
MACH_RCV_IN_PROGRESS_TIMED      = 0x10004011

# mach/kern_return.h, mig_errors.h
ret_dict = {0: "KERN_SUCCESS",
                1:  "KERN_INVALID_ADDRESS",
                2:  "KERN_PROTECTION_FAILURE",
                3:  "KERN_NO_SPACE",
                4:  "KERN_INVALID_ARGUMENT",
                5:  "KERN_FAILURE",
                0x10000003: "MACH_SEND_INVALID_DEST",
                -300: "MIG_TYPE_ERROR",
                -301: "MIG_REPLY_MISMATCH",
                -302: "MIG_REMOTE_ERROR",
                -303: "MIG_BAD_ID",
                -304: "MIG_BAD_ARGUMENTS",
                -305: "MIG_NO_REPLY",
                -306: "MIG_EXCEPTION",
                -307: "MIG_ARRAY_TOO_LARGE",
                -308: "MIG_SERVER_DIED",
                -309: "MIG_TRAILER_ERROR"}



# mach/thread_info.h
THREAD_BASIC_INFO       = 3

class thread_basic_info(Structure):
    _fields_ = [("user_time", (c_int * 2)),
                ("system_time", (c_int * 2)),
                ("cpu_usage", c_int),
                ("policy", c_int),
                ("run_state", c_int),
                ("flags", c_int),
                ("suspend_count", c_int),
                ("sleep_time", c_int)]

th_state_dict = {1: "TH_STATE_RUNNING",
                2: "TH_STATE_STOPPED",
                3: "TH_STATE_WAITING",
                4: "TH_STATE_UNINTERRUPTIBLE",
                5: "TH_STATE_HALTED"}

MACH_MSG_TYPE_MOVE_RECEIVE      = 16
MACH_MSG_TYPE_MOVE_SEND         = 17
MACH_MSG_TYPE_MOVE_SEND_ONCE    = 18
MACH_MSG_TYPE_COPY_SEND         = 19
MACH_MSG_TYPE_MAKE_SEND         = 20
MACH_MSG_TYPE_MAKE_SEND_ONCE    = 21
MACH_MSG_TYPE_COPY_RECEIVE      = 22

# mach/task_info.h
MACH_TASK_BASIC_INFO = 20

class mach_task_basic_info(Structure):
    _fields_ = [("virtual_size", c_uint64),
                ("resident_size", c_uint64),
                ("resident_size_max", c_uint64),
                ("user_time", (c_int * 2)),
                ("system_time", (c_int * 2)),
                ("policy", c_int),
                ("suspend_count", c_int)]
    # _fields_ = [("data", (c_char * 48))]

class task_basic_info(Structure):
    _fields_ = [("suspend_count", c_int),
                ("virtual_size", c_uint),
                ("resident_size", c_uint),
                ("user_time", (c_int * 2)),
                ("system_time", (c_int * 2)),
                ("policy", c_int)]

# mach/exception_types.h
exception_mask_t = c_uint
exception_type_t = c_int
exception_data_type_t = c_uint64
exception_data_t = POINTER(exception_data_type_t)

EXC_BAD_ACCESS      = 1
EXC_BAD_INSTRUCTION = 2
EXC_ARITHMETIC      = 3
EXC_EMULATION       = 4
EXC_SOFTWARE        = 5
EXC_BREAKPOINT      = 6
EXC_SYSCALL         = 7
EXC_MACH_SYSCALL    = 8
EXC_RPC_ALERT       = 9
EXC_CRASH           = 10
EXC_RESOURCE        = 11

EXC_MASK_BAD_ACCESS         = 1 << EXC_BAD_ACCESS
EXC_MASK_BAD_INSTRUCTION    = 1 << EXC_BAD_INSTRUCTION
EXC_MASK_ARITHMETIC         = 1 << EXC_ARITHMETIC
EXC_MASK_EMULATION          = 1 << EXC_EMULATION
EXC_MASK_SOFTWARE           = 1 << EXC_SOFTWARE
EXC_MASK_BREAKPOINT         = 1 << EXC_BREAKPOINT
EXC_MASK_SYSCALL            = 1 << EXC_SYSCALL
EXC_MASK_MACH_SYSCALL       = 1 << EXC_MACH_SYSCALL
EXC_MASK_RPC_ALERT          = 1 << EXC_RPC_ALERT
EXC_MASK_CRASH              = 1 << EXC_CRASH
EXC_MASK_RESOURCE           = 1 << EXC_RESOURCE

EXCEPTION_DEFAULT   = 1
EXCEPTION_STATE     = 2
EXCEPTION_STATE_IDENTITY  = 3

MACH_EXCEPTION_CODES = 0x80000000

# mach/i386/thread_status.h
x86_THREAD_STATE32      = 1
x86_FLOAT_STATE32       = 2
x86_EXCEPTION_STATE32   = 3
x86_THREAD_STATE64      = 4
x86_FLOAT_STATE64       = 5
x86_EXCEPTION_STATE64   = 6
x86_THREAD_STATE        = 7
x86_FLOAT_STATE         = 8
x86_EXCEPTION_STATE     = 9
x86_DEBUG_STATE32       = 10
x86_DEBUG_STATE64       = 11
x86_DEBUG_STATE         = 12
THREAD_STATE_NONE       = 13

class x86_thread_state64_t(Structure):
    _fields_ = [("rax", c_uint64),
                ("rbx", c_uint64),
                ("rcx", c_uint64),
                ("rdx", c_uint64),
                ("rdi", c_uint64),
                ("rsi", c_uint64),
                ("rbp", c_uint64),
                ("rsp", c_uint64),
                ("r8", c_uint64),
                ("r9", c_uint64),
                ("r10", c_uint64),
                ("r11", c_uint64),
                ("r12", c_uint64),
                ("r13", c_uint64),
                ("r14", c_uint64),
                ("r15", c_uint64),
                ("rip", c_uint64),
                ("rflags", c_uint64),
                ("cs", c_uint64),
                ("fs", c_uint64),
                ("gs", c_uint64)]

class x86_exception_state64_t(Structure):
    _fields_ = [("trapno", c_uint16),
                ("cpu", c_uint16),
                ("err", c_uint32),
                ("faultvaddr", c_uint64)]

x86_THREAD_STATE64_COUNT = c_uint(sizeof(x86_thread_state64_t) / sizeof(c_int))

# macdll/Exception.c

class macdll_reply_t(Structure):
    _fields_ = [("head", mach_msg_header_t),
                ("data", (c_char * 256))]

class macdll_msg_t(Structure):
    _fields_ = [("head", mach_msg_header_t),
                ("msgh_body", mach_msg_body_t),
                ("data", (c_char * 1024))]

# middleware.h

class middleware_result(Structure):
    _fields_ = [
                ("exception_port", mach_port_t),
                ("thread", mach_port_t),
                ("task", mach_port_t),
                ("exception", exception_type_t),
                ("code", exception_data_t),
                ("codeCnt", mach_msg_type_number_t),
                ]
