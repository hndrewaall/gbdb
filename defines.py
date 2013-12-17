from ctypes import *

# sys/spawn.h
POSIX_SPAWN_SETSIGDEF		= 0x0004
POSIX_SPAWN_SETSIGMASK		= 0x0008
POSIX_SPAWN_START_SUSPENDED	= 0x0080

# spawn.h
pid_t					= c_int
posix_spawnattr_t		= c_void_p

# sys/signal.h
sigset_t				= c_uint32
SIGKILL					= 9
SIGSTOP					= 17
SIGCONT					= 19

# mach/port.h
mach_port_t				= c_void_p

MACH_PORT_RIGHT_SEND		= 0
MACH_PORT_RIGHT_RECEIVE		= 1
MACH_PORT_RIGHT_SEND_ONCE	= 2
MACH_PORT_RIGHT_PORT_SET	= 3
MACH_PORT_RIGHT_DEAD_NAME	= 4
MACH_PORT_RIGHT_LABELH	    = 5   
MACH_PORT_RIGHT_NUMBER		= 6 

# mach/message.h
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

kern_ret_dict = {0:	"KERN_SUCCESS",
				1:	"KERN_INVALID_ADDRESS",
				2:	"KERN_PROTECTION_FAILURE",
				3:	"KERN_NO_SPACE",
				4:	"KERN_INVALID_ARGUMENT",
				5:	"KERN_FAILURE",
				0x10000003: "MACH_SEND_INVALID_DEST"}	

th_state_dict = {1: "TH_STATE_RUNNING",
				2: "TH_STATE_STOPPED",
				3: "TH_STATE_WAITING",
				4: "TH_STATE_UNINTERRUPTIBLE",
				5: "TH_STATE_HALTED"}

MACH_MSG_TYPE_MOVE_RECEIVE		= 16
MACH_MSG_TYPE_MOVE_SEND			= 17
MACH_MSG_TYPE_MOVE_SEND_ONCE	= 18
MACH_MSG_TYPE_COPY_SEND			= 19
MACH_MSG_TYPE_MAKE_SEND			= 20
MACH_MSG_TYPE_MAKE_SEND_ONCE	= 21
MACH_MSG_TYPE_COPY_RECEIVE		= 22

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

EXC_BAD_ACCESS		= 1
EXC_BAD_INSTRUCTION = 2
EXC_ARITHMETIC		= 3
EXC_EMULATION		= 4	
EXC_SOFTWARE		= 5
EXC_BREAKPOINT		= 6
EXC_SYSCALL			= 7
EXC_MACH_SYSCALL	= 8
EXC_RPC_ALERT		= 9	
EXC_CRASH			= 10
EXC_RESOURCE		= 11	

EXC_MASK_BAD_ACCESS			= 1 << EXC_BAD_ACCESS
EXC_MASK_BAD_INSTRUCTION 	= 1 << EXC_BAD_INSTRUCTION
EXC_MASK_ARITHMETIC			= 1 << EXC_ARITHMETIC
EXC_MASK_EMULATION			= 1 << EXC_EMULATION
EXC_MASK_SOFTWARE			= 1 << EXC_SOFTWARE
EXC_MASK_BREAKPOINT			= 1 << EXC_BREAKPOINT
EXC_MASK_SYSCALL			= 1 << EXC_SYSCALL
EXC_MASK_MACH_SYSCALL		= 1 << EXC_MACH_SYSCALL
EXC_MASK_RPC_ALERT			= 1 << EXC_RPC_ALERT
EXC_MASK_CRASH				= 1 << EXC_CRASH
EXC_MASK_RESOURCE			= 1 << EXC_RESOURCE

EXCEPTION_DEFAULT	= 1
EXCEPTION_STATE		= 2
EXCEPTION_STATE_ID	= 3

MACH_EXCEPTION_CODES = 0x80000000

# mach/thread_status.h
x86_THREAD_STATE32		= 1
x86_FLOAT_STATE32		= 2
x86_EXCEPTION_STATE32	= 3
x86_THREAD_STATE64		= 4
x86_FLOAT_STATE64		= 5
x86_EXCEPTION_STATE64	= 6
x86_THREAD_STATE		= 7
x86_FLOAT_STATE			= 8
x86_EXCEPTION_STATE		= 9
x86_DEBUG_STATE32		= 10
x86_DEBUG_STATE64		= 11
x86_DEBUG_STATE			= 12
THREAD_STATE_NONE		= 13

