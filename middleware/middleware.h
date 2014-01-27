#include <Python/Python.h>
#include "mach_exc.h"
#include <stdio.h>


typedef struct middleware_result {
	mach_port_t             exception_port;
    mach_port_t             thread;
    mach_port_t             task;
    exception_type_t        exception;
    exception_data_t        code;
    mach_msg_type_number_t  codeCnt;
} middleware_result;

kern_return_t run_callback(
	mach_port_t             exception_port,
    mach_port_t             thread,
    mach_port_t             task,
    exception_type_t        exception,
    exception_data_t        code,
    mach_msg_type_number_t  codeCnt );

extern PyObject *callback;