#include "middleware.h"


extern kern_return_t catch_mach_exception_raise(
    mach_port_t             exception_port,
    mach_port_t             thread,
    mach_port_t             task,
    exception_type_t        exception,
    exception_data_t        code,
    mach_msg_type_number_t  codeCnt )
{
    return run_callback(exception_port, thread, task, exception, code,
                        codeCnt );
}

extern kern_return_t catch_mach_exception_raise_state(
    mach_port_t             exception_port,
    exception_type_t        exception,
    const exception_data_t  code,
    mach_msg_type_number_t  codeCnt,
    int *                   flavor,
    const thread_state_t    old_state,
    mach_msg_type_number_t  old_stateCnt,
    thread_state_t          new_state,
    mach_msg_type_number_t *new_stateCnt )
{
    return KERN_FAILURE;
}

extern kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t             exception_port,
    mach_port_t             thread,
    mach_port_t             task,
    exception_type_t        exception,
    exception_data_t        code,
    mach_msg_type_number_t  codeCnt,
    int *                   flavor,
    thread_state_t          old_state,
    mach_msg_type_number_t  old_stateCnt,
    thread_state_t          new_state,
    mach_msg_type_number_t *new_stateCnt )
{
    return KERN_FAILURE;
}