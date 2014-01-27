#include "middleware.h"

static middleware_result *mresult;

extern kern_return_t run_callback(
    mach_port_t             exception_port,
    mach_port_t             thread,
    mach_port_t             task,
    exception_type_t        exception,
    exception_data_t        code,
    mach_msg_type_number_t  codeCnt )
{
    mresult = malloc(sizeof(middleware_result));
    mresult->exception_port = exception_port;
    mresult->thread = thread;
    mresult->task = task;
    mresult->exception = exception;
    mresult->code = code;
    mresult->codeCnt = codeCnt;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    PyObject_CallObject(callback, NULL);
    PyGILState_Release(gstate);

    return KERN_SUCCESS;
}

extern middleware_result get_result()
{
    return *mresult;
}

// extern int get_code0()
// {
//     return mresult->code[0];
// }

// extern int get_code1()
// {
//     return mresult->code[1];
// }

// extern void *get_code1_addr()
// {
//     return &(mresult->code[1]);
// }

// extern void *get_code()
// {
//     return mresult->code;
// }