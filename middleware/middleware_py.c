#include "middleware.h"


PyObject *callback = NULL;

static PyObject *
middleware_set_callback(PyObject *self, PyObject *args)
{
    PyObject *result = NULL;
    PyObject *func;

    if (PyArg_ParseTuple(args, "O", &func)) {
        if (!PyCallable_Check(func)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
            return NULL;
        }
        Py_XINCREF(func);
        Py_XDECREF(callback);
        callback = func;
        Py_INCREF(Py_None);
        result = Py_None;
    }
    return result;
}

static PyMethodDef MiddlewareMethods[] = {
    {"set_callback",  middleware_set_callback, METH_VARARGS, "Set callback function for debug events."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initmiddleware(void)
{
    (void) Py_InitModule("middleware", MiddlewareMethods);
}