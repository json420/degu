/*
degu: an embedded HTTP server and client library
Copyright (C) 2014 Novacut Inc

This file is part of `degu`.

`degu` is free software: you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

`degu` is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License along
with `degu`.  If not, see <http://www.gnu.org/licenses/>.

Authors:
    Jason Gerard DeRose <jderose@novacut.com>
*/

#include <Python.h>


#define MAX_LINE_BYTES 4096
#define MAX_HEADER_COUNT 15

static PyObject *degu_MAX_LINE_BYTES = NULL;
static PyObject *degu_EmptyPreambleError = NULL;
static PyObject *_TWO = NULL;

#define _SET(pyobj, source) \
    Py_CLEAR(pyobj); \
    pyobj = source; \
    if (pyobj == NULL) { \
        goto error; \
    }

#define _READLINE(py_size, size) \
    line_size = 0; \
    line_data = NULL; \
    _SET(line, PyObject_CallFunctionObjArgs(rfile_readline, py_size, NULL)) \
    if (!PyBytes_CheckExact(line)) { \
        PyErr_Format(PyExc_TypeError, \
            "rfile.readline() returned %R, should return <class 'bytes'>", \
            line->ob_type \
        ); \
        goto error; \
    } \
    line_size = PyBytes_GET_SIZE(line); \
    if (line_size > size) { \
        PyErr_Format(PyExc_ValueError, \
            "rfile.readline() returned %u bytes, expected at most %u", \
            line_size, size \
        ); \
        goto error; \
    } \
    line_data = PyBytes_AS_STRING(line);

#define _START(size) \
    (size < 2 ? 0 : size - 2)

#define _CHECK_LINE_TERMINATION(format) \
    if (line_size < 2 || memcmp(line_data + (line_size - 2), "\r\n", 2) != 0) { \
        PyObject *_crlf = PySequence_GetSlice(line, _START(line_size), line_size); \
        if (_crlf == NULL) { \
            goto error; \
        } \
        PyErr_Format(PyExc_ValueError, (format), _crlf); \
        Py_CLEAR(_crlf); \
        goto error; \
    }


static PyObject *
degu_read_preamble(PyObject *self, PyObject *args)
{
    PyObject *rfile = NULL;
    PyObject *rfile_readline = NULL;  // rfile.readline() method
    PyObject *line = NULL;
    size_t line_size = 0;
    const char *line_data = NULL;
    PyObject *first_line = NULL;
    PyObject *header_lines = NULL;
    uint8_t i;
    PyObject *text = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "O:read_preamble", &rfile)) {
        return NULL;
    }

    /*
    For performance, we first get a reference to the rfile.readline() method and
    then call it each time we need using PyObject_CallFunctionObjArgs().

    This creates an additional reference to the rfile that we own, which means
    that the rfile can't get GC'ed through any subtle weirdness when the
    (potentially pure-Python) rfile.readline() callback is called.

    The performance improvement is impressive, though.  At the time of this
    change, we got around a 66% improvement by switching from
    PyObject_CallMethod() to PyObject_CallFunctionObjArgs() with the retained
    rfile_readline reference (from around 300k to 500k calls per second).

    See the _READLINE() macro for more details. 
    */
    _SET(rfile_readline, PyObject_GetAttrString(rfile, "readline"))
    if (!PyCallable_Check(rfile_readline)) {
        Py_CLEAR(rfile_readline);
        PyErr_SetString(PyExc_TypeError, "rfile.readline is not callable");
        return NULL;
    }

    // Read the first line:
    _READLINE(degu_MAX_LINE_BYTES, MAX_LINE_BYTES)
    if (line_size <= 0) {
        PyErr_SetString(degu_EmptyPreambleError, "HTTP preamble is empty");
        goto error;
    }
    _CHECK_LINE_TERMINATION("bad line termination: %R")
    if (line_size == 2) {
        PyErr_SetString(PyExc_ValueError, "first preamble line is empty");
        goto error;
    }
    _SET(first_line, PyUnicode_DecodeLatin1(line_data, line_size - 2, "strict"))

    // Read the header lines:
    header_lines = PyList_New(0);
    for (i=0; i<MAX_HEADER_COUNT; i++) {
        _READLINE(degu_MAX_LINE_BYTES, MAX_LINE_BYTES)
        _CHECK_LINE_TERMINATION("bad header line termination: %R")
        if (line_size == 2) {  // Stop on the first empty CRLF terminated line
            goto success;
        }
        _SET(text, PyUnicode_DecodeLatin1(line_data, line_size - 2, "strict"))
        PyList_Append(header_lines, text);
    }

    // If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
    // we just need to check for the final CRLF preamble termination:
    _READLINE(_TWO, 2)
    if (line_size != 2 || memcmp(line_data, "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError,
            "too many headers (> %u)", MAX_HEADER_COUNT
        );
        goto error;
    }

success:
    if (first_line == NULL || header_lines == NULL) {
        Py_FatalError("very bad things");
    }
    ret = PyTuple_Pack(2, first_line, header_lines);
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(rfile_readline);
    Py_CLEAR(line);
    Py_CLEAR(first_line);
    Py_CLEAR(header_lines);
    Py_CLEAR(text);
    return ret;  
}


/* module init */
static struct PyMethodDef degu_functions[] = {
    {"read_preamble", degu_read_preamble, METH_VARARGS, "read_preamble(rfile)"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef degu = {
    PyModuleDef_HEAD_INIT,
    "_degu",
    NULL,
    -1,
    degu_functions
};

PyMODINIT_FUNC
PyInit__degu(void)
{
    PyObject *module;

    module = PyModule_Create(&degu);
    if (module == NULL) {
        return NULL;
    }

    // Integer constants:
    PyModule_AddIntMacro(module, MAX_HEADER_COUNT);
    PyModule_AddIntMacro(module, MAX_LINE_BYTES);

    // We need a reference to the pyobj MAX_LINE_BYTES for _READLINE():
    degu_MAX_LINE_BYTES = PyObject_GetAttrString(module, "MAX_LINE_BYTES");
    if (degu_MAX_LINE_BYTES == NULL) {
        return NULL;
    }

    // _degu.EmptyPreambleError:
    degu_EmptyPreambleError = PyErr_NewException(
        "_degu.EmptyPreambleError", PyExc_ConnectionError, NULL
    );
    if (degu_EmptyPreambleError == NULL) {
        return NULL;
    }
    Py_INCREF(degu_EmptyPreambleError);
    PyModule_AddObject(module, "EmptyPreambleError", degu_EmptyPreambleError);

    // Python int ``2`` used with _READLINE() macro:
    _TWO = PyLong_FromLong(2);
    if (_TWO == NULL) {
        return NULL;
    }

    return module;
}
