/*
degu: an embedded HTTP server and client library
Copyright (C) 2013 Novacut Inc

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

#define READ_LINE(maxsize) \
    if (line != NULL) { \
        PyErr_SetString(PyExc_RuntimeError, "line != NULL"); \
        goto cleanup; \
    } \
    line = PyObject_CallMethod(rfile, "readline", "n", maxsize); \
    if (!line) { \
        goto cleanup; \
    } \
    if (!PyBytes_CheckExact(line)) { \
        PyErr_Format(PyExc_TypeError, \
            "rfile.readline() must return a bytes instance" \
        ); \
        goto cleanup; \
    } \
    line_size = PyBytes_GET_SIZE(line); \
    if (line_size > maxsize) { \
        PyErr_Format(PyExc_ValueError, \
            "rfile.readline() returned %u bytes, expected at most %u", line_size, maxsize \
        ); \
        goto cleanup; \
    } \
    line_data = PyBytes_AS_STRING(line);

#define CHECK_LINE_TERMINATION() \
    if (line_size < 2 || memcmp(line_data + (line_size - 2), "\r\n", 2) != 0) { \
        PyErr_Format(PyExc_ValueError, "bad line termination"); \
        goto cleanup; \
    }

#define FREE_LINE() \
    Py_DECREF(line); \
    line = NULL; \
    line_size = 0; \
    line_data = NULL;


static PyObject *
degu_read_preamble(PyObject *self, PyObject *args)
{
    PyObject *rfile = NULL;
    PyObject *line = NULL;
    Py_ssize_t line_size = 0;
    const char *line_data = NULL;
    PyObject *first_line = NULL;
    PyObject *header_lines = NULL;
    uint8_t i;
    PyObject *text = NULL;
    PyObject *tup = NULL;

    if (!PyArg_ParseTuple(args, "O:read_preamble", &rfile)) {
        return NULL;
    }

    // Retain reference to rfile when calling rfile.readline():
    Py_INCREF(rfile);

    // Read the first line:
    READ_LINE(MAX_LINE_BYTES)
    if (line_size <= 0) {
        PyErr_Format(PyExc_ValueError, "EmptyPreambleError");
    }
    CHECK_LINE_TERMINATION()
    first_line = PyUnicode_DecodeLatin1(line_data, line_size - 2, NULL);
    FREE_LINE()
    if (!first_line) {
        goto cleanup;
    }

    // Read the header lines:
    header_lines = PyList_New(0);
    for (i=0; i<MAX_HEADER_COUNT; i++) {
        READ_LINE(MAX_LINE_BYTES)
        CHECK_LINE_TERMINATION()
        if (line_size == 2) {  // Stop on the first empty CRLF terminated line
            goto success;
        }
        text = PyUnicode_DecodeLatin1(line_data, line_size - 2, NULL);
        FREE_LINE()
        if (!text) {
            goto cleanup;
        }
        PyList_Append(header_lines, text);
        Py_DECREF(text);
        text = NULL;
    }

    // If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
    // we just need to check for the final CRLF preamble termination:
    READ_LINE(2)
    if (line_size != 2 || memcmp(line_data, "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError, "Too many header lines");
        goto cleanup;
    }

success:
    tup = PyTuple_Pack(2, first_line, header_lines);

cleanup:
    Py_DECREF(rfile);
    Py_XDECREF(line);
    Py_XDECREF(first_line);
    Py_XDECREF(header_lines);
    return tup;  
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
    return PyModule_Create(&degu);
}
