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


static inline PyObject *
_degu_read_first_line(PyObject *rfile)
{
    PyObject *line = NULL;
    Py_ssize_t size = 0;
    const char *data = NULL;
    PyObject *text = NULL;

    // Call rfile.readline():
    line = PyObject_CallMethod(rfile, "readline", "n", MAX_LINE_BYTES);
    if (!line) {
        return NULL;
    }

    // Check type returned by rfile.readline():
    if (!PyBytes_CheckExact(line)) {
        PyErr_Format(PyExc_TypeError,
            "rfile.readline() must return a bytes instance"
        );
        Py_DECREF(line);
        return NULL;
    }

    // Check length and value of bytes returned by rfile.readline():
    size = PyBytes_GET_SIZE(line);
    data = PyBytes_AS_STRING(line);
    if (size <= 0) {
        PyErr_Format(PyExc_ValueError, "EmptyPreambleError");
    }
    else if (size < 2 || memcmp(data + (size - 2), "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError, "Bad Line Termination");
    }
    else {
        text = PyUnicode_DecodeLatin1(data, size - 2, NULL);
    }

    Py_DECREF(line);
    return text;
}

static inline PyObject *
_degu_read_header_line(PyObject *rfile)
{
    PyObject *line = NULL;
    Py_ssize_t size = 0;
    const char *data = NULL;
    PyObject *text = NULL;

    // Call rfile.readline():
    line = PyObject_CallMethod(rfile, "readline", "n", MAX_LINE_BYTES);
    if (!line) {
        return NULL;
    }

    // Check type returned by rfile.readline():
    if (!PyBytes_CheckExact(line)) {
        PyErr_Format(PyExc_TypeError,
            "rfile.readline() must return a bytes instance"
        );
        Py_DECREF(line);
        return NULL;
    }

    // Check length and value of bytes returned by rfile.readline():
    size = PyBytes_GET_SIZE(line);
    data = PyBytes_AS_STRING(line);
    if (size < 2 || memcmp(data + (size - 2), "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError, "Bad Header Line Termination");
    }
    else {
        text = PyUnicode_DecodeLatin1(data, size - 2, NULL);
    }

    Py_DECREF(line);
    return text;
}


static inline PyObject *
_degu_read_last_line(PyObject *rfile)
{
    PyObject *line = NULL;
    Py_ssize_t size = 0;
    const char *data = NULL;

    // Call rfile.readline():
    line = PyObject_CallMethod(rfile, "readline", "n", 2);
    if (!line) {
        return NULL;
    }

    // Check type returned by rfile.readline():
    if (!PyBytes_CheckExact(line)) {
        PyErr_Format(PyExc_TypeError,
            "rfile.readline() must return a bytes instance"
        );
        Py_DECREF(line);
        return NULL;
    }

    // Check length and value of bytes returned by rfile.readline():
    size = PyBytes_GET_SIZE(line);
    data = PyBytes_AS_STRING(line);
    if (size < 2 || memcmp(data, "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError, "Bad Preamble Termination");
        Py_DECREF(line);
        return NULL;
    }
    Py_DECREF(line);
    Py_RETURN_NONE;
}


static PyObject *
degu_read_preamble(PyObject *self, PyObject *args)
{
    PyObject *rfile = NULL;
    PyObject *line = NULL;
    PyObject *first_line = NULL;
    PyObject *header_lines = NULL;
    uint8_t i;
    PyObject *tup = NULL;

    if (!PyArg_ParseTuple(args, "O:read_preamble", &rfile)) {
        return NULL;
    }

    // Retain reference to rfile when calling rfile.readline():
    Py_INCREF(rfile);

    // Read the first line:
    first_line = _degu_read_first_line(rfile);
    if (!first_line) {
        goto done;
    }

    // Read the header lines:
    header_lines = PyList_New(0);
    for (i=0; i<MAX_HEADER_COUNT; i++) {
        line = _degu_read_header_line(rfile);
        if (!line) {
            goto done;
        }
        if (PyUnicode_GET_LENGTH(line) <= 0) {
            goto okay;
        }
        PyList_Append(header_lines, line);
        Py_DECREF(line);
        line = NULL;
    }

    // If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
    // we just need to check for the final CRLF preamble termination:
    line = _degu_read_last_line(rfile);
    if (!line) {
        goto done;
    }
    if (PyUnicode_GET_LENGTH(line) <= 0) {
        PyErr_Format(PyExc_ValueError, "Too many header lines");
        goto done;
    }

okay:
    tup = PyTuple_Pack(2, first_line, header_lines);

done:
    Py_DECREF(rfile);
    Py_XDECREF(first_line);
    Py_XDECREF(line);
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
