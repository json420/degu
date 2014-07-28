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
static PyObject *int_zero = NULL;
static PyObject *int_two = NULL;
static PyObject *name_casefold = NULL;
static PyObject *name_readline = NULL;
static PyObject *key_content_length = NULL;
static PyObject *key_transfer_encoding = NULL;
static PyObject *str_chunked = NULL;

#define _SET(pyobj, source) \
    pyobj = source; \
    if (pyobj == NULL) { \
        goto error; \
    }

#define _RESET(pyobj, source) \
    Py_CLEAR(pyobj); \
    pyobj = source; \
    if (pyobj == NULL) { \
        goto error; \
    }

#define _READLINE(py_size, size) \
    line_len = 0; \
    _RESET(line, PyObject_CallFunctionObjArgs(rfile_readline, py_size, NULL)) \
    if (!PyBytes_CheckExact(line)) { \
        PyErr_Format(PyExc_TypeError, \
            "rfile.readline() returned %R, should return <class 'bytes'>", \
            line->ob_type \
        ); \
        goto error; \
    } \
    line_len = PyBytes_GET_SIZE(line); \
    if (line_len > size) { \
        PyErr_Format(PyExc_ValueError, \
            "rfile.readline() returned %u bytes, expected at most %u", \
            line_len, size \
        ); \
        goto error; \
    } \
    line_buf = PyBytes_AS_STRING(line);

#define _START(size) \
    (size < 2 ? 0 : size - 2)

#define _CHECK_LINE_TERMINATION(format) \
    if (line_len < 2 || memcmp(line_buf + (line_len - 2), "\r\n", 2) != 0) { \
        PyObject *_crlf = PySequence_GetSlice(line, _START(line_len), line_len); \
        if (_crlf == NULL) { \
            goto error; \
        } \
        PyErr_Format(PyExc_ValueError, (format), _crlf); \
        Py_CLEAR(_crlf); \
        goto error; \
    }


static PyObject *
degu_read_preamble2(PyObject *self, PyObject *args)
{
    // Borrowed references we don't need to decrement:
    PyObject *rfile = NULL;
    PyObject *borrowed = NULL;

    // Owned references we need to decrement when != NULL:
    PyObject *rfile_readline = NULL;  // rfile.readline() method
    PyObject *line = NULL;
    PyObject *first_line = NULL;
    PyObject *headers = NULL;
    PyObject *key = NULL;
    PyObject *value = NULL;
    PyObject *casefolded_key = NULL;

    // Owned reference we transfer on success, decrement on error:
    PyObject *ret = NULL;

    size_t line_len, key_len, value_len;
    const char *line_buf, *buf;
    uint8_t i;

    if (!PyArg_ParseTuple(args, "O:read_preamble2", &rfile)) {
        return NULL;
    }

    /*
    For performance, we first get a reference to the rfile.readline() method and
    then call it each time we need using PyObject_CallFunctionObjArgs().

    This creates an additional reference to the rfile that we own, which means
    that the rfile can't get GC'ed through any subtle weirdness when the
    rfile.readline() callback is called.

    See the _READLINE() macro for more details. 
    */
    _SET(rfile_readline, PyObject_GetAttr(rfile, name_readline))
    if (!PyCallable_Check(rfile_readline)) {
        Py_CLEAR(rfile_readline);
        PyErr_SetString(PyExc_TypeError, "rfile.readline is not callable");
        return NULL;
    }

    // Read the first line:
    _READLINE(degu_MAX_LINE_BYTES, MAX_LINE_BYTES)
    if (line_len <= 0) {
        PyErr_SetString(degu_EmptyPreambleError, "HTTP preamble is empty");
        goto error;
    }
    _CHECK_LINE_TERMINATION("bad line termination: %R")
    if (line_len == 2) {
        PyErr_SetString(PyExc_ValueError, "first preamble line is empty");
        goto error;
    }
    _SET(first_line, PyUnicode_DecodeLatin1(line_buf, line_len - 2, "strict"))

    /*
    Read the header lines:

          char| K: V
        offset| 0123
          size| 1234
    */
    _SET(headers, PyDict_New())
    for (i=0; i<MAX_HEADER_COUNT; i++) {
        _READLINE(degu_MAX_LINE_BYTES, MAX_LINE_BYTES)
        _CHECK_LINE_TERMINATION("bad header line termination: %R")
        if (line_len == 2) {  // Stop on the first empty CRLF terminated line
            goto done;
        }
        line_len -= 2;
        buf = memmem(line_buf, line_len, ": ", 2);
        if (buf == NULL || buf < line_buf + 1 || buf > line_buf + line_len - 3) {
            PyErr_Format(PyExc_ValueError, "bad header line: %R", line);
            goto error;
        }
        key_len = buf - line_buf;
        value_len = line_len - key_len - 2;
        buf += 2;
        _RESET(key, PyUnicode_DecodeLatin1(line_buf, key_len, "strict"))
        _RESET(value, PyUnicode_DecodeLatin1(buf, value_len, "strict"))
        _RESET(casefolded_key, PyObject_CallMethodObjArgs(key, name_casefold, NULL))
        if (PyDict_SetDefault(headers, casefolded_key, value) != value) {
            PyErr_Format(PyExc_ValueError, "duplicate header: %R", line);
            goto error;
        }
    }

    // If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
    // we just need to check for the final CRLF preamble termination:
    _READLINE(int_two, 2)
    if (line_len != 2 || memcmp(line_buf, "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError,
            "too many headers (> %u)", MAX_HEADER_COUNT
        );
        goto error;
    }

done:
    if (PyDict_Contains(headers, key_content_length)) {
        if (PyDict_Contains(headers, key_transfer_encoding)) {
            PyErr_SetString(PyExc_ValueError, 
                "cannot have both content-length and transfer-encoding headers"
            );
            goto error;
        }
        _SET(borrowed, PyDict_GetItemWithError(headers, key_content_length))
        _RESET(value, PyLong_FromUnicodeObject(borrowed, 10))
        if (PyObject_RichCompareBool(value, int_zero, Py_LT) > 0) {
            PyErr_Format(PyExc_ValueError, "negative content-length: %R", value);
            goto error;
        }
        if (PyDict_SetItem(headers, key_content_length, value) != 0) {
            goto error;
        }
    }
    else if (PyDict_Contains(headers, key_transfer_encoding)) {
        _SET(borrowed, PyDict_GetItemWithError(headers, key_transfer_encoding))
        if (PyUnicode_Compare(borrowed, str_chunked) != 0) {
            PyErr_Format(PyExc_ValueError, "bad transfer-encoding: %R", borrowed);
            goto error;
        }
    }
    ret = PyTuple_Pack(2, first_line, headers);
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(rfile_readline);
    Py_CLEAR(line);
    Py_CLEAR(first_line);
    Py_CLEAR(headers);
    Py_CLEAR(key);  // Note: we can't unit test this object with sys.getrefcount()
    Py_CLEAR(value);
    Py_CLEAR(casefolded_key);
    return ret;  
}


/* module init */
static struct PyMethodDef degu_functions[] = {
    {"read_preamble2", degu_read_preamble2, METH_VARARGS, "read_preamble2(rfile)"},
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
    _RESET(int_zero, PyLong_FromLong(0))
    _RESET(int_two, PyLong_FromLong(2))
    _RESET(name_casefold, PyUnicode_InternFromString("casefold"))
    _RESET(name_readline, PyUnicode_InternFromString("readline"))
    _RESET(key_content_length, PyUnicode_InternFromString("content-length"))
    _RESET(key_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _RESET(str_chunked, PyUnicode_InternFromString("chunked"))

    return module;

error:
    return NULL;
}
