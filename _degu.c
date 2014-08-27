/*
 * degu: an embedded HTTP server and client library
 * Copyright (C) 2014 Novacut Inc
 *
 * This file is part of `degu`.
 *
 * `degu` is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * `degu` is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with `degu`.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Jason Gerard DeRose <jderose@novacut.com>
 */

#include <Python.h>


#define MAX_LINE_BYTES 4096
#define MAX_HEADER_COUNT 15

static PyObject *degu_MAX_LINE_BYTES = NULL;
static PyObject *degu_EmptyPreambleError = NULL;
static PyObject *int_zero = NULL;
static PyObject *int_two = NULL;
static PyObject *name_readline = NULL;
static PyObject *key_content_length = NULL;
static PyObject *key_transfer_encoding = NULL;
static PyObject *str_chunked = NULL;


static const uint8_t DEGU_ASCII[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
     32, 33, 34, 35, 36, 37, 38, 39,  // ' '  '!'  '"'  '#'  '$'  '%'  '&'  "'" 
     40, 41, 42, 43, 44, 45, 46, 47,  // '('  ')'  '*'  '+'  ','  '-'  '.'  '/' 
     48, 49, 50, 51, 52, 53, 54, 55,  // '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7' 
     56, 57, 58, 59, 60, 61, 62, 63,  // '8'  '9'  ':'  ';'  '<'  '='  '>'  '?' 
     64, 65, 66, 67, 68, 69, 70, 71,  // '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G' 
     72, 73, 74, 75, 76, 77, 78, 79,  // 'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O' 
     80, 81, 82, 83, 84, 85, 86, 87,  // 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W' 
     88, 89, 90, 91, 92, 93, 94, 95,  // 'X'  'Y'  'Z'  '['  '\\' ']'  '^'  '_' 
     96, 97, 98, 99,100,101,102,103,  // '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g' 
    104,105,106,107,108,109,110,111,  // 'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o' 
    112,113,114,115,116,117,118,119,  // 'p'  'q'  'r'  's'  't'  'u'  'v'  'w' 
    120,121,122,123,124,125,126,255,  // 'x'  'y'  'z'  '{'  '|'  '}'  '~'      
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
};

static const uint8_t DEGU_HEADER_KEY[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255, 45,255,255,  //                          '-'           
     48, 49, 50, 51, 52, 53, 54, 55,  // '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7' 
     56, 57,255,255,255,255,255,255,  // '8'  '9'                               
    255, 97, 98, 99,100,101,102,103,  //      'A'  'B'  'C'  'D'  'E'  'F'  'G' 
    104,105,106,107,108,109,110,111,  // 'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O' 
    112,113,114,115,116,117,118,119,  // 'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W' 
    120,121,122,255,255,255,255,255,  // 'X'  'Y'  'Z'                          
    255, 97, 98, 99,100,101,102,103,  //      'a'  'b'  'c'  'd'  'e'  'f'  'g' 
    104,105,106,107,108,109,110,111,  // 'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o' 
    112,113,114,115,116,117,118,119,  // 'p'  'q'  'r'  's'  't'  'u'  'v'  'w' 
    120,121,122,255,255,255,255,255,  // 'x'  'y'  'z'                          
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
};


/* 
 * degu_decode(): valid ASCII, possibly casefold.
 *
 *
 */
static inline PyObject *
degu_decode(const size_t len, const uint8_t *buf, const uint8_t *table)
{
    PyObject *dst;
    uint8_t *dst_buf;
    uint8_t r;
    size_t i;

    dst = PyUnicode_New(len, 127);
    if (dst == NULL) {
        return NULL;
    }
    dst_buf = PyUnicode_1BYTE_DATA(dst);
    for (r = i = 0; i < len; i++) {
        r |= dst_buf[i] = table[buf[i]];
    }
    if (r & 128) {
        Py_CLEAR(dst);
        PyObject *tmp = PyBytes_FromStringAndSize((char *)buf, len);
        if (tmp != NULL) {
            PyErr_Format(PyExc_ValueError, "invalid ASCII: %R", tmp);
            Py_CLEAR(tmp);
        }
    }
    return dst;
}


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
    line_buf = (uint8_t *)PyBytes_AS_STRING(line);

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
degu_read_preamble(PyObject *self, PyObject *args)
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

    // Owned reference we transfer on success, decrement on error:
    PyObject *ret = NULL;

    size_t line_len, key_len, value_len;
    const uint8_t *line_buf, *buf;
    uint8_t i;

    if (!PyArg_ParseTuple(args, "O:read_preamble", &rfile)) {
        return NULL;
    }

    /*
     * For performance, we first get a reference to the rfile.readline() method
     * and then call it each time we need using PyObject_CallFunctionObjArgs().
     *
     * This creates an additional reference to the rfile that we own, which
     * means that the rfile can't get GC'ed through any subtle weirdness when
     * the rfile.readline() callback is called.
     *
     * See the _READLINE() macro for more details. 
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
    _SET(first_line, degu_decode(line_len - 2, line_buf, DEGU_ASCII))

    /*
     * Read the header lines:
     *
     *      char| K: V
     *    offset| 0123
     *      size| 1234
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

        /* Decode & lowercase the header key */
        _RESET(key, degu_decode(key_len, line_buf, DEGU_HEADER_KEY))

        /* Decode the header value */
        _RESET(value, degu_decode(value_len, buf, DEGU_ASCII))

        if (PyDict_SetDefault(headers, key, value) != value) {
            PyErr_Format(PyExc_ValueError, "duplicate header: %R", line);
            goto error;
        }
    }

    /*
     * If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
     * we just need to check for the final CRLF preamble termination:
     */
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
    Py_CLEAR(key);
    Py_CLEAR(value);
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

    // Other Python `int` and `str` objects we need for performance:
    _RESET(int_zero, PyLong_FromLong(0))
    _RESET(int_two, PyLong_FromLong(2))
    _RESET(name_readline, PyUnicode_InternFromString("readline"))
    _RESET(key_content_length, PyUnicode_InternFromString("content-length"))
    _RESET(key_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _RESET(str_chunked, PyUnicode_InternFromString("chunked"))

    return module;

error:
    return NULL;
}
