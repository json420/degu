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

/* `degu.base.EmptyPreambleError` */
static PyObject *degu_EmptyPreambleError = NULL;

/* Pre-built global Python `int` and `str` objects for performance */
static PyObject *int_zero = NULL;               //  0
static PyObject *str_readline = NULL;           //  'readline'
static PyObject *str_content_length = NULL;     //  'content-length'
static PyObject *str_transfer_encoding = NULL;  //  'transfer-encoding'
static PyObject *str_chunked = NULL;            //  'chunked'

/*
 * Pre-built args tuples for PyObject_Call() when calling rfile.readline().
 *
 * This makes read_preamble() about 18% faster compared to when it previously
 * used PyObject_CallFunctionObjArgs() with pre-built `int` objects.
 *
 * See the _READLINE() macro for details.
 */ 
static PyObject *args_size_two = NULL;  //  (2,)
static PyObject *args_size_max = NULL;  //  (4096,)


/*
 * _VALUES: table for validating the first preamble line plus header values.
 *
 * Degu only allows these 95 possible byte values to exist in the first line of
 * the HTTP preamble, and likewise to exist in the header values.  This is a
 * superset of the byte values allowed in the more restrictive `_KEYS` table.
 *
 * Valid entries get mapped to themselves (ie, no case-folding is done).
 * 
 * Invalid entries will always have the high bit set, for which you can do a
 * single error check at the end using (r & 128).
 *
 * See the `_decode()` function for more details.
 */
static const uint8_t _VALUES[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
     32, 33, 34, 35, 36, 37, 38, 39,  //  ' '  '!'  '"'  '#'  '$'  '%'  '&'  "'"
     40, 41, 42, 43, 44, 45, 46, 47,  //  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
     48, 49, 50, 51, 52, 53, 54, 55,  //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
     56, 57, 58, 59, 60, 61, 62, 63,  //  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
     64, 65, 66, 67, 68, 69, 70, 71,  //  '@'  'A'  'B'  'C'  'D'  'E'  'F'  'G'
     72, 73, 74, 75, 76, 77, 78, 79,  //  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
     80, 81, 82, 83, 84, 85, 86, 87,  //  'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
     88, 89, 90, 91, 92, 93, 94, 95,  //  'X'  'Y'  'Z'  '['  '\\' ']'  '^'  '_'
     96, 97, 98, 99,100,101,102,103,  //  '`'  'a'  'b'  'c'  'd'  'e'  'f'  'g'
    104,105,106,107,108,109,110,111,  //  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    112,113,114,115,116,117,118,119,  //  'p'  'q'  'r'  's'  't'  'u'  'v'  'w'
    120,121,122,123,124,125,126,255,  //  'x'  'y'  'z'  '{'  '|'  '}'  '~'
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
 * _KEYS: table for validating and case-folding header keys (header names).
 *
 * Degu only allows these 63 possible byte values to exist in header names.
 * This is a subset of the byte values allowed in the more permissive `_VALUES`
 * table.
 *
 * Entries in [-0-9a-z] get mapped to themselves, and entries in [A-Z] get
 * mapped to their lowercase equivalent in [a-z].
 * 
 * Invalid entries will always have the high bit set, for which you can do a
 * single error check at the end using (r & 128).
 *
 * See the `_decode()` function for more details.
 */
static const uint8_t _KEYS[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255, 45,255,255,  //                           '-'
     48, 49, 50, 51, 52, 53, 54, 55,  //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
     56, 57,255,255,255,255,255,255,  //  '8'  '9'
    255, 97, 98, 99,100,101,102,103,  //       'A'  'B'  'C'  'D'  'E'  'F'  'G'
    104,105,106,107,108,109,110,111,  //  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    112,113,114,115,116,117,118,119,  //  'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
    120,121,122,255,255,255,255,255,  //  'X'  'Y'  'Z'
    255, 97, 98, 99,100,101,102,103,  //       'a'  'b'  'c'  'd'  'e'  'f'  'g'
    104,105,106,107,108,109,110,111,  //  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    112,113,114,115,116,117,118,119,  //  'p'  'q'  'r'  's'  't'  'u'  'v'  'w'
    120,121,122,255,255,255,255,255,  //  'x'  'y'  'z'
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
 * _decode(): validate against *table*, possibly case-fold.
 *
 * The *table* determines what bytes are allowed, and whether to case-fold.
 *
 * Return value will be an `str` instance, or NULL when there was an error.
 */
static PyObject *
_decode(const size_t len, const uint8_t *buf, const uint8_t *table, const char *format)
{
    PyObject *dst = NULL;
    uint8_t *dst_buf = NULL;
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
        if (r != 255) {
            Py_FatalError("internal error in `_decode()`");
        }
        PyObject *tmp = PyBytes_FromStringAndSize((char *)buf, len);
        if (tmp != NULL) {
            PyErr_Format(PyExc_ValueError, format, tmp);
        }
        Py_CLEAR(tmp);
    }
    return dst;
}


/*
 * _SET() macro: assign a PyObject pointer.
 *
 * Use this when you're assuming *pyobj* has been initialized to NULL.
 *
 * This macro will call Py_FatalError() if *pyobj* does not start equal to NULL
 * (a sign that perhaps you should be using the _RESET() macro instead).
 *
 * If *source* returns NULL, this macro will `goto error`, so it can only be
 * used within a function with an appropriate "error" label.
 */
#define _SET(pyobj, source) \
    if (pyobj != NULL) { \
        Py_FatalError("internal error in _SET() macro: pyobj is not NULL at start"); \
    } \
    pyobj = (source); \
    if (pyobj == NULL) { \
        goto error; \
    }


/*
 * _RESET() macro: Py_CLEAR() existing, then assign to a new PyObject pointer.
 *
 * Use this to decrement the current object pointed to by *pyobj*, and then
 * assign it to the PyObject pointer returned by *source*.
 *
 * If *source* returns NULL, this macro will `goto error`, so it can only be
 * used within a function with an appropriate "error" label.
 */
#define _RESET(pyobj, source) \
    Py_CLEAR(pyobj); \
    pyobj = source; \
    if (pyobj == NULL) { \
        goto error; \
    }


/*
 * _READLINE() macro: read the next line in the preamble using rfile.readline().
 */
#define _READLINE(py_args, size) \
    line_len = 0; \
    _RESET(line, PyObject_Call(readline, py_args, NULL)) \
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


/* _START() macro: only used below in _CHECK_LINE_TERMINATION() */
#define _START(size) \
    (size < 2 ? 0 : size - 2)


/*
 * _CHECK_LINE_TERMINATION() macro: ensure the line ends with ``b'\r\n'``.
 */
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


/*

    |-- line ------------------------------------------------------------------|
    |-- line1 ------|
                      |-- line -------------------------------------------------|


 */


static PyObject *
_parse_preamble(const uint8_t *preamble_buf, const size_t preamble_len)
{
    const uint8_t *line_buf, *crlf, *sep;
    size_t line_len, key_len, value_len;
    PyObject *first_line = NULL;
    PyObject *headers = NULL;
    PyObject *key = NULL;
    PyObject *value = NULL;
    PyObject *line = NULL;
    PyObject *ret = NULL;

    uint8_t has_content_length = 0;
    uint8_t has_transfer_encoding = 0;

    line_buf = preamble_buf;
    line_len = preamble_len;
    crlf = memmem(line_buf, line_len, "\r\n", 2);
    if (crlf != NULL) {
        line_len = crlf - line_buf;
    }

    _SET(first_line,
        _decode(line_len, line_buf, _VALUES, "bad bytes in first line: %R")
    )

    /* Read, parse, and decode the header lines */
    _SET(headers, PyDict_New())
    while (crlf != NULL) {
        line_buf = crlf + 2;
        line_len = preamble_len - (line_buf - preamble_buf);
        crlf = memmem(line_buf, line_len, "\r\n", 2);
        if (crlf != NULL) {
            line_len = crlf - line_buf;
        }

        /* We require both the header key and header value to each be at least
         * one byte in length.  This means that the shortest valid header line
         * (minus the CRLF) is four bytes in length:
         *
         *      line| k: v
         *    offset| 0123
         *      size| 1234
         *
         * So when (line_len < 4), there's no reason to proceed.  This
         * short-circuiting is also a bit safer just in case a given `memmem()`
         * implementation isn't well behaved when (haystacklen < needlelen).
         */
        if (line_len < 4) {
            _SET(line, PyBytes_FromStringAndSize((char *)line_buf, line_len))
            PyErr_Format(PyExc_ValueError, "header line too short: %R", line);
            goto error;
        }

        sep = memmem(line_buf, line_len, ": ", 2);
        if (sep == NULL || sep < line_buf + 1 || sep > line_buf + line_len - 3) {
            _SET(line, PyBytes_FromStringAndSize((char *)line_buf, line_len))
            PyErr_Format(PyExc_ValueError, "bad header line: %R", line);
            goto error;
        }
        key_len = sep - line_buf;
        value_len = line_len - key_len - 2;

        /* Decode & case-fold the header name */
        _RESET(key,
            _decode(key_len, line_buf, _KEYS, "bad bytes in header name: %R")
        )
        _RESET(value,
            _decode(value_len, sep + 2, _VALUES, "bad bytes in header value: %R")
        )
        if (key_len == 14 && memcmp(PyUnicode_1BYTE_DATA(key), "content-length", 14) == 0) {
            has_content_length = 1;
            _RESET(key, str_content_length);
            Py_INCREF(key);
            PyObject *tmp = NULL;
            _SET(tmp, PyLong_FromUnicodeObject(value, 10))
            _RESET(value, tmp)
            if (PyObject_RichCompareBool(value, int_zero, Py_LT) > 0) {
                PyErr_Format(PyExc_ValueError, "negative content-length: %R", value);
                goto error;
            }
        }
        else if (key_len == 17 && memcmp(PyUnicode_1BYTE_DATA(key), "transfer-encoding", 17) == 0) {
            has_transfer_encoding = 1;
            _RESET(key, str_transfer_encoding);
            Py_INCREF(key);
            if (value_len != 7 || memcmp(PyUnicode_1BYTE_DATA(value), "chunked", 7) != 0) {
                PyErr_Format(PyExc_ValueError, "bad transfer-encoding: %R", value);
                goto error;
            }
            _RESET(value, str_chunked);
            Py_INCREF(value);
        }

        /* Store in headers dict, make sure it's not a duplicate key */
        if (PyDict_SetDefault(headers, key, value) != value) {
            _SET(line, PyBytes_FromStringAndSize((char *)line_buf, line_len))
            PyErr_Format(PyExc_ValueError, "duplicate header: %R", line);
            goto error;
        }
    }

    if (has_content_length && has_transfer_encoding) {
        PyErr_SetString(PyExc_ValueError, 
            "cannot have both content-length and transfer-encoding headers"
        );
        goto error; 
    }
    ret = PyTuple_Pack(2, first_line, headers);
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(first_line);
    Py_CLEAR(headers);
    Py_CLEAR(key);
    Py_CLEAR(value);
    Py_CLEAR(line);
    return ret;  

}


static PyObject *
degu_parse_preamble(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_preamble", &buf, &len)) {
        return NULL;
    }
    return _parse_preamble(buf, len);   
}



/*
 * C implementation of `degu.base.read_preamble()`.
 */
static PyObject *
degu_read_preamble(PyObject *self, PyObject *args)
{
    /* Borrowed references we don't need to decrement */
    PyObject *rfile = NULL;
    PyObject *borrowed = NULL;

    /* Owned references we need to decrement in "cleanup" when != NULL */
    PyObject *readline = NULL;
    PyObject *line = NULL;
    PyObject *first_line = NULL;
    PyObject *headers = NULL;
    PyObject *key = NULL;
    PyObject *value = NULL;

    /* Return value is a ``(first_line, headers)`` tuple */
    PyObject *ret = NULL;

    size_t line_len, key_len, value_len;
    const uint8_t *line_buf, *buf;
    uint8_t i;

    if (!PyArg_ParseTuple(args, "O:read_preamble", &rfile)) {
        return NULL;
    }

    /* For performance, we first get a reference to the rfile.readline() method
     * and then call it each time we need using PyObject_Call().
     *
     * This creates an additional reference to the rfile that we own, which
     * means that the rfile can't get GC'ed through any subtle weirdness when
     * the rfile.readline() callback is called.
     *
     * See the _READLINE() macro for more details. 
     */
    _SET(readline, PyObject_GetAttr(rfile, str_readline))
    if (!PyCallable_Check(readline)) {
        Py_CLEAR(readline);
        PyErr_SetString(PyExc_TypeError, "rfile.readline is not callable");
        return NULL;
    }

    /* Read and decode the first preamble line */
    _READLINE(args_size_max, MAX_LINE_BYTES)
    if (line_len <= 0) {
        PyErr_SetString(degu_EmptyPreambleError, "HTTP preamble is empty");
        goto error;
    }
    _CHECK_LINE_TERMINATION("bad line termination: %R")
    if (line_len == 2) {
        PyErr_SetString(PyExc_ValueError, "first preamble line is empty");
        goto error;
    }
    _SET(first_line,
        _decode(line_len - 2, line_buf, _VALUES, "bad bytes in first line: %R")
    )

    /* Read, parse, and decode the header lines */
    _SET(headers, PyDict_New())
    for (i=0; i<MAX_HEADER_COUNT; i++) {
        _READLINE(args_size_max, MAX_LINE_BYTES)
        _CHECK_LINE_TERMINATION("bad header line termination: %R")
        if (line_len == 2) {
            goto done;  // Stop on the first empty CRLF terminated line
        }

        /* We require both the header key and header value to each be at least
         * one byte in length.  This means that the shortest valid header line
         * (including the CRLF) is six bytes in length:
         *
         *      line| k: vRN  <-- "RN" means "\r\n", the CRLF terminator
         *    offset| 012345
         *      size| 123456
         *
         * So when (line_len < 6), there's no reason to proceed.  This
         * short-circuiting is also a bit safer just in case a given `memmem()`
         * implementation isn't well behaved when (haystacklen < needlelen).
         */
        if (line_len < 6) {
            PyErr_Format(PyExc_ValueError, "header line too short: %R", line);
            goto error;
        }

        /* Find the ": " so we can split the line into a header key and value.
         *
         * Security note: we must be very careful with the pointer maths here!
         */
        line_len -= 2;  // Now we want the line length minus the CRLF
        buf = memmem(line_buf, line_len, ": ", 2);
        if (buf == NULL || buf < line_buf + 1 || buf > line_buf + line_len - 3) {
            PyErr_Format(PyExc_ValueError, "bad header line: %R", line);
            goto error;
        }
        key_len = buf - line_buf;
        value_len = line_len - key_len - 2;
        buf += 2;  // Move the pointer to the first byte in the header value

        /* Decode & case-fold the header key */
        _RESET(key,
            _decode(key_len, line_buf, _KEYS, "bad bytes in header name: %R")
        )

        /* Decode the header value */
        _RESET(value,
            _decode(value_len, buf, _VALUES, "bad bytes in header value: %R")
        )

        /* Store in headers dict, make sure it's not a duplicate key */
        if (PyDict_SetDefault(headers, key, value) != value) {
            PyErr_Format(PyExc_ValueError, "duplicate header: %R", line);
            goto error;
        }
    }

    /* If we reach this point, we've already read MAX_HEADER_COUNT headers, so 
     * we just need to check for the final CRLF preamble terminator:
     */
    _READLINE(args_size_two, 2)
    if (line_len != 2 || memcmp(line_buf, "\r\n", 2) != 0) {
        PyErr_Format(PyExc_ValueError,
            "too many headers (> %u)", MAX_HEADER_COUNT
        );
        goto error;
    }

done:
    if (PyDict_Contains(headers, str_content_length)) {
        if (PyDict_Contains(headers, str_transfer_encoding)) {
            PyErr_SetString(PyExc_ValueError, 
                "cannot have both content-length and transfer-encoding headers"
            );
            goto error;
        }
        _SET(borrowed, PyDict_GetItemWithError(headers, str_content_length))
        _RESET(value, PyLong_FromUnicodeObject(borrowed, 10))
        if (PyObject_RichCompareBool(value, int_zero, Py_LT) > 0) {
            PyErr_Format(PyExc_ValueError, "negative content-length: %R", value);
            goto error;
        }
        if (PyDict_SetItem(headers, str_content_length, value) != 0) {
            goto error;
        }
    }
    else if (PyDict_Contains(headers, str_transfer_encoding)) {
        _SET(borrowed, PyDict_GetItemWithError(headers, str_transfer_encoding))
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
    Py_CLEAR(readline);
    Py_CLEAR(line);
    Py_CLEAR(first_line);
    Py_CLEAR(headers);
    Py_CLEAR(key);
    Py_CLEAR(value);
    return ret;  
}



/* module init */
static struct PyMethodDef degu_functions[] = {
    {"parse_preamble", degu_parse_preamble, METH_VARARGS, "parse_preamble(preamble)"},
    {"read_preamble", degu_read_preamble, METH_VARARGS, "read_preamble(rfile)"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef degu = {
    PyModuleDef_HEAD_INIT,
    "degu._base",
    NULL,
    -1,
    degu_functions
};

PyMODINIT_FUNC
PyInit__base(void)
{
    PyObject *module = NULL;
    PyObject *int_size_max = NULL;
    PyObject *int_size_two = NULL;

    module = PyModule_Create(&degu);
    if (module == NULL) {
        return NULL;
    }

    /* Init integer constants */
    PyModule_AddIntMacro(module, MAX_HEADER_COUNT);
    PyModule_AddIntMacro(module, MAX_LINE_BYTES);

    /* Init EmptyPreambleError exception */
    _SET(degu_EmptyPreambleError,
        PyErr_NewException("degu._base.EmptyPreambleError", PyExc_ConnectionError, NULL)
    )
    Py_INCREF(degu_EmptyPreambleError);
    PyModule_AddObject(module, "EmptyPreambleError", degu_EmptyPreambleError);

    /* Init global Python `int` and `str` objects we need for performance */
    _SET(int_zero, PyLong_FromLong(0))
    _SET(str_readline, PyUnicode_InternFromString("readline"))
    _SET(str_content_length, PyUnicode_InternFromString("content-length"))
    _SET(str_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _SET(str_chunked, PyUnicode_InternFromString("chunked"))

    /* Init pre-built global args tuple for rfile.readline(MAX_LINE_BYTES) */
    _SET(int_size_max, PyObject_GetAttrString(module, "MAX_LINE_BYTES"))    
    _SET(args_size_max, PyTuple_Pack(1, int_size_max))
    Py_CLEAR(int_size_max);

    /* Init pre-built global args tuple for rfile.readline(2) */
    _SET(int_size_two, PyLong_FromLong(2))
    _SET(args_size_two, PyTuple_Pack(1, int_size_two))
    Py_CLEAR(int_size_two);

    return module;

error:
    return NULL;
}
