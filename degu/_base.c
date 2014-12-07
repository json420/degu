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


#define _MAX_LINE_SIZE 4096
#define _MAX_HEADER_COUNT 20

#define CRLF "\r\n"
#define SEP ": "
#define GET "GET"
#define PUT "PUT"
#define POST "POST"
#define HEAD "HEAD"
#define DELETE "DELETE"
#define CONTENT_LENGTH "content-length"
#define TRANSFER_ENCODING "transfer-encoding"
#define CHUNKED "chunked"

#define CONTENT_LENGTH_BIT    1
#define TRANSFER_ENCODING_BIT 2

/* `degu.base.EmptyPreambleError` */
static PyObject *degu_EmptyPreambleError = NULL;

/* Pre-built global Python `int` and `str` objects for performance */
static PyObject *int_zero = NULL;               //  0
static PyObject *str_readline = NULL;           //  'readline'
static PyObject *str_content_length = NULL;     //  'content-length'
static PyObject *str_transfer_encoding = NULL;  //  'transfer-encoding'
static PyObject *str_chunked = NULL;            //  'chunked'
static PyObject *str_empty = NULL;              //  ''
static PyObject *str_crlf = NULL;               //  '\r\n'

static PyObject *str_GET = NULL;     // 'GET'
static PyObject *str_PUT = NULL;     // 'PUT'
static PyObject *str_POST = NULL;    // 'POST'
static PyObject *str_HEAD = NULL;    // 'HEAD'
static PyObject *str_DELETE = NULL;  // 'DELETE'


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


static void
_value_error(const uint8_t *buf, const size_t len, const char *format)
{
    PyObject *tmp = PyBytes_FromStringAndSize((char *)buf, len);
    if (tmp != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp);
    }
    Py_CLEAR(tmp);
}


static PyObject *
_parse_method(const uint8_t *buf, const size_t len)
{
    PyObject *method = NULL;

    if (len == 3) {
        if (memcmp(buf, GET, 3) == 0) {
            method = str_GET;
        }
        else if (memcmp(buf, PUT, 3) == 0) {
            method = str_PUT;
        }
    }
    else if (len == 4) {
        if (memcmp(buf, POST, 4) == 0) {
            method = str_POST;
        }
        else if (memcmp(buf, HEAD, 4) == 0) {
            method = str_HEAD;
        }
    }
    else if (len == 6) {
        if (memcmp(buf, DELETE, 6) == 0) {
            method = str_DELETE;
        }
    }

    if (method == NULL) {
        _value_error(buf, len, "bad HTTP method: %R");
    }
    else {
        Py_INCREF(method);
    }
    return method;
}


static PyObject *
degu_parse_method(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "s#:parse_method", &buf, &len)) {
        return NULL;
    }
    return _parse_method(buf, len);
}



/*
 * _decode(): validate against *table*, possibly case-fold.
 *
 * The *table* determines what bytes are allowed, and whether to case-fold.
 *
 * Return value will be an `str` instance, or NULL when there was an error.
 */
static PyObject *
_decode(const uint8_t *buf, const size_t len, const uint8_t *table, const char *format)
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
        _value_error(buf, len, format);
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


#define _SET_AND_INC(pyobj, source) \
    _SET(pyobj, source) \
    Py_INCREF(pyobj);


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

#define _REPLACE(pyobj, source) \
    _RESET(pyobj, source) \
    Py_INCREF(pyobj);


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
    if (line_len < 2 || memcmp(line_buf + (line_len - 2), CRLF, 2) != 0) { \
        PyObject *_crlf = PySequence_GetSlice(line, _START(line_len), line_len); \
        if (_crlf == NULL) { \
            goto error; \
        } \
        PyErr_Format(PyExc_ValueError, (format), _crlf); \
        Py_CLEAR(_crlf); \
        goto error; \
    }


#define _LENMEMCMP(a_buf, a_len, b_buf, b_len) \
    (a_len == b_len && memcmp(a_buf, b_buf, a_len) == 0)


static inline int
_parse_header_line(uint8_t *buf, const size_t len, PyObject *headers)
{
    uint8_t *sep = NULL;
    uint8_t *key_buf, *val_buf;
    size_t key_len, val_len;
    PyObject *key = NULL;
    PyObject *val = NULL;
    PyObject *tmp = NULL;
    uint8_t r;
    size_t i;
    int flags = 0;

    sep = memmem(buf, len, SEP, 2);
    if (sep == NULL || sep < buf + 1 || sep > buf + len - 3) {
        _value_error(buf, len, "bad header line: %R");
        goto error;
    }
    key_buf = buf;
    key_len = sep - buf;
    val_buf = sep + 2;
    val_len = len - key_len - 2;

    /* Casefold and validate header name in place */
    for (r = i = 0; i < key_len; i++) {
        r |= key_buf[i] = _KEYS[key_buf[i]];
    }
    if (r & 128) {
        if (r != 255) {
            Py_FatalError("internal error in `_parse_header_line()`");
        }
        _value_error(key_buf, key_len, "bad bytes in header name: %R");
    }

    if (_LENMEMCMP(key_buf, key_len, CONTENT_LENGTH, 14)) {
        _SET_AND_INC(key, str_content_length)
        _SET(tmp,
            _decode(val_buf, val_len, _VALUES, "bad bytes in header value: %R")
        )
        _SET(val, PyLong_FromUnicodeObject(tmp, 10))
        int overflow = -2;
        long size = PyLong_AsLongAndOverflow(val, &overflow);
        if (overflow != 0) {
            PyErr_Format(PyExc_ValueError, "content-length too large: %R", tmp);
            goto error;
        }
        if (size < 0) {
            PyErr_Format(PyExc_ValueError, "negative content-length: %R", val);
            goto error;
        }
        flags = CONTENT_LENGTH_BIT;
    }
    else if (_LENMEMCMP(key_buf, key_len, TRANSFER_ENCODING, 17)) {
        if (! _LENMEMCMP(val_buf, val_len, CHUNKED, 7)) {
            _value_error(val_buf, val_len, "bad transfer-encoding: %R");
            goto error;

        }
        _SET_AND_INC(key, str_transfer_encoding)
        _SET_AND_INC(val, str_chunked)
        flags = TRANSFER_ENCODING_BIT;
    }
    else {
        _SET(key,
            PyUnicode_FromKindAndData(PyUnicode_1BYTE_KIND, key_buf, key_len)
        )
        _SET(val,
            _decode(val_buf, val_len, _VALUES, "bad bytes in header value: %R")
        )
    }

    /* Store in headers dict, make sure it's not a duplicate key */
    if (PyDict_SetDefault(headers, key, val) != val) {
        PyErr_Format(PyExc_ValueError, "duplicate header: %R: %R", key, val);
        goto error;
    }
    goto cleanup;

error:  
    flags = -1;

cleanup:
    Py_CLEAR(key);
    Py_CLEAR(val);
    Py_CLEAR(tmp);
    return flags;

}


static PyObject *
_parse_preamble(const uint8_t *preamble_buf, const size_t preamble_len)
{
    const uint8_t *line_buf, *crlf;
    size_t line_len;
    PyObject *first_line = NULL;
    PyObject *headers = NULL;
    PyObject *ret = NULL;

    uint8_t flags = 0;
    int newflags;

    line_buf = preamble_buf;
    line_len = preamble_len;
    crlf = memmem(line_buf, line_len, CRLF, 2);
    if (crlf != NULL) {
        line_len = crlf - line_buf;
    }

    _SET(first_line,
        _decode(line_buf, line_len, _VALUES, "bad bytes in first line: %R")
    )

    /* Read, parse, and decode the header lines */
    _SET(headers, PyDict_New())
    while (crlf != NULL) {
        line_buf = crlf + 2;
        line_len = preamble_len - (line_buf - preamble_buf);
        crlf = memmem(line_buf, line_len, CRLF, 2);
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
            _value_error(line_buf, line_len, "header line too short: %R");
            goto error;
        }

        newflags = _parse_header_line((uint8_t *)line_buf, line_len, headers);
        if (newflags < 0) {
            goto error;
        }
        flags |= newflags;
    }

    if (flags == 3) {
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


static PyObject *
degu_format_request_preamble(PyObject *self, PyObject *args)
{
    PyObject *method, *uri, *headers, *key, *val;
    Py_ssize_t header_count, pos, i;
    PyObject *first_line = NULL;
    PyObject *lines = NULL;
    PyObject *str = NULL;  /* str version of request preamble */
    PyObject *ret = NULL;  /* bytes version of request preamble */

    if (!PyArg_ParseTuple(args, "UUO:format_request_preamble", &method, &uri, &headers)) {
        return NULL;
    }
    if (!PyDict_CheckExact(headers)) {
        PyErr_Format(PyExc_TypeError,
            "headers must be a <class 'dict'>, got a %R", headers->ob_type
        );
        return NULL;
    }

    header_count = PyDict_Size(headers);
    if (header_count == 0) {
        /* Fast-path for when there are zero headers */
        _SET(str, PyUnicode_FromFormat("%S %S HTTP/1.1\r\n\r\n", method, uri))
    }
    else if (header_count == 1) {
        /* Fast-path for when there is one header */
        pos = 0;
        while (PyDict_Next(headers, &pos, &key, &val)) {
            _SET(str,
                PyUnicode_FromFormat("%S %S HTTP/1.1\r\n%S: %S\r\n\r\n",
                    method, uri, key, val
                )
            )
        }        
    }
    else if (header_count > 1) {
        /* Generic path for when header_count > 1 */
        _SET(lines, PyList_New(header_count))
        pos = i = 0;
        while (PyDict_Next(headers, &pos, &key, &val)) {
            PyList_SET_ITEM(lines, i,
                PyUnicode_FromFormat("%S: %S\r\n", key, val)
            );
            i++;
        }
        if (PyList_Sort(lines) != 0) {
            goto error;
        }
        _SET(first_line,
            PyUnicode_FromFormat("%S %S HTTP/1.1\r\n", method, uri)
        )
        if (PyList_Insert(lines, 0, first_line) != 0) {
            goto error;
        }
        if (PyList_Append(lines, str_crlf) != 0) {
            goto error;
        }
        _SET(str, PyUnicode_Join(str_empty, lines))
    }
    else {
        goto error;
    }

    /* Encode str as ASCII bytes */
    _SET(ret, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(first_line);
    Py_CLEAR(lines);
    Py_CLEAR(str);
    return  ret;
}


static PyObject *
degu_format_response_preamble(PyObject *self, PyObject *args)
{
    PyObject *status, *reason, *headers, *key, *val;
    Py_ssize_t header_count, pos, i;
    PyObject *first_line = NULL;
    PyObject *lines = NULL;
    PyObject *str = NULL;  /* str version of response preamble */
    PyObject *ret = NULL;  /* bytes version of response preamble */

    if (!PyArg_ParseTuple(args, "OUO:format_response_preamble", &status, &reason, &headers)) {
        return NULL;
    }
    if (!PyDict_CheckExact(headers)) {
        PyErr_Format(PyExc_TypeError,
            "headers must be a <class 'dict'>, got a %R", headers->ob_type
        );
        return NULL;
    }

    header_count = PyDict_Size(headers);
    if (header_count == 0) {
        /* Fast-path for when there are zero headers */
        _SET(str, PyUnicode_FromFormat("HTTP/1.1 %S %S\r\n\r\n", status, reason))
    }
    else if (header_count == 1) {
        /* Fast-path for when there is one header */
        pos = 0;
        while (PyDict_Next(headers, &pos, &key, &val)) {
            _SET(str,
                PyUnicode_FromFormat("HTTP/1.1 %S %S\r\n%S: %S\r\n\r\n",
                    status, reason, key, val
                )
            )
        }        
    }
    else if (header_count > 1) {
        /* Generic path for when header_count > 1 */
        _SET(lines, PyList_New(header_count))
        pos = i = 0;
        while (PyDict_Next(headers, &pos, &key, &val)) {
            PyList_SET_ITEM(lines, i,
                PyUnicode_FromFormat("%S: %S\r\n", key, val)
            );
            i++;
        }
        if (PyList_Sort(lines) != 0) {
            goto error;
        }
        _SET(first_line,
            PyUnicode_FromFormat("HTTP/1.1 %S %S\r\n", status, reason)
        )
        if (PyList_Insert(lines, 0, first_line) != 0) {
            goto error;
        }
        if (PyList_Append(lines, str_crlf) != 0) {
            goto error;
        }
        _SET(str, PyUnicode_Join(str_empty, lines))
    }
    else {
        goto error;
    }

    /* Encode str as ASCII bytes */
    _SET(ret, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(first_line);
    Py_CLEAR(lines);
    Py_CLEAR(str);
    return  ret;
}



/*
 * C implementation of `degu.base._read_preamble()`.
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

    if (!PyArg_ParseTuple(args, "O:_read_preamble", &rfile)) {
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
    _READLINE(args_size_max, _MAX_LINE_SIZE)
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
        _decode(line_buf, line_len - 2, _VALUES, "bad bytes in first line: %R")
    )

    /* Read, parse, and decode the header lines */
    _SET(headers, PyDict_New())
    for (i=0; i<_MAX_HEADER_COUNT; i++) {
        _READLINE(args_size_max, _MAX_LINE_SIZE)
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
            _decode(line_buf, key_len, _KEYS, "bad bytes in header name: %R")
        )

        /* Decode the header value */
        _RESET(value,
            _decode(buf, value_len, _VALUES, "bad bytes in header value: %R")
        )

        /* Store in headers dict, make sure it's not a duplicate key */
        if (PyDict_SetDefault(headers, key, value) != value) {
            PyErr_Format(PyExc_ValueError, "duplicate header: %R", line);
            goto error;
        }
    }

    /* If we reach this point, we've already read _MAX_HEADER_COUNT headers, so 
     * we just need to check for the final CRLF preamble terminator:
     */
    _READLINE(args_size_two, 2)
    if (line_len != 2 || memcmp(line_buf, CRLF, 2) != 0) {
        PyErr_Format(PyExc_ValueError,
            "too many headers (> %u)", _MAX_HEADER_COUNT
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
    {"parse_method", degu_parse_method, METH_VARARGS, "parse_method(method)"},
    {"parse_preamble", degu_parse_preamble, METH_VARARGS, "parse_preamble(preamble)"},
    {"_read_preamble", degu_read_preamble, METH_VARARGS, "_read_preamble(rfile)"},
    {"format_request_preamble", degu_format_request_preamble, METH_VARARGS,
        "format_request_preamble(method, uri, headers)"},
    {"format_response_preamble", degu_format_response_preamble, METH_VARARGS,
        "format_response_preamble(status, reason, headers)"},
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
    PyModule_AddIntMacro(module, _MAX_HEADER_COUNT);
    PyModule_AddIntMacro(module, _MAX_LINE_SIZE);

#define _ADD_MODULE_STRING(pyobj, name) \
    _SET(pyobj, PyUnicode_InternFromString(name)) \
    Py_INCREF(pyobj); \
    if (PyModule_AddObject(module, name, pyobj) != 0) { \
        goto error; \
    }

    /* Init string constants */
    _ADD_MODULE_STRING(str_GET,    GET)
    _ADD_MODULE_STRING(str_PUT,    PUT)
    _ADD_MODULE_STRING(str_POST,   POST)
    _ADD_MODULE_STRING(str_HEAD,   HEAD)
    _ADD_MODULE_STRING(str_DELETE, DELETE)

    /* Init EmptyPreambleError exception */
    _SET(degu_EmptyPreambleError,
        PyErr_NewException("degu._base.EmptyPreambleError", PyExc_ConnectionError, NULL)
    )
    Py_INCREF(degu_EmptyPreambleError);
    PyModule_AddObject(module, "EmptyPreambleError", degu_EmptyPreambleError);

    /* Init global Python `int` and `str` objects we need for performance */
    _SET(int_zero, PyLong_FromLong(0))
    _SET(str_readline, PyUnicode_InternFromString("readline"))
    _SET(str_content_length, PyUnicode_InternFromString(CONTENT_LENGTH))
    _SET(str_transfer_encoding, PyUnicode_InternFromString(TRANSFER_ENCODING))
    _SET(str_chunked, PyUnicode_InternFromString(CHUNKED))
    _SET(str_empty, PyUnicode_InternFromString(""))
    _SET(str_crlf, PyUnicode_InternFromString(CRLF))

    /* Init pre-built global args tuple for rfile.readline(_MAX_LINE_SIZE) */
    _SET(int_size_max, PyObject_GetAttrString(module, "_MAX_LINE_SIZE"))    
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
