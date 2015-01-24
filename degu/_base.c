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
#include <stdbool.h>


#define _MAX_LINE_SIZE 4096  // Hello
#define _MAX_HEADER_COUNT 20

#define READER_BUFFER_SIZE 65536
#define MAX_PREAMBLE_SIZE 32768

// Constraints for the content-length value:
#define MAX_KEY 32
#define MAX_CL_LEN 16
#define MAX_CL_VALUE 9007199254740992
#define CONTENT_LENGTH_BIT    1
#define TRANSFER_ENCODING_BIT 2

/* `degu.base.EmptyPreambleError` */
static PyObject *degu_EmptyPreambleError = NULL;

/* Pre-built global Python object for performance */
static PyObject *str_recv_into = NULL;          //  'recv_into'
static PyObject *str_Body = NULL;               //  'Body'
static PyObject *str_ChunkedBody = NULL;        //  'ChunkedBody'
static PyObject *str_content_length = NULL;     //  'content-length'
static PyObject *str_transfer_encoding = NULL;  //  'transfer-encoding'
static PyObject *str_chunked = NULL;            //  'chunked'
static PyObject *str_crlf = NULL;               //  '\r\n'
static PyObject *str_GET    = NULL;  // 'GET'
static PyObject *str_PUT    = NULL;  // 'PUT'
static PyObject *str_POST   = NULL;  // 'POST'
static PyObject *str_HEAD   = NULL;  // 'HEAD'
static PyObject *str_DELETE = NULL;  // 'DELETE'
static PyObject *str_OK     = NULL;  // 'OK'

static PyObject *str_empty = NULL;    //  ''
static PyObject *bytes_empty = NULL;  // b''

/* Keys used in the RGI request dict */
static PyObject *str_method  = NULL;  // 'method'
static PyObject *str_uri     = NULL;  // 'uri'
static PyObject *str_script  = NULL;  // 'script'
static PyObject *str_path    = NULL;  // 'path'
static PyObject *str_query   = NULL;  // 'query'
static PyObject *str_headers = NULL;  // 'headers'
static PyObject *str_body    = NULL;  // 'body'



/***************    BEGIN GENERATED TABLES    *********************************/
static const uint8_t _NAMES[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255, 45,255,255, //                           '-'
     48, 49, 50, 51, 52, 53, 54, 55, //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
     56, 57,255,255,255,255,255,255, //  '8'  '9'
    255, 97, 98, 99,100,101,102,103, //       'A'  'B'  'C'  'D'  'E'  'F'  'G'
    104,105,106,107,108,109,110,111, //  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
    112,113,114,115,116,117,118,119, //  'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
    120,121,122,255,255,255,255,255, //  'X'  'Y'  'Z'
    255, 97, 98, 99,100,101,102,103, //       'a'  'b'  'c'  'd'  'e'  'f'  'g'
    104,105,106,107,108,109,110,111, //  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
    112,113,114,115,116,117,118,119, //  'p'  'q'  'r'  's'  't'  'u'  'v'  'w'
    120,121,122,255,255,255,255,255, //  'x'  'y'  'z'
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
 * DIGIT  1 00000001  b'0123456789'
 * ALPHA  2 00000010  b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
 * PATH   4 00000100  b'-.:_~'
 * QUERY  8 00001000  b'%&+='
 * URI   16 00010000  b'/?'
 * SPACE 32 00100000  b' '
 * VALUE 64 01000000  b'"\'()*,;[]'
 */
#define DIGIT_MASK  254  // 11111110  ~(DIGIT)
#define PATH_MASK   248  // 11111000  ~(DIGIT|ALPHA|PATH)
#define QUERY_MASK  240  // 11110000  ~(DIGIT|ALPHA|PATH|QUERY)
#define URI_MASK    224  // 11100000  ~(DIGIT|ALPHA|PATH|QUERY|URI)
#define REASON_MASK 220  // 11011100  ~(DIGIT|ALPHA|SPACE)
#define VALUE_MASK  128  // 10000000  ~(DIGIT|ALPHA|PATH|QUERY|URI|SPACE|VALUE)
static const uint8_t _FLAGS[256] = {
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
     32,128, 64,128,128,  8,  8, 64, //  ' '       '"'            '%'  '&'  "'"
     64, 64, 64,  8, 64,  4,  4, 16, //  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
      1,  1,  1,  1,  1,  1,  1,  1, //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
      1,  1,  4, 64,128,  8,128, 16, //  '8'  '9'  ':'  ';'       '='       '?'
    128,  2,  2,  2,  2,  2,  2,  2, //       'A'  'B'  'C'  'D'  'E'  'F'  'G'
      2,  2,  2,  2,  2,  2,  2,  2, //  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
      2,  2,  2,  2,  2,  2,  2,  2, //  'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
      2,  2,  2, 64,128, 64,128,  4, //  'X'  'Y'  'Z'  '['       ']'       '_'
    128,  2,  2,  2,  2,  2,  2,  2, //       'a'  'b'  'c'  'd'  'e'  'f'  'g'
      2,  2,  2,  2,  2,  2,  2,  2, //  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
      2,  2,  2,  2,  2,  2,  2,  2, //  'p'  'q'  'r'  's'  't'  'u'  'v'  'w'
      2,  2,  2,128,128,128,  4,128, //  'x'  'y'  'z'                 '~'
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
};
/***************    END GENERATED TABLES      *********************************/


static inline size_t
_min(const size_t a, const size_t b)
{
    if (a < b) {
        return a;
    }
    return b;
}


typedef struct {
    const uint8_t *buf;
    const size_t len;
} DeguBuf;


static const DeguBuf NULL_DeguBuf = {NULL, 0}; 


#define _DEGU_BUF_CONSTANT(name, text) \
    static const DeguBuf name = {(uint8_t *)text, sizeof(text) - 1}; 

_DEGU_BUF_CONSTANT(LF, "\n")
_DEGU_BUF_CONSTANT(CRLF, "\r\n")
_DEGU_BUF_CONSTANT(CRLF_CRLF, "\r\n\r\n")
_DEGU_BUF_CONSTANT(OK, "OK")
_DEGU_BUF_CONSTANT(REQUEST_PROTOCOL, " HTTP/1.1")
_DEGU_BUF_CONSTANT(RESPONSE_PROTOCOL, "HTTP/1.1 ")
_DEGU_BUF_CONSTANT(GET, "GET")
_DEGU_BUF_CONSTANT(PUT, "PUT")
_DEGU_BUF_CONSTANT(POST, "POST")
_DEGU_BUF_CONSTANT(HEAD, "HEAD")
_DEGU_BUF_CONSTANT(DELETE, "DELETE")
_DEGU_BUF_CONSTANT(CONTENT_LENGTH, "content-length")
_DEGU_BUF_CONSTANT(TRANSFER_ENCODING, "transfer-encoding")
_DEGU_BUF_CONSTANT(CHUNKED, "chunked")


static bool
_equal(const DeguBuf a, const DeguBuf b) {
    if (a.buf == NULL || b.buf == NULL) {
        Py_FatalError("_equal(): comparing a NULL buffer");
    }
    if (a.len == b.len && memcmp(a.buf, b.buf, a.len) == 0) {
        return true;
    }
    return false;
}


static void
_check_subslice(DeguBuf parent, DeguBuf child)
{
    if (parent.buf == NULL || parent.len == 0) {
        Py_FatalError("parent.buf == NULL || parent.len == 0");
    }
    if (child.buf == NULL || child.buf < parent.buf) {
        Py_FatalError("child.buf == NULL || child.buf < parent.buf");
    }
    if (child.len > parent.len) {
        Py_FatalError("child.len > parent.len");
    }
    if (child.buf + child.len > parent.buf + parent.len) {
        Py_FatalError("child.buf + child.len > parent.buf + parent.len");
    }
}


static DeguBuf
_slice(DeguBuf src, const size_t start, const size_t stop)
{
    if (src.buf == NULL || src.len == 0) {
        Py_FatalError("_slice(): NULL src buffer");
    }
    if (start > stop || stop > src.len) {
        Py_FatalError("_slice(): requested subslice not within parent");
    }
    DeguBuf dst = {src.buf + start, stop - start};
    _check_subslice(src, dst);
    return dst;
}


static DeguBuf
_slice_before(DeguBuf src, const uint8_t *buf)
{
    if (buf < src.buf) {
        Py_FatalError("_slice_before: buf < src.buf");
    }
    return _slice(src, 0, buf - src.buf);
}


static DeguBuf
_slice_after(DeguBuf src, const uint8_t *buf)
{
    if (buf < src.buf) {
        Py_FatalError("_slice_after: buf < src.buf");
    }
    return _slice(src, buf - src.buf, src.len);
}


static DeguBuf
_slice_between(DeguBuf src, const uint8_t *buf_a, const uint8_t *buf_b)
{
    if (buf_a < src.buf || buf_b < src.buf) {
        Py_FatalError("_slice_between: buf_a < src.buf || buf_b < src.buf");
    }
    return _slice(src, buf_a - src.buf, buf_b - src.buf);
}


static PyObject *
_tobytes(DeguBuf src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    if (src.len == 0) {
        Py_XINCREF(bytes_empty);
        return bytes_empty;
    }
    return PyBytes_FromStringAndSize((const char *)src.buf, src.len);
}



static void
_value_error(DeguBuf src, const char *format)
{
    PyObject *tmp = _tobytes(src);
    if (tmp != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp);
    }
    Py_CLEAR(tmp);
}


static void
_value_error2(const char *format, DeguBuf src1, DeguBuf src2)
{
    PyObject *tmp1 = _tobytes(src1);
    PyObject *tmp2 = _tobytes(src2);
    if (tmp1 != NULL && tmp2 != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp1, tmp2);
    }
    Py_CLEAR(tmp1);
    Py_CLEAR(tmp2);
}


static uint8_t *
_calloc_buf(const size_t len)
{
    uint8_t *buf = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        PyErr_NoMemory();
    }
    return buf;
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


#define _SET_ITEM(dict, key, val) \
    if (PyDict_SetItem(dict, key, val) != 0) { \
        goto error; \
    }


#define _APPEND(list, item) \
    if (PyList_Append(list, item) != 0) { \
        goto error; \
    }


#define _VALUE_ERROR(src, format) \
    _value_error(src, format); \
    goto error;


static PyObject *
_parse_method(DeguBuf src)
{
    PyObject *method = NULL;

    if (src.len == 3) {
        if (_equal(src, GET)) {
            method = str_GET;
        }
        else if (_equal(src, PUT)) {
            method = str_PUT;
        }
    }
    else if (src.len == 4) {
        if (_equal(src, POST)) {
            method = str_POST;
        }
        else if (_equal(src, HEAD)) {
            method = str_HEAD;
        }
    }
    else if (_equal(src, DELETE)) {
        method = str_DELETE;
    }
    if (method == NULL) {
        _value_error(src, "bad HTTP method: %R");
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
    return _parse_method((DeguBuf){buf, len});
}


static PyObject *
_parse_header_name(DeguBuf src)
{
    PyObject *dst = NULL;
    uint8_t *dst_buf;
    uint8_t r;
    size_t i;

    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return NULL; 
    }
    if (src.len > MAX_KEY) {
        _value_error(
            _slice(src, 0, MAX_KEY),
            "header name too long: %R..."
        );
        return NULL; 
    }
    dst = PyUnicode_New(src.len, 127);
    if (dst == NULL) {
        return NULL;
    }
    dst_buf = PyUnicode_1BYTE_DATA(dst);
    for (r = i = 0; i < src.len; i++) {
        r |= dst_buf[i] = _NAMES[src.buf[i]];
    }
    if (r & 128) {
        Py_CLEAR(dst);
        if (r != 255) {
            Py_FatalError("internal error in `_parse_header_name()`");
        }
        _value_error(src, "bad bytes in header name: %R");
    }
    return dst;
}


static PyObject *
parse_header_name(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_header_name", &buf, &len)) {
        return NULL;
    }
    return _parse_header_name((DeguBuf){buf, len});
}


static PyObject *
_decode(DeguBuf src, const uint8_t mask, const char *format)
{
    PyObject *dst = NULL;
    uint8_t *dst_buf = NULL;
    uint8_t c, bits;
    size_t i;

    if (mask == 0 || (mask & 1) != 0) {
        Py_FatalError("internal error in `_decode()`: bad mask");
    }
    if (src.len < 1) {
        _SET_AND_INC(dst, str_empty);
        goto done;
    }
    _SET(dst, PyUnicode_New(src.len, 127))
    dst_buf = PyUnicode_1BYTE_DATA(dst);
    for (bits = i = 0; i < src.len; i++) {
        c = dst_buf[i] = src.buf[i];
        bits |= _FLAGS[c];
    }
    if (bits == 0) {
        Py_FatalError("internal error in `_decode()`");
    }
    if ((bits & mask) != 0) {
        _value_error(src, format);
        goto error;
    }
    goto done;

error:
    Py_CLEAR(dst);

done:
    return dst;
}



/*
 * _parse_content_length(): strictly parse `buf` to build a `PyLongObject`.
 *
 * This is largely to work-around shortcomings in the CPython C API, which
 * has `PyLong_FromString()`, but no `PyLong_FromStringAndSize()`.  This
 * allows us to more strictly parse a content-length header value, and without
 * building an intermediate `PyUnicodeObject` (which carries a fairly large
 * performance hit).
 *
 * This function doesn't allow leading or trailing whitespace, nor does it
 * allow leading zeros (except in the special case when buf == b'0').
 *
 */
static PyObject *
_parse_content_length(DeguBuf src)
{
    uint64_t accum = 0;
    uint8_t bits = 0;
    uint8_t c;
    size_t i;

    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "content-length is empty");
        return NULL; 
    }
    if (src.len > MAX_CL_LEN) {
        _value_error(
            _slice(src, 0, MAX_CL_LEN),
            "content-length too long: %R..."
        );
        return NULL; 
    }
    for (i = 0; i < src.len; i++) {
        accum *= 10;
        c = src.buf[i];
        bits |= _FLAGS[c];
        accum += (c - 48);
    }
    if (bits == 0) {
        Py_FatalError("internal error in `_parse_content_length`");
    }
    if ((bits & DIGIT_MASK) != 0) {
        _value_error(src, "bad bytes in content-length: %R");
        return NULL;
    }
    if (src.buf[0] == 48 && src.len != 1) {
        _value_error(src, "content-length has leading zero: %R");
        return NULL;
    }
    if (accum > (uint64_t)MAX_CL_VALUE) {
        PyErr_Format(PyExc_ValueError,
            "content-length value too large: %llu", accum
        );
        return NULL;
    }
    return PyLong_FromUnsignedLongLong(accum);
}


static PyObject *
parse_content_length(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "s#:parse_content_length", &buf, &len)) {
        return NULL;
    }
    return _parse_content_length((DeguBuf){buf, len});
}


static PyObject *
_parse_status(DeguBuf src)
{

    uint8_t d;
    uint8_t err;
    unsigned long accum;

    if (src.len != 3) {
        _value_error(src, "bad status length: %R");
        return NULL;
    }
    d = src.buf[0];    err =  (d < 49 || d > 57);    accum =  (d - 48) * 100;
    d = src.buf[1];    err |= (d < 48 || d > 57);    accum += (d - 48) *  10;
    d = src.buf[2];    err |= (d < 48 || d > 57);    accum += (d - 48);
    if (err || accum < 100 || accum > 599) {
        _value_error(src, "bad status: %R");
        return NULL;
    }
    return PyLong_FromUnsignedLong(accum);
}


static PyObject *
_parse_reason(DeguBuf src)
{
    if (_equal(src, OK)) {
        Py_XINCREF(str_OK);
        return str_OK;
    }
    return _decode(src, REASON_MASK, "bad reason: %R");
}


static bool
_parse_response_line(DeguBuf src, PyObject *response)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;

    /* Reject any response line shorter than 15 bytes:
     *
     *     "HTTP/1.1 200 OK"[0:15]
     *      ^^^^^^^^^^^^^^^
     */
    if (src.len < 15) {
        _value_error(src, "response line too short: %R");
        return false;
    }

    /* protocol, spaces:
     *
     *     "HTTP/1.1 200 OK"[0:9]
     *      ^^^^^^^^^
     *
     *     "HTTP/1.1 200 OK"[12:13]
     *                  ^
     */

    if (memcmp(src.buf, "HTTP/1.1 ", 9) != 0 || src.buf[12] != ' ') {
        _value_error(src, "bad response line: %R");
        return false;
    }

    /* status:
     *
     *     "HTTP/1.1 200 OK"[9:12]
     *               ^^^
     */

    _SET(status, _parse_status(_slice(src, 9, 12)))

    /* reason:
     *
     *     "HTTP/1.1 200 OK"[13:]
     *                   ^^
     */
    _SET(reason, _parse_reason(_slice(src, 13, src.len)))

    /* Success! */
    PyTuple_SET_ITEM(response, 0, status);
    PyTuple_SET_ITEM(response, 1, reason);
    return true;

error:
    Py_CLEAR(status);
    Py_CLEAR(reason);
    return false;
}


static PyObject *
parse_response_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "s#:parse_response_line", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    PyObject *response = PyTuple_New(2);
    if (response == NULL) {
        return NULL;
    }
    if (!_parse_response_line(src, response)) {
        Py_CLEAR(response);
    }
    return response;
}


static PyObject *
_parse_path(DeguBuf src)
{
    PyObject *path = NULL;
    PyObject *component = NULL;
    const uint8_t *start, *stop, *final_stop;

    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "path is empty");
        goto error;
    }
    if (src.buf[0] != '/') {
        _VALUE_ERROR(src, "path[0:1] != b'/': %R")
    }

    _SET(path, PyList_New(0))
    if (src.len == 1) {
        goto cleanup;
    }
    final_stop = src.buf + src.len;
    start = src.buf + 1;
    while (start < final_stop) {
        stop = memchr(start, '/', final_stop - start);
        if (stop == NULL) {
            stop = final_stop;
        }
        if (start >= stop) {
            _VALUE_ERROR(src, "b'//' in path: %R")
        }
        if (stop - start == 2)
        _REPLACE(component,
            _decode(
                _slice_between(src, start, stop),
                PATH_MASK,
                "bad bytes in path component: %R"
            )
        )
        _APPEND(path, component)
        start = stop + 1;
    }
    if (src.buf[src.len - 1] == '/') {
        _APPEND(path, str_empty)
    }
    goto cleanup;

error:
    Py_CLEAR(path);

cleanup:
    Py_CLEAR(component);
    return path;
}


static inline PyObject *
_parse_query(DeguBuf src)
{
    return _decode(src, QUERY_MASK, "bad bytes in query: %R");
}


static bool
_parse_uri(DeguBuf src, PyObject *request)
{
    bool success = true;
    const uint8_t *q;
    PyObject *uri = NULL;
    PyObject *script = NULL;
    PyObject *path = NULL;
    PyObject *query = NULL;

    /* Sanity check */
    if (src.buf == NULL || request == NULL || !PyDict_CheckExact(request)) {
        Py_FatalError("bad internal call to _parse_uri()");
    }

    /* Don't allow an empty uri */
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "uri is empty");
        goto error;
    }

    /* Build PyObjects used as values in request dict */
    _SET(uri,
        _decode(src, URI_MASK, "bad bytes in uri: %R")
    )
    _SET(script, PyList_New(0))
    q = memchr(src.buf, '?', src.len);
    if (q == NULL) {
        _SET(path, _parse_path(src))
        _SET_AND_INC(query, Py_None)
    }
    else {
        _SET(path, _parse_path(_slice_before(src, q)))
        _SET(query, _parse_query(_slice_after(src, q + 1)))
    }

    /* Fill in values in request dict */
    _SET_ITEM(request, str_uri, uri)
    _SET_ITEM(request, str_script, script)
    _SET_ITEM(request, str_path, path)
    _SET_ITEM(request, str_query, query)
    goto cleanup;

error:
    success = false;

cleanup:
    Py_CLEAR(uri);
    Py_CLEAR(script);
    Py_CLEAR(path);
    Py_CLEAR(query);
    return success;
}


static bool
_parse_request_line(DeguBuf line, PyObject *request)
{
    bool success = true;
    uint8_t *sep;
    size_t method_stop, uri_start;
    PyObject *method = NULL;

    /* Sanity check */
    if (line.buf == NULL || request == NULL || !PyDict_CheckExact(request)) {
        Py_FatalError("bad internal call to _parse_request_line()");
    }

    /* Reject any request line shorter than 14 bytes:
     *
     *     "GET / HTTP/1.1"[0:14]
     *      ^^^^^^^^^^^^^^
     */
    if (line.len < 14) {
        _value_error(line, "request line too short: %R");
        goto error;
    }

    /* verify final 9 bytes (protocol):
     *
     *     "GET / HTTP/1.1"[-9:]
     *           ^^^^^^^^^
     */
    DeguBuf protocol = _slice(line, line.len - 9, line.len);
    if (! _equal(protocol, REQUEST_PROTOCOL)) {
        _value_error(protocol, "bad protocol in request line: %R");
        goto error;
    }

    /* Now we'll work with line[0:-9]
     *
     *     "GET / HTTP/1.1"[0:-9]
     *      ^^^^^
     */
    DeguBuf src = _slice(line, 0, line.len - protocol.len);

    /* Search for method terminating space, plus start of uri:
     *
     *     "GET /"
     *         ^^
     */
    sep = memmem(src.buf, src.len, " /", 2);
    if (sep == NULL) {
        _value_error(line, "bad request line: %R");
        goto error;
    }
    method_stop = sep - src.buf;
    uri_start = method_stop + 1;

    /* Parse the method, add it to the request dict */
    _SET(method, _parse_method(_slice(src, 0, method_stop)))
    _SET_ITEM(request, str_method, method)

    /* _parse_uri() will fill in uri, script, request, and query */
    if (!_parse_uri(_slice(src, uri_start, src.len), request)) {
        goto error;
    }
    goto cleanup;

error:
    success = false;

cleanup:
    Py_CLEAR(method);
    return success;
}


static PyObject *
parse_uri(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *request = NULL;

    if (!PyArg_ParseTuple(args, "y#:parse_uri", &buf, &len)) {
        return NULL;
    }
    _SET(request, PyDict_New())
    DeguBuf src = {buf, len};
    if (!_parse_uri(src, request)) {
        goto error;
    }
    goto cleanup;

error:
    Py_CLEAR(request);

cleanup:
    return request;
}


static PyObject *
parse_request_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *request = NULL;

    if (!PyArg_ParseTuple(args, "s#:parse_request_line", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    _SET(request, PyDict_New())
    if (! _parse_request_line(src, request)) {
        goto error;
    }
    goto done;

error:
    Py_CLEAR(request);

done:
    return request;
}


static inline bool
_parse_key(DeguBuf key, uint8_t *scratch)
{
    uint8_t r;
    size_t i;

    if (key.len > MAX_KEY) {
        _value_error(_slice(key, 0, MAX_KEY), "header name too long: %R...");
        return false;
    }
    for (r = i = 0; i < key.len; i++) {
        r |= scratch[i] = _NAMES[key.buf[i]];
    }
    if (r & 128) {
        if (r != 255) {
            Py_FatalError("internal error in `_parse_header_name()`");
        }
        _value_error(key, "bad bytes in header name: %R");
        return false;
    }
    return true;
}


static PyObject *
_tostr(DeguBuf src)
{
    PyObject *dst = PyUnicode_New(src.len, 127);
    if (dst == NULL) {
        return NULL;
    }
    uint8_t *dst_buf = PyUnicode_1BYTE_DATA(dst);
    memcpy(dst_buf, src.buf, src.len);
    return dst;
}


static inline PyObject *
_parse_val(DeguBuf val)
{
    return _decode(val, VALUE_MASK, "bad bytes in header value: %R");
}


static int
_parse_header_line(DeguBuf src, PyObject *headers, uint8_t *scratch)
{
    const uint8_t *sep = NULL;
    PyObject *key = NULL;
    PyObject *val = NULL;
    int flags = 0;

    if (src.len < 4) {
        _value_error(src, "header line too short: %R");
        goto error;
    }

    // FIXME: User a better error message here
    sep = memmem(src.buf + 1, src.len - 1, ": ", 2);
    if (sep == NULL) {
        _value_error(src, "bad header line: %R");
        goto error;
    }
    DeguBuf rawkeysrc = _slice(src, 0, sep - src.buf);
    DeguBuf valsrc = _slice(src, rawkeysrc.len + 2, src.len);

    if (! _parse_key(rawkeysrc, scratch)) {
        goto error;
    }
    DeguBuf keysrc = {scratch, rawkeysrc.len};

    if (_equal(keysrc, CONTENT_LENGTH)) {
        _SET_AND_INC(key, str_content_length)
        _SET(val, _parse_content_length(valsrc))
        flags = CONTENT_LENGTH_BIT;
    }
    else if (_equal(keysrc, TRANSFER_ENCODING)) {
        if (! _equal(valsrc, CHUNKED)) {
            _value_error(valsrc, "bad transfer-encoding: %R");
            goto error;
        }
        _SET_AND_INC(key, str_transfer_encoding)
        _SET_AND_INC(val, str_chunked)
        flags = TRANSFER_ENCODING_BIT;
    }
    else {
        _SET(key, _tostr(keysrc))
        _SET(val, _parse_val(valsrc))
    }

    /* Store in headers dict, make sure it's not a duplicate key */
    if (PyDict_SetDefault(headers, key, val) != val) {
        _value_error(src, "duplicate header: %R");
        goto error;
    }
    goto cleanup;

error:  
    flags = -1;

cleanup:
    Py_CLEAR(key);
    Py_CLEAR(val);
    return flags;
}


static PyObject *
_parse_headers(DeguBuf src, uint8_t *scratch)
{
    PyObject *headers = NULL;
    const uint8_t *start, *stop, *final_stop;
    uint8_t flags = 0;
    int newflags;

    _SET(headers, PyDict_New())
    if (src.len == 0) {
        goto cleanup;
    }

    final_stop = src.buf + src.len;
    start = src.buf;
    while (start < final_stop) {
        stop = memmem(start, final_stop - start, CRLF.buf, CRLF.len);
        if (stop == NULL) {
            stop = final_stop;
        }
        newflags = _parse_header_line(
            _slice_between(src, start, stop), headers, scratch
        );
        if (newflags < 0) {
            goto error;
        }
        flags |= newflags;
        start = stop + 2;
    }
    if (flags == 3) {
        PyErr_SetString(PyExc_ValueError, 
            "cannot have both content-length and transfer-encoding headers"
        );
        goto error; 
    }
    goto cleanup;

error:
    Py_CLEAR(headers);

cleanup:
    return headers;
}


static PyObject *
_parse_request(DeguBuf src, uint8_t *scratch)
{
    PyObject *request = NULL;
    PyObject *headers = NULL;
    uint8_t *crlf;
    size_t stop_line, start_headers;

    crlf = memmem(src.buf, src.len, CRLF.buf, CRLF.len);
    if (crlf == NULL) {
        stop_line =  src.len;
        start_headers = src.len;
    }
    else {
        stop_line = crlf - src.buf;
        start_headers = stop_line + 2;
    }

    _SET(request, PyDict_New())
    if (! _parse_request_line(_slice(src, 0, stop_line), request)) {
        goto error;
    }
    _SET(headers,
        _parse_headers(_slice(src, start_headers, src.len), scratch)
    )
    _SET_ITEM(request, str_headers, headers)
    goto cleanup;

error:
    Py_CLEAR(request);

cleanup:
    Py_CLEAR(headers);
    return request;
}


static PyObject *
_parse_response(DeguBuf src, uint8_t *scratch)
{
    PyObject *response = NULL;
    PyObject *headers = NULL;
    uint8_t *crlf;
    size_t stop_line, start_headers;

    crlf = memmem(src.buf, src.len, CRLF.buf, CRLF.len);
    if (crlf == NULL) {
        stop_line =  src.len;
        start_headers = src.len;
    }
    else {
        stop_line = crlf - src.buf;
        start_headers = stop_line + 2;
    }
    _SET(response, PyTuple_New(3))
    if (! _parse_response_line(_slice(src, 0, stop_line), response)) {
        goto error;
    }
    _SET(headers,
        _parse_headers(_slice(src, start_headers, src.len), scratch)
    )
    PyTuple_SET_ITEM(response, 2, headers);
    goto cleanup;

error:
    Py_CLEAR(response);
    Py_CLEAR(headers);

cleanup:
    return response;
}


static PyObject *
parse_request(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    if (!PyArg_ParseTuple(args, "y#:parse_request", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    uint8_t *scratch = _calloc_buf(MAX_KEY);
    if (scratch == NULL) {
        return NULL;
    }
    PyObject *ret = _parse_request(src, scratch);
    free(scratch);
    return ret;
}


static PyObject *
parse_response(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    if (!PyArg_ParseTuple(args, "y#:parse_response", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    uint8_t *scratch = _calloc_buf(MAX_KEY);
    if (scratch == NULL) {
        return NULL;
    }
    PyObject *ret = _parse_response(src, scratch);
    free(scratch);
    return ret;
}


static PyObject *
_format_headers(PyObject *headers)
{
    PyObject *key, *val;
    ssize_t header_count, pos, i;
    PyObject *lines = NULL;
    PyObject *ret = NULL;  /* str version of request preamble */

    header_count = PyDict_Size(headers);
    _SET(lines, PyList_New(header_count))
    pos = i = 0;
    while (PyDict_Next(headers, &pos, &key, &val)) {
        PyList_SET_ITEM(lines, i,
            PyUnicode_FromFormat("%S: %S\r\n", key, val)
        );
        i++;
    }
    /* Sorting is really expensive!
     *
     * 8 headers, sorted:
     *     597,177: format_headers(headers)
     * 
     * 8 headers, unsorted:
     *     752,831: format_headers(headers)
     */
    if (header_count > 1) {
        if (PyList_Sort(lines) != 0) {
            goto error;
        }
    }
    _SET(ret, PyUnicode_Join(str_empty, lines))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(lines);
    return  ret;
}


static PyObject *
format_headers(PyObject *self, PyObject *args)
{
    PyObject *headers = NULL;

    if (!PyArg_ParseTuple(args, "O:format_headers", &headers)) {
        return NULL;
    }
    if (!PyDict_CheckExact(headers)) {
        PyErr_Format(PyExc_TypeError,
            "headers must be a <class 'dict'>, got a %R", headers->ob_type
        );
        return NULL;
    }

    return _format_headers(headers);
}


static PyObject *
degu_format_request_preamble(PyObject *self, PyObject *args)
{
    PyObject *method, *uri, *headers, *key, *val;
    ssize_t header_count, pos, i;
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
    ssize_t header_count, pos, i;
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


typedef struct {
    PyObject_HEAD
    PyObject *sock_recv_into;
    PyObject *bodies_Body;
    PyObject *bodies_ChunkedBody;
    uint8_t *scratch;
    size_t rawtell;
    uint8_t *buf;
    size_t len;
    size_t start;
    size_t stop;
} Reader;


static void
Reader_dealloc(Reader *self)
{
    Py_CLEAR(self->sock_recv_into);
    Py_CLEAR(self->bodies_Body);
    Py_CLEAR(self->bodies_ChunkedBody);
    if (self->scratch != NULL) {
        free(self->scratch);
        self->scratch = NULL;
    }
    if (self->buf != NULL) {
        free(self->buf);
        self->buf = NULL;
    }
}


static int
Reader_init(Reader *self, PyObject *args, PyObject *kw)
{
    PyObject *sock=NULL, *bodies=NULL;
    static char *keys[] = {"sock", "bodies", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO|Reader", keys, &sock, &bodies)) {
        return -1;
    }

    _SET(self->sock_recv_into, PyObject_GetAttr(sock, str_recv_into))
    if (!PyCallable_Check(self->sock_recv_into)) {
        PyErr_SetString(PyExc_TypeError, "sock.recv_into() is not callable");
        goto error;
    }
    _SET(self->bodies_Body, PyObject_GetAttr(bodies, str_Body))
    if (!PyCallable_Check(self->bodies_Body)) {
        PyErr_SetString(PyExc_TypeError, "bodies.Body() is not callable");
        goto error;
    }
    _SET(self->bodies_ChunkedBody, PyObject_GetAttr(bodies, str_ChunkedBody))
    if (!PyCallable_Check(self->bodies_ChunkedBody)) {
        PyErr_SetString(PyExc_TypeError, "bodies.ChunkedBody() is not callable");
        goto error;
    }

    _SET(self->scratch, _calloc_buf(MAX_KEY))
    self->len = READER_BUFFER_SIZE;
    _SET(self->buf, _calloc_buf(self->len))
    self->rawtell = 0;
    self->start = 0;
    self->stop = 0;
    return 0;

error:
    Reader_dealloc(self);
    return -1;
}


/* _Reader_recv_into():
 *     -1  general error code for when _SET() goes to error
 *     -2  sock.recv_into() did not return an `int`
 *     -3  overflow when converting to size_t (`OverflowError` raised)
 *     -4  sock.recv_into() did not return 0 <= size <= len
 */
static ssize_t
_Reader_sock_recv_into(Reader *self, uint8_t *buf, const size_t len)
{
    PyObject *view = NULL;
    PyObject *int_size = NULL;
    ssize_t size;
    ssize_t ret = -1;

    if (self == NULL || buf == NULL || len < 1) {
        Py_FatalError("bad internal call to _Reader_recv_into()");
    }

    _SET(view,
        PyMemoryView_FromMemory((char *)buf, len, PyBUF_WRITE)
    )
    _SET(int_size,
        PyObject_CallFunctionObjArgs(self->sock_recv_into, view, NULL)
    )

    /* sock.recv_into() must return an `int` */
    if (!PyLong_CheckExact(int_size)) {
        PyErr_Format(PyExc_TypeError,
            "sock.recv_into() returned %R, should return <class 'int'>",
            int_size->ob_type
        );
        ret = -2;
        goto error;
    }

    /* Convert to size_t, check for OverflowError */
    size = PyLong_AsSsize_t(int_size);
    if (PyErr_Occurred()) {
        ret = -3;
        goto error;
    }

    /* sock.recv_into() must return (0 <= size <= len) */
    if (size < 0 || size > len) {
        PyErr_Format(PyExc_IOError,
            "sock.recv_into() returned size=%zd; need 0 <= size <= %zd",
            size, len
        );
        ret = - 4;
        goto error;
    }

    /* Add this number into our running raw read total */
    self->rawtell += size;
    ret = size;
    goto cleanup;

error:
    if (ret >= 0) {
        Py_FatalError(
            "internal error in _Reader_recv_into(): in error, but ret >= 0"
        );
    }

cleanup:
    Py_CLEAR(view);
    Py_CLEAR(int_size);
    return ret;
}


static DeguBuf
_Reader_peek(Reader *self, const size_t size)
{
    if (self->buf == NULL) {
        Py_FatalError("_Reader_peak: buf == NULL");
    }
    if (self->stop > self->len) {
        Py_FatalError("_Reader_peak: stop > len");
    }
    if (self->start >= self->stop && self->start != 0) {
        Py_FatalError("_Reader_peak: start >= stop && start != 0");
    }
    const uint8_t *cur_buf = self->buf + self->start;
    const size_t cur_len = self->stop - self->start;
    return (DeguBuf){cur_buf, _min(size, cur_len)};
}


static DeguBuf
_Reader_drain(Reader *self, const size_t size)
{
    DeguBuf cur = _Reader_peek(self, size);
    self->start += cur.len;
    if (self->start >= self->stop) {
        self->start = 0;
        self->stop = 0;
    }
    return  cur;
}


static DeguBuf
_Reader_fill(Reader *self, const size_t size)
{
    ssize_t added;

    if (size < 0 || size > self->len) {
        PyErr_Format(PyExc_ValueError,
            "need 0 <= size <= %zd; got %zd", self->len, size
        );
        return NULL_DeguBuf;
    }
    DeguBuf cur = _Reader_peek(self, size);
    if (cur.len == size) {
        return cur;
    }
    if (cur.len > size) {
        Py_FatalError("_Reader_fill(): cur.len > size");
    }
    if (self->start > 0) {
        memmove(self->buf, cur.buf, cur.len);
        self->start = 0;
        self->stop = cur.len;
    }
    added = _Reader_sock_recv_into(self, self->buf + cur.len, self->len - cur.len);
    if (added < 0) {
        return NULL_DeguBuf;
    }
    self->stop += added;
    return _Reader_peek(self, size);
}


static DeguBuf
_Reader_fill_until(Reader *self, const size_t size, DeguBuf end, bool *found)
{
    size_t avail;
    uint8_t *ptr;
    size_t offset;
    ssize_t added;

    if (end.buf == NULL) {
        Py_FatalError("_Reader_fill_until: end.buf == NULL");
    }
    if (end.len == 0) {
        PyErr_SetString(PyExc_ValueError, "end cannot be empty");
        return NULL_DeguBuf;
    }
    if (size < end.len || size > self->len) {
        PyErr_Format(PyExc_ValueError,
            "need %zd <= size <= %zd; got %zd", end.len, self->len, size
        );
        return NULL_DeguBuf;
    }

    /* First, search current buffer */
    DeguBuf cur = _Reader_peek(self, size);
    if (cur.len >= end.len) {
        ptr = memmem(cur.buf, cur.len, end.buf, end.len);
        if (ptr != NULL) {
            *found = true;
            offset = ptr - cur.buf;
            return _Reader_peek(self, offset + end.len); 
        }
        if (cur.len >= size) {
            if (cur.len != size) {
                Py_FatalError("_Reader_fill_until: cur.len >= size");
            }
            return cur;
        }
    }

    /* Shift buffer if needed */
    if (self->start > 0) {
        if (cur.len < 1) {
            Py_FatalError("_Reader_fill_until: cur.len < 1");
        }
        memmove(self->buf, cur.buf, cur.len);
        self->start = 0;
        self->stop = cur.len;
    }

    /* Now search till found */
    while (self->stop < size) {
        if (self->stop > self->len) {
            Py_FatalError("_Reader_fill_until: self->stop > self->len");
        }
        avail = self->len - self->stop;
        added = _Reader_sock_recv_into(self, self->buf + self->stop, avail);
        if (added < 0) {
            return NULL_DeguBuf;
        }
        if (added == 0) {
            return _Reader_peek(self, self->stop);
        }
        self->stop += added;
        ptr = memmem(self->buf, _min(self->stop, size), end.buf, end.len);
        if (ptr != NULL) {
            *found = true;
            offset = ptr - self->buf;
            return _Reader_peek(self, offset + end.len); 
        }
    }
    return _Reader_peek(self, size); 
}


static DeguBuf
_Reader_search(Reader *self, const size_t size, DeguBuf end,
               const int include_end, const int always_return)
{
    bool found = false;

    if (end.buf == NULL) {
        Py_FatalError("_Reader_search: end.buf == NULL");
    }
    if (end.len == 0) {
        PyErr_SetString(PyExc_ValueError, "end cannot be empty");
        return NULL_DeguBuf;
    }

    DeguBuf src = _Reader_fill_until(self, size, end, &found);
    if (src.buf == NULL) {
        return NULL_DeguBuf;
    }
    if (src.len == 0) {
        return src;
    }

    if (! found) {
        if (always_return) {
            return _Reader_drain(self, src.len);
        }
        _value_error2(
            "%R not found in %R...", end, _slice(src, 0, _min(src.len, 32))
        );
        return NULL_DeguBuf;
    }

    DeguBuf ret = _Reader_drain(self, src.len);
    if (include_end) {
        return ret;
    }
    return _slice(ret, 0, ret.len - end.len);
}


static PyObject *
Reader_read_request(Reader *self) {
    DeguBuf src = _Reader_search(self, self->len, CRLF_CRLF, false, false);
    if (src.buf == NULL) {
        return NULL;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "request preamble is empty");
        return NULL;
    }
    return _parse_request(src, self->scratch);
}


static PyObject *
Reader_read_response(Reader *self) {
    DeguBuf src = _Reader_search(self, self->len, CRLF_CRLF, false, false);
    if (src.buf == NULL) {
        return NULL;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "response preamble is empty");
        return NULL;
    }
    return _parse_response(src, self->scratch);
}


static PyObject *
Reader_fill(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_fill(self, size));
}


static PyObject *
Reader_expose(Reader *self) {
    DeguBuf rawbuf = {self->buf, self->len};
    return _tobytes(rawbuf);
}


static PyObject *
Reader_peek(Reader *self, PyObject *args) {
    ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_peek(self, size));
}


static PyObject *
Reader_drain(Reader *self, PyObject *args) {
    ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_drain(self, size));
}


static PyObject *
Reader_fill_until(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    uint8_t *end_buf = NULL;
    size_t end_len = 0;
    bool found = false;
    PyObject *pyfound = NULL;
    PyObject *pydata = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "ny#", &size, &end_buf, &end_len)) {
        return NULL;
    }
    DeguBuf end = {end_buf, end_len};
    DeguBuf src = _Reader_fill_until(self, size, end, &found);
    if (found) {
        pyfound = Py_True;
    }
    else {
        pyfound = Py_False;
    }
    Py_INCREF(pyfound);
    _SET(pydata, _tobytes(src))
    _SET(ret, PyTuple_Pack(2, pyfound, pydata))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(pyfound);
    Py_CLEAR(pydata);
    return ret;
}


static PyObject *
Reader_search(Reader *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"size", "end", "include_end", "always_return", NULL};
    ssize_t size = -1;
    uint8_t *end_buf = NULL;
    size_t end_len = 0;
    int include_end = false;
    int always_return = false;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "ny#|pp:search", keys,
            &size, &end_buf, &end_len, &include_end, &always_return)) {
        return NULL;
    }
    DeguBuf end = {end_buf, end_len};
    return _tobytes(
        _Reader_search(self, size, end, include_end, always_return)
    );
}


static PyObject *
Reader_readline(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_search(self, size, LF, true, true));
}


static PyObject *
Reader_read(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    uint8_t *dst_buf;
    size_t start;
    ssize_t added;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    if (size < 0) {
        PyErr_Format(PyExc_ValueError, "need size >= 0; got %zd", size);
        return NULL;
    }
    DeguBuf src = _Reader_drain(self, size);
    if (src.len == size) {
        _SET(ret, _tobytes(src))
        goto cleanup;
    }
    if (src.len >= size) {
        Py_FatalError("_Reader_read: src.len >= size");
    }

    _SET(ret, PyBytes_FromStringAndSize(NULL, size))
    dst_buf = (uint8_t *)PyBytes_AS_STRING(ret);
    memcpy(dst_buf, src.buf, src.len);

    start = src.len;
    while (start < size) {
        added = _Reader_sock_recv_into(self, dst_buf + start, size - start);
        if (added < 0) {
            goto error;
        }
        if (added == 0) {
            break;
        }
        start += added;
        if (start > size) {
            Py_FatalError("_Reader_read: start > size");
        }
    }
    if (start < size) {
        if (_PyBytes_Resize(&ret, start) != 0) {
            goto error;
        }
    }
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    return ret;
}


static PyObject *
Reader_close(Reader *self)
{
    Py_RETURN_NONE;
}


static PyObject *
Reader_start_stop(Reader *self)
{
    PyObject *ret = NULL;
    PyObject *start = PyLong_FromSize_t(self->start);
    PyObject *stop = PyLong_FromSize_t(self->stop);
    if (start != NULL && stop != NULL) {
        ret = PyTuple_Pack(2, start, stop);
    }
    Py_CLEAR(start);
    Py_CLEAR(stop);
    return ret;
}


/* Reader.rawtell() */
static PyObject *
Reader_rawtell(Reader *self) {
    return PyLong_FromSize_t(self->rawtell);
}

/* Reader.tell() */
static PyObject *
Reader_tell(Reader *self) {
    DeguBuf cur = _Reader_peek(self, self->len);
    return PyLong_FromSize_t(self->rawtell - cur.len);
}


static PyMethodDef Reader_methods[] = {
    {"close", (PyCFunction)Reader_close, METH_NOARGS, "close()"},
    {"start_stop", (PyCFunction)Reader_start_stop, METH_NOARGS,
        "return (start, stop) tuple"
    },
    {"rawtell", (PyCFunction)Reader_rawtell, METH_NOARGS,
        "return number of bytes thus far read from the underlying socket"
    },
    {"tell", (PyCFunction)Reader_tell, METH_NOARGS,
        "total bytes thus far read from logical stream"
    },
    {"read_request", (PyCFunction)Reader_read_request, METH_NOARGS,
        "read_request()"
    },
    {"read_response", (PyCFunction)Reader_read_response, METH_NOARGS,
        "read_response()"
    },

    {"fill", (PyCFunction)Reader_fill, METH_VARARGS, "fill(size)"},
    {"fill_until", (PyCFunction)Reader_fill_until, METH_VARARGS,
        "fill_until(size, end)"
    },
    {"expose", (PyCFunction)Reader_expose, METH_NOARGS, "expose()"},
    {"peek", (PyCFunction)Reader_peek, METH_VARARGS, "peek(size)"},
    {"drain", (PyCFunction)Reader_drain, METH_VARARGS, "drain(size)"},
    {"search", (PyCFunction)Reader_search, METH_VARARGS | METH_KEYWORDS,
        "search(size, end, include_end=False, always_return=False)"
    },
    {"readline", (PyCFunction)Reader_readline, METH_VARARGS, "readline(size)"},
    {"read", (PyCFunction)Reader_read, METH_VARARGS, "read(size)"},

    {NULL}
};


static PyTypeObject ReaderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "degu._base.Reader",          /* tp_name */
    sizeof(Reader),               /* tp_basicsize */
    0,                            /* tp_itemsize */
    (destructor)Reader_dealloc,   /* tp_dealloc */
    0,                            /* tp_print */
    0,                            /* tp_getattr */
    0,                            /* tp_setattr */
    0,                            /* tp_reserved */
    0,                            /* tp_repr */
    0,                            /* tp_as_number */
    0,                            /* tp_as_sequence */
    0,                            /* tp_as_mapping */
    0,                            /* tp_hash  */
    0,                            /* tp_call */
    0,                            /* tp_str */
    0,                            /* tp_getattro */
    0,                            /* tp_setattro */
    0,                            /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,           /* tp_flags */
    "Reader(sock, bodies)",       /* tp_doc */
    0,                            /* tp_traverse */
    0,                            /* tp_clear */
    0,                            /* tp_richcompare */
    0,                            /* tp_weaklistoffset */
    0,                            /* tp_iter */
    0,                            /* tp_iternext */
    Reader_methods,               /* tp_methods */
    0,                            /* tp_members */
    0,                            /* tp_getset */
    0,                            /* tp_base */
    0,                            /* tp_dict */
    0,                            /* tp_descr_get */
    0,                            /* tp_descr_set */
    0,                            /* tp_dictoffset */
    (initproc)Reader_init,        /* tp_init */
    0,                            /* tp_alloc */
    0,                            /* tp_new */
};



/* module init */
static struct PyMethodDef degu_functions[] = {
    {"parse_method", degu_parse_method, METH_VARARGS, "parse_method(method)"},
    {"parse_uri", parse_uri, METH_VARARGS, "parse_uri(uri)"},

    {"parse_header_name", parse_header_name, METH_VARARGS,
        "parse_header_name(buf)"
    },
    {"parse_content_length", parse_content_length, METH_VARARGS,
        "parse_content_length(value)"
    },
    {"parse_response_line", parse_response_line, METH_VARARGS,
        "parse_response_line(line)"},
    {"parse_request_line", parse_request_line, METH_VARARGS,
        "parse_request_line(line)"},
    {"parse_request", parse_request, METH_VARARGS, "parse_request(preamble)"},
    {"parse_response", parse_response, METH_VARARGS, "parse_response(preamble)"},

    {"format_headers", format_headers, METH_VARARGS, "format_headers(headers)"},
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

    ReaderType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ReaderType) < 0)
        return NULL;

    module = PyModule_Create(&degu);
    if (module == NULL) {
        return NULL;
    }

    Py_INCREF(&ReaderType);
    PyModule_AddObject(module, "Reader", (PyObject *)&ReaderType);

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
    _ADD_MODULE_STRING(str_GET,    "GET")
    _ADD_MODULE_STRING(str_PUT,    "PUT")
    _ADD_MODULE_STRING(str_POST,   "POST")
    _ADD_MODULE_STRING(str_HEAD,   "HEAD")
    _ADD_MODULE_STRING(str_DELETE, "DELETE")
    _ADD_MODULE_STRING(str_OK,     "OK")

    /* Init EmptyPreambleError exception */
    _SET(degu_EmptyPreambleError,
        PyErr_NewException("degu._base.EmptyPreambleError", PyExc_ConnectionError, NULL)
    )
    Py_INCREF(degu_EmptyPreambleError);
    PyModule_AddObject(module, "EmptyPreambleError", degu_EmptyPreambleError);

    /* Init global Python `int` and `str` objects we need for performance */
    _SET(str_recv_into, PyUnicode_InternFromString("recv_into"))
    _SET(str_Body, PyUnicode_InternFromString("Body"))
    _SET(str_ChunkedBody, PyUnicode_InternFromString("ChunkedBody"))
    _SET(str_content_length, PyUnicode_InternFromString("content-length"))
    _SET(str_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _SET(str_chunked, PyUnicode_InternFromString("chunked"))
    _SET(str_crlf, PyUnicode_InternFromString("\r\n"))

    _SET(str_empty, PyUnicode_InternFromString(""))
    _SET(bytes_empty, PyBytes_FromStringAndSize(NULL, 0))

    _SET(str_method, PyUnicode_InternFromString("method"))
    _SET(str_uri, PyUnicode_InternFromString("uri"))
    _SET(str_script, PyUnicode_InternFromString("script"))
    _SET(str_path, PyUnicode_InternFromString("path"))
    _SET(str_query, PyUnicode_InternFromString("query"))
    _SET(str_headers, PyUnicode_InternFromString("headers"))
    _SET(str_body, PyUnicode_InternFromString("body"))

    return module;

error:
    return NULL;
}
