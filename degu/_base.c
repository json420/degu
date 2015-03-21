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
#include "structmember.h"
#include <stdbool.h>
#include <sys/socket.h>

#define _MAX_LINE_SIZE 4096
#define MIN_PREAMBLE 4096
#define MAX_PREAMBLE 65536
#define DEFAULT_PREAMBLE 32768
#define MAX_KEY 32
#define MAX_CL_LEN 16
#define MAX_IO_SIZE 16777216
#define MAX_LENGTH 9999999999999999ull

/* `degu.base.EmptyPreambleError` */
static PyObject *degu_EmptyPreambleError = NULL;

static PyObject *str_shutdown = NULL;         //  'shutdown'
static PyObject *str_recv_into = NULL;        //  'recv_into'
static PyObject *str_send = NULL;             //  'send'
static PyObject *str_write_to = NULL;         //  'write_to'
static PyObject *str_Body = NULL;             //  'Body'
static PyObject *str_BodyIter = NULL;         //  'BodyIter'
static PyObject *str_ChunkedBody = NULL;      //  'ChunkedBody'
static PyObject *str_ChunkedBodyIter = NULL;  //  'ChunkedBodyIter'

static PyObject *str_content_length = NULL;     //  'content_length'
static PyObject *key_content_length = NULL;     //  'content-length'
static PyObject *key_range   = NULL;            //  'range'
static PyObject *key_transfer_encoding = NULL;  //  'transfer-encoding'
static PyObject *str_chunked = NULL;            //  'chunked'
static PyObject *str_crlf = NULL;               //  '\r\n'
static PyObject *key_content_type = NULL;       //  'content-type'
static PyObject *val_application_json = NULL; // 'application/json'
static PyObject *str_GET    = NULL;  // 'GET'
static PyObject *str_PUT    = NULL;  // 'PUT'
static PyObject *str_POST   = NULL;  // 'POST'
static PyObject *str_HEAD   = NULL;  // 'HEAD'
static PyObject *str_DELETE = NULL;  // 'DELETE'
static PyObject *str_OK     = NULL;  // 'OK'
static PyObject *str_empty = NULL;    //  ''

static PyObject *int_SHUT_RDWR = NULL;  // socket.SHUT_RDWR (2)



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

static const uint8_t _NUM[256] = {
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
      0,  1,  2,  3,  4,  5,  6,  7, //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
      8,  9,255,255,255,255,255,255, //  '8'  '9'
    255, 26, 27, 28, 29, 30, 31,255, //       'A'  'B'  'C'  'D'  'E'  'F'
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255, 26, 27, 28, 29, 30, 31,255, //       'a'  'b'  'c'  'd'  'e'  'f'
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
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,
};

/*
 * DIGIT  1 00000001  b'0123456789'
 * ALPHA  2 00000010  b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
 * PATH   4 00000100  b'+-.:_~'
 * QUERY  8 00001000  b'%&='
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
     64, 64, 64,  4, 64,  4,  4, 16, //  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
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



/*******************************************************************************
 * Internal API: Macros:
 *     _SET()
 *     _SET_AND_INC()
 */
#define _SET(pyobj, source) \
    if (pyobj != NULL) { \
        Py_FatalError("_SET(): pyobj != NULL prior to assignment"); \
        goto error; \
    } \
    pyobj = (source); \
    if (pyobj == NULL) { \
        goto error; \
    }

#define _SET_AND_INC(pyobj, source) \
    _SET(pyobj, source) \
    Py_INCREF(pyobj);


/*******************************************************************************
 * Internal API: Misc:
 *     _min()
 *     _calloc_buf()
 *     _get_callable()
 */
static inline size_t
_min(const size_t a, const size_t b)
{
    if (a < b) {
        return a;
    }
    return b;
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

static bool
_check_headers(PyObject *headers)
{
    if (!PyDict_CheckExact(headers)) {
        PyErr_Format(PyExc_TypeError,
            "headers: need a <class 'dict'>; got a %R: %R",
            Py_TYPE(headers), headers
        );
        return false;
    }
    return true;
}

static PyObject *
_getcallable(const char *objname, PyObject *obj, PyObject *name)
{
    PyObject *attr = PyObject_GetAttr(obj, name);
    if (attr == NULL) {
        return NULL;
    }
    if (!PyCallable_Check(attr)) {
        Py_CLEAR(attr);
        PyErr_Format(PyExc_TypeError, "%s.%S() is not callable", objname, name);
    }
    return attr;
}



/*******************************************************************************
 * Internal API: _Src:
 *     _isempty()
 *     _slice()
 *     _equal()
 *     _search()
 *     _tostr()
 *     _tobytes()
 *     _value_error()
 *     _value_error2()
 *     _decode()
 */

/* _Src (source): a read-only buffer.
 *
 * None of these modifications should be possible:
 *
 *     src.buf++;         // Can't move the base pointer
 *     src.len++;         // Can't change the length
 *     src.buf[0] = 'D';  // Can't modify the buffer content
 */
typedef const struct {
    const uint8_t *buf;
    const size_t len;
} _Src;

/* _Dst (destination): a writable buffer.
 *
 * You can modify the buffer content:
 *
 *     dst.buf[0] = 'D';
 *
 * But you still can't modify the base pointer or length:
 *
 *     dst.buf++;         // Can't move the base pointer
 *     dst.len++;         // Can't change the length

 */
typedef const struct {
    uint8_t *buf;
    const size_t len;
} _Dst;


static _Src NULL_Src = {NULL, 0}; 
static _Dst NULL_Dst = {NULL, 0}; 

#define _DEGU_BUF_CONSTANT(name, text) \
    static _Src name = {(uint8_t *)text, sizeof(text) - 1}; 

_DEGU_BUF_CONSTANT(LF, "\n")
_DEGU_BUF_CONSTANT(CRLF, "\r\n")
_DEGU_BUF_CONSTANT(CRLFCRLF, "\r\n\r\n")
_DEGU_BUF_CONSTANT(SPACE, " ")
_DEGU_BUF_CONSTANT(SLASH, "/")
_DEGU_BUF_CONSTANT(SPACE_SLASH, " /")
_DEGU_BUF_CONSTANT(QMARK, "?")
_DEGU_BUF_CONSTANT(SEP, ": ")
_DEGU_BUF_CONSTANT(REQUEST_PROTOCOL, " HTTP/1.1")
_DEGU_BUF_CONSTANT(RESPONSE_PROTOCOL, "HTTP/1.1 ")
_DEGU_BUF_CONSTANT(GET, "GET")
_DEGU_BUF_CONSTANT(PUT, "PUT")
_DEGU_BUF_CONSTANT(POST, "POST")
_DEGU_BUF_CONSTANT(HEAD, "HEAD")
_DEGU_BUF_CONSTANT(DELETE, "DELETE")
_DEGU_BUF_CONSTANT(OK, "OK")
_DEGU_BUF_CONSTANT(CONTENT_LENGTH, "content-length")
_DEGU_BUF_CONSTANT(TRANSFER_ENCODING, "transfer-encoding")
_DEGU_BUF_CONSTANT(CHUNKED, "chunked")
_DEGU_BUF_CONSTANT(RANGE, "range")
_DEGU_BUF_CONSTANT(CONTENT_TYPE, "content-type")

_DEGU_BUF_CONSTANT(APPLICATION_JSON, "application/json")
_DEGU_BUF_CONSTANT(BYTES_EQ, "bytes=")
_DEGU_BUF_CONSTANT(MINUS, "-")

static inline bool
_isempty(_Src src)
{
    if (src.buf == NULL || src.len == 0) {
        return true;
    }
    return false;
}

static _Src
_slice(_Src src, const size_t start, const size_t stop)
{
    if (_isempty(src) || start > stop || stop > src.len) {
        Py_FatalError("_slice(): bad internal call");
    }
    return (_Src){src.buf + start, stop - start};
}

static inline bool
_equal(_Src a, _Src b) {
    if (a.len == b.len && memcmp(a.buf, b.buf, a.len) == 0) {
        return true;
    }
    return false;
}

static inline ssize_t
_find(_Src haystack, _Src needle)
{
    uint8_t *ptr = memmem(haystack.buf, haystack.len, needle.buf, needle.len);
    if (ptr == NULL) {
        return -1;
    }
    return ptr - haystack.buf;
}

static inline size_t
_search(_Src haystack, _Src needle)
{
    uint8_t *ptr = memmem(haystack.buf, haystack.len, needle.buf, needle.len);
    if (ptr == NULL) {
        return haystack.len;
    }
    return (size_t)(ptr - haystack.buf);
}

static PyObject *
_tostr(_Src src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyUnicode_FromKindAndData(
        PyUnicode_1BYTE_KIND, src.buf, (ssize_t)src.len
    );
}

static PyObject *
_tobytes(_Src src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)src.buf, (ssize_t)src.len);
}

static _Src
_frombytes(PyObject *bytes)
{
    if (bytes == NULL || !PyBytes_CheckExact(bytes)) {
        Py_FatalError("_frombytes(): bad internal call");
    }
    return (_Src){
        (uint8_t *)PyBytes_AS_STRING(bytes),
        (size_t)PyBytes_GET_SIZE(bytes)
    };
}

static void
_value_error(const char *format, _Src src)
{
    PyObject *tmp = _tobytes(src);
    if (tmp != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp);
    }
    Py_CLEAR(tmp);
}

static void
_value_error2(const char *format, _Src src1, _Src src2)
{
    PyObject *tmp1 = _tobytes(src1);
    PyObject *tmp2 = _tobytes(src2);
    if (tmp1 != NULL && tmp2 != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp1, tmp2);
    }
    Py_CLEAR(tmp1);
    Py_CLEAR(tmp2);
}

static PyObject *
_decode(_Src src, const uint8_t mask, const char *format)
{
    PyObject *dst = NULL;
    uint8_t *dst_buf = NULL;
    uint8_t c, bits;
    size_t i;

    if (mask == 0 || (mask & 1) != 0) {
        Py_FatalError("_decode: bad mask");
    }
    if (src.len < 1) {
        _SET_AND_INC(dst, str_empty);
        goto done;
    }
    _SET(dst, PyUnicode_New((ssize_t)src.len, 127))
    dst_buf = PyUnicode_1BYTE_DATA(dst);
    for (bits = i = 0; i < src.len; i++) {
        c = dst_buf[i] = src.buf[i];
        bits |= _FLAGS[c];
    }
    if (bits == 0) {
        Py_FatalError("internal error in `_decode()`");
    }
    if ((bits & mask) != 0) {
        _value_error(format, src);
        goto error;
    }
    goto done;

error:
    Py_CLEAR(dst);

done:
    return dst;
}

static inline bool
_dst_isempty(_Dst dst)
{
    if (dst.buf == NULL || dst.len == 0) {
        return true;
    }
    return false;
}

static _Dst
_dst_slice(_Dst dst, const size_t start, const size_t stop)
{
    if (_dst_isempty(dst) || start > stop || stop > dst.len) {
        Py_FatalError("_dst_slice(): bad internal call");
    }
    return (_Dst){dst.buf + start, stop - start};
}

static void
_move(_Dst dst, _Src src)
{
    if (_dst_isempty(dst) || _isempty(src) || dst.len < src.len) {
        Py_FatalError("_move(): bad internal call");
    }
    memmove(dst.buf, src.buf, src.len);
}

static void
_copy(_Dst dst, _Src src)
{
    if (_dst_isempty(dst) || _isempty(src) || dst.len < src.len) {
        Py_FatalError("_copy(): bad internal call");
    }
    memcpy(dst.buf, src.buf, src.len);
}

static _Dst
_calloc_dst(const size_t len)
{
    uint8_t *buf = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL_Dst;
    }
    return (_Dst){buf, len};
}


/*******************************************************************************
 * Internal API: DeguHeaders/DeguRequest/DeguResponse:
 *     _clear_degu_headers()
 *     _clear_degu_request()
 *     _clear_degu_response()   
 */
#define DEGU_HEADERS_HEAD \
    PyObject *headers; \
    PyObject *content_length; \
    PyObject *range; \
    uint8_t flags;

typedef struct {
    DEGU_HEADERS_HEAD
} DeguHeaders;

typedef struct {
    DEGU_HEADERS_HEAD
    PyObject *method;
    PyObject *uri;
    PyObject *script;
    PyObject *path;
    PyObject *query;
    PyObject *body;
} DeguRequest;

typedef struct {
    DEGU_HEADERS_HEAD
    PyObject *status;
    PyObject *reason;
    PyObject *body;
} DeguResponse;

#define NEW_DEGU_HEADERS \
     ((DeguHeaders){NULL, NULL, NULL, 0})

#define NEW_DEGU_REQUEST \
     ((DeguRequest){NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL})

#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, NULL, 0, NULL, NULL, NULL})

static void
_clear_degu_headers(DeguHeaders *dh)
{
    Py_CLEAR(dh->headers);
    Py_CLEAR(dh->content_length);
    Py_CLEAR(dh->range);
}

static void
_clear_degu_request(DeguRequest *dr)
{
    _clear_degu_headers((DeguHeaders *)dr);
    Py_CLEAR(dr->method);
    Py_CLEAR(dr->uri);
    Py_CLEAR(dr->script);
    Py_CLEAR(dr->path);
    Py_CLEAR(dr->query);
    Py_CLEAR(dr->body);
}

static void
_clear_degu_response(DeguResponse *dr)
{
    _clear_degu_headers((DeguHeaders *)dr);
    Py_CLEAR(dr->status);
    Py_CLEAR(dr->reason);
    Py_CLEAR(dr->body);
}


/*******************************************************************************
 * Range object
 */

typedef struct {
    PyObject_HEAD
    PyObject *start;
    PyObject *stop;
    uint64_t _start;
    uint64_t _stop;
} Range;

static void
Range_dealloc(Range *self)
{
    Py_CLEAR(self->start);
    Py_CLEAR(self->stop);
    Py_TYPE(self)->tp_free((PyObject*)self);  // Oops, make sure to do this!
}

static int64_t
_validate_length(const char *name, PyObject *obj)
{
    if (!PyLong_CheckExact(obj)) {
        PyErr_Format(PyExc_TypeError,
            "%s: need a <class 'int'>; got a %R: %R", name, Py_TYPE(obj), obj
        );
        return -1; 
    }
    const uint64_t length = PyLong_AsUnsignedLongLong(obj);
    if (PyErr_Occurred()) {
        return -1;
    }
    if (length > MAX_LENGTH) {
        PyErr_Format(PyExc_ValueError,
            "need 0 <= %s <= %llu; got %llu", name, MAX_LENGTH, length
        );
        return -1;
    }
    return (int64_t)length;
}

static int
Range_init(Range *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"start", "stop", NULL};
    PyObject *start = NULL;
    PyObject *stop = NULL;
    int64_t _start, _stop;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO:Range", keys, &start, &stop)) {
        return -1;
    }
    _start = _validate_length("start", start);
    if (_start < 0) {
        return -1;
    }
    _stop = _validate_length("stop", stop);
    if (_stop < 0) {
        return -1;
    }
    if (_start >= _stop) {
        PyErr_Format(PyExc_ValueError,
            "need start < stop; got %lld >= %lld", _start, _stop
        );
        return -1;
    }
    self->_start = (uint64_t)_start;
    self->_stop = (uint64_t)_stop;
    _SET_AND_INC(self->start, start)
    _SET_AND_INC(self->stop,  stop)
    return 0;

error:
    return -1;
}

static PyObject *
Range_repr(Range *self)
{
    return PyUnicode_FromFormat("Range(%R, %R)", self->start, self->stop);
}

static PyObject *
Range_str(Range *self)
{
    return PyUnicode_FromFormat("bytes=%llu-%llu",
        self->_start, self->_stop - 1
    );
}

static PyMemberDef Range_members[] = {
    {"start", T_OBJECT_EX, offsetof(Range, start), 0, "start"},
    {"stop",  T_OBJECT_EX, offsetof(Range, stop),  0, "stop"},
    {NULL}
};

static PyTypeObject RangeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "degu._base.Range",           /* tp_name */
    sizeof(Range),                /* tp_basicsize */
    0,                            /* tp_itemsize */
    (destructor)Range_dealloc,    /* tp_dealloc */
    0,                            /* tp_print */
    0,                            /* tp_getattr */
    0,                            /* tp_setattr */
    0,                            /* tp_reserved */
    (reprfunc)Range_repr,         /* tp_repr */
    0,                            /* tp_as_number */
    0,                            /* tp_as_sequence */
    0,                            /* tp_as_mapping */
    0,                            /* tp_hash  */
    0,                            /* tp_call */
    (reprfunc)Range_str,          /* tp_str */
    0,                            /* tp_getattro */
    0,                            /* tp_setattro */
    0,                            /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,           /* tp_flags */
    "Range(start, stop)",         /* tp_doc */
    0,                            /* tp_traverse */
    0,                            /* tp_clear */
    0,                            /* tp_richcompare */
    0,                            /* tp_weaklistoffset */
    0,                            /* tp_iter */
    0,                            /* tp_iternext */
    0,                            /* tp_methods */
    Range_members,                /* tp_members */
    0,                            /* tp_getset */
    0,                            /* tp_base */
    0,                            /* tp_dict */
    0,                            /* tp_descr_get */
    0,                            /* tp_descr_set */
    0,                            /* tp_dictoffset */
    (initproc)Range_init,         /* tp_init */
};

/*******************************************************************************
 * Internal API: Parsing: Headers:
 *     _parse_key()
 *     _parse_val()
 *     _parse_content_length()
 *     _parse_header_line()
 *     _parse_headers()
 */
static bool
_parse_key(_Src src, _Dst dst)
{
    uint8_t r;
    size_t i;
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return false; 
    }
    if (src.len > dst.len) {
        _value_error("header name too long: %R...", _slice(src, 0, dst.len));
        return false;
    }
    for (r = i = 0; i < src.len; i++) {
        r |= dst.buf[i] = _NAMES[src.buf[i]];
    }
    if (r & 128) {
        if (r != 255) {
            Py_FatalError("_parse_key: r != 255");
        }
        _value_error("bad bytes in header name: %R", src);
        return false;
    }
    return true;
}

static inline PyObject *
_parse_val(_Src src)
{
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header value is empty");
        return NULL; 
    }
    return _decode(src, VALUE_MASK, "bad bytes in header value: %R");
}

static int64_t
_parse_decimal(_Src src)
{
    int64_t accum;
    uint8_t n, err;
    size_t i;

    if (src.len < 1 || src.len > MAX_CL_LEN) {
        return -1;
    }
    accum = err = _NUM[src.buf[0]];
    for (i = 1; i < src.len; i++) {
        n = _NUM[src.buf[i]];
        err |= n;
        accum *= 10;
        accum += n;
    }
    if ((err & 240) != 0) {
        return -2;
    }
    if (src.buf[0] == 48 && src.len != 1) {
        return -3;
    }
    return accum;
}

static void
_set_content_length_error(_Src src, const int64_t value)
{
    if (value == -1) {
        if (src.len < 1) {
            PyErr_SetString(PyExc_ValueError, "content-length is empty");
        }
        else {
            _value_error("content-length too long: %R...",
                _slice(src, 0, MAX_CL_LEN)
            );
        }
    }
    else if (value == -2) {
        _value_error("bad bytes in content-length: %R", src);
    }
    else if (value == -3) {
        _value_error("content-length has leading zero: %R", src);
    }
    else {
        Py_FatalError("_set_content_length_error(): bad internal call");
    }
}

static PyObject *
_parse_content_length(_Src src)
{
    const int64_t value = _parse_decimal(src);
    if (value < 0) {
        _set_content_length_error(src, value);
        return NULL;
    }
    return PyLong_FromLongLong(value);
}

static PyObject *
_parse_range(_Src src)
{
    ssize_t index;
    int64_t start, end;
    PyObject *int_start = NULL;
    PyObject *int_stop = NULL;
    PyObject *ret = NULL;

    if (src.len < 9 || src.len > 39 || !_equal(_slice(src, 0, 6), BYTES_EQ)) {
        goto bad_range;
    }
    _Src inner = _slice(src, 6, src.len);
    index = _find(inner, MINUS);
    if (index < 1) {
        goto bad_range;
    }
    start = _parse_decimal(_slice(inner, 0, (size_t)index));
    end = _parse_decimal(_slice(inner, (size_t)index + 1, inner.len));
    if (start < 0 || end < start) {
        goto bad_range;
    }
    _SET(int_start, PyLong_FromLongLong(start))
    _SET(int_stop, PyLong_FromLongLong(end + 1))
    _SET(ret, PyTuple_Pack(2, int_start, int_stop))
    goto done;

bad_range:
    _value_error("bad range: %R", src);

error:
    Py_CLEAR(ret);

done:
    Py_CLEAR(int_start);
    Py_CLEAR(int_stop);
    return ret;
}

static bool
_parse_header_line(_Src src, _Dst scratch, DeguHeaders *dh)
{
    ssize_t index;
    size_t keystop, valstart;
    bool success = true;
    PyObject *key = NULL;
    PyObject *val = NULL;

    /* Split header line, validate & casefold header name */
    if (src.len < 4) {
        _value_error("header line too short: %R", src);
        goto error;
    }
    index = _find(src, SEP);
    if (index < 0) {
        _value_error("bad header line: %R", src);
        goto error;
    }
    keystop = (size_t)index;
    valstart = keystop + SEP.len;
    _Src rawkey = _slice(src, 0, keystop);
    _Src valsrc = _slice(src, valstart, src.len);
    if (! _parse_key(rawkey, scratch)) {
        goto error;
    }
    _Src keysrc = {scratch.buf, rawkey.len};

    /* Validate header value (with special handling and fast-paths) */
    if (_equal(keysrc, CONTENT_LENGTH)) {
        _SET_AND_INC(key, key_content_length)
        _SET(val, _parse_content_length(valsrc))
        if (dh->content_length == NULL) {
            _SET_AND_INC(dh->content_length, val)
        }
        dh->flags |= 1;
    }
    else if (_equal(keysrc, TRANSFER_ENCODING)) {
        if (! _equal(valsrc, CHUNKED)) {
            _value_error("bad transfer-encoding: %R", valsrc);
            goto error;
        }
        _SET_AND_INC(key, key_transfer_encoding)
        _SET_AND_INC(val, str_chunked)
        dh->flags |= 2;
    }
    else if (_equal(keysrc, RANGE)) {
        _SET_AND_INC(key, key_range)
        _SET(val, _parse_val(valsrc))
        if (dh->range == NULL) {
            _SET(dh->range, _parse_range(valsrc))
        }
        dh->flags |= 4;
    }
    else if (_equal(keysrc, CONTENT_TYPE)) {
        _SET_AND_INC(key, key_content_type)
        if (_equal(valsrc, APPLICATION_JSON)) {
            _SET_AND_INC(val, val_application_json)
        }
        else {
            _SET(val, _parse_val(valsrc))
        }
    }
    else {
        _SET(key, _tostr(keysrc))
        _SET(val, _parse_val(valsrc))
    }

    /* Store in headers dict, make sure it's not a duplicate key */
    if (PyDict_SetDefault(dh->headers, key, val) != val) {
        _value_error("duplicate header: %R", src);
        goto error;
    }
    goto cleanup;

error:
    success = false;

cleanup:
    Py_CLEAR(key);
    Py_CLEAR(val);
    return success;
}

static bool
_parse_headers(_Src src, _Dst scratch, DeguHeaders *dh)
{
    size_t start, stop;

    _SET(dh->headers, PyDict_New())
    start = 0;
    while (start < src.len) {
        stop = start + _search(_slice(src, start, src.len), CRLF);
        if (!_parse_header_line(_slice(src, start, stop), scratch, dh)) {
            goto error;
        }
        start = stop + CRLF.len;
    }
    if ((dh->flags & 3) == 3) {
        PyErr_SetString(PyExc_ValueError, 
            "cannot have both content-length and transfer-encoding headers"
        );
        goto error; 
    }
    if ((dh->flags & 4) && (dh->flags & 3)) {
        PyErr_SetString(PyExc_ValueError, 
            "cannot include range header and content-length/transfer-encoding"
        );
        goto error; 
    }
    if (dh->range == NULL) {
        _SET_AND_INC(dh->range, Py_None)
    }
    return true;

error:
    return false;
}


/*******************************************************************************
 * Internal API: Parsing: Request:
 *     _parse_method()
 *     _parse_path_component()
 *     _parse_path()
 *     _parse_query()
 *     _parse_uri()
 *     _parse_request_line()
 *     _parse_request()
 */
static PyObject *
_parse_method(_Src src)
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
        _value_error("bad HTTP method: %R", src);
    }
    else {
        Py_INCREF(method);
    }
    return method;
}

static inline PyObject *
_parse_path_component(_Src src)
{
    return _decode(src, PATH_MASK, "bad bytes in path component: %R");
}

static PyObject *
_parse_path(_Src src)
{
    PyObject *path = NULL;
    PyObject *component = NULL;
    size_t start, stop;

    if (_isempty(src)) {
        Py_FatalError("_parse_path(): bad internal call");
        goto error;
    }
    if (src.buf[0] != '/') {
        _value_error("path[0:1] != b'/': %R", src);
        goto error;
    }
    _SET(path, PyList_New(0))
    if (src.len == 1) {
        goto cleanup;
    }
    start = 1;
    while (start < src.len) {
        stop = start + _search(_slice(src, start, src.len), SLASH);
        if (start >= stop) {
            _value_error("b'//' in path: %R", src);
            goto error;
        }
        _SET(component,
            _parse_path_component(_slice(src, start, stop))
        )
        if (PyList_Append(path, component) != 0) {
            goto error;
        }
        Py_CLEAR(component);
        start = stop + 1;
    }
    if (_equal(_slice(src, src.len - 1, src.len), SLASH)) {
        if (PyList_Append(path, str_empty) != 0) {
            goto error;
        }
    }
    goto cleanup;

error:
    Py_CLEAR(path);

cleanup:
    Py_CLEAR(component);
    return path;
}

static inline PyObject *
_parse_query(_Src src)
{
    return _decode(src, QUERY_MASK, "bad bytes in query: %R");
}

static bool
_parse_uri(_Src src, DeguRequest *dr)
{
    size_t path_stop, query_start;

    if (src.buf == NULL) {
        Py_FatalError("_parse_uri(): bad internal call");
        goto error;
    }
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "uri is empty");
        goto error;
    }
    path_stop = _search(src, QMARK);
    _SET(dr->uri, _decode(src, URI_MASK, "bad bytes in uri: %R"))
    _SET(dr->script, PyList_New(0))
    _SET(dr->path, _parse_path(_slice(src, 0, path_stop)))
    if (path_stop < src.len) {
        query_start = path_stop + QMARK.len;
        _SET(dr->query, _parse_query(_slice(src, query_start, src.len)))
    }
    else {
        _SET_AND_INC(dr->query, Py_None)
    }
    return true;

error:
    return false;
}

static bool
_parse_request_line(_Src line, DeguRequest *dr)
{
    ssize_t index;
    size_t method_stop, uri_start;

    /* Reject any request line shorter than 14 bytes:
     *     "GET / HTTP/1.1"[0:14]
     *      ^^^^^^^^^^^^^^
     */
    if (line.len < 14) {
        _value_error("request line too short: %R", line);
        goto error;
    }

    /* verify final 9 bytes (protocol):
     *     "GET / HTTP/1.1"[-9:]
     *           ^^^^^^^^^
     */
    _Src protocol = _slice(line, line.len - 9, line.len);
    if (! _equal(protocol, REQUEST_PROTOCOL)) {
        _value_error("bad protocol in request line: %R", protocol);
        goto error;
    }

    /* Now we'll work with line[0:-9]
     *     "GET / HTTP/1.1"[0:-9]
     *      ^^^^^
     */
    _Src src = _slice(line, 0, line.len - protocol.len);

    /* Search for method terminating space, plus start of uri:
     *     "GET /"
     *         ^^
     */
    index = _find(src, SPACE_SLASH);
    if (index < 0) {
        _value_error("bad request line: %R", line);
        goto error;
    }
    method_stop = (size_t)index;
    uri_start = method_stop + 1;
    _Src method_src = _slice(src, 0, method_stop);
    _Src uri_src = _slice(src, uri_start, src.len);

    /* _parse_method(), _parse_uri() handle the rest */
    _SET(dr->method, _parse_method(method_src))
    if (!_parse_uri(uri_src, dr)) {
        goto error;
    }
    return true;

error:
    return false;
}

static bool
_parse_request(_Src src, _Dst scratch, DeguRequest *dr)
{
    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    _Src line_src = _slice(src, 0, stop);
    _Src headers_src = _slice(src, start, src.len);
    if (!_parse_request_line(line_src, dr)) {
        goto error;
    }
    if (!_parse_headers(headers_src, scratch, (DeguHeaders *)dr)) {
        goto error;
    }
    return true;

error:
    return false;
}


/*******************************************************************************
 * Internal API: Parsing: Response:
 *     _parse_status()
 *     _parse_reason()
 *     _parse_response_line()
 *     _parse_response()
 */

static inline uint8_t
_sub48(const uint8_t d)
{
    return (uint8_t)(d - 48);
}

static inline PyObject *
_parse_status(_Src src)
{
    uint8_t d, err;
    unsigned long accum;

    if (src.len != 3) {
        _value_error("bad status length: %R", src);
        return NULL;
    }
    d = src.buf[0];    err =  (d < 49 || d > 53);    accum =  _sub48(d) * 100u;
    d = src.buf[1];    err |= (d < 48 || d > 57);    accum += _sub48(d) *  10u;
    d = src.buf[2];    err |= (d < 48 || d > 57);    accum += _sub48(d);
    if (err || accum < 100 || accum > 599) {
        _value_error("bad status: %R", src);
        return NULL;
    }
    return PyLong_FromUnsignedLong(accum);
}

static inline PyObject *
_parse_reason(_Src src)
{
    if (_equal(src, OK)) {
        Py_XINCREF(str_OK);
        return str_OK;
    }
    return _decode(src, REASON_MASK, "bad reason: %R");
}

static bool
_parse_response_line(_Src src, DeguResponse *dr)
{
    /* Reject any response line shorter than 15 bytes:
     *     "HTTP/1.1 200 OK"[0:15]
     *      ^^^^^^^^^^^^^^^
     */
    if (src.len < 15) {
        _value_error("response line too short: %R", src);
        goto error;
    }

    /* protocol, spaces:
     *     "HTTP/1.1 200 OK"[0:9]
     *      ^^^^^^^^^
     *
     *     "HTTP/1.1 200 OK"[12:13]
     *                  ^
     */
    _Src pcol = _slice(src, 0, 9);
    _Src sp = _slice(src, 12, 13);
    if (! (_equal(pcol, RESPONSE_PROTOCOL) && _equal(sp, SPACE))) {
        _value_error("bad response line: %R", src);
        goto error;
    }

    /* status:
     *     "HTTP/1.1 200 OK"[9:12]
     *               ^^^
     */
    _SET(dr->status, _parse_status(_slice(src, 9, 12)))

    /* reason:
     *     "HTTP/1.1 200 OK"[13:]
     *                   ^^
     */
    _SET(dr->reason, _parse_reason(_slice(src, 13, src.len)))
    return true;

error:
    return false;
}

static bool
_parse_response(_Src src, _Dst scratch, DeguResponse *dr)
{
    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    _Src line_src = _slice(src, 0, stop);
    _Src headers_src = _slice(src, start, src.len);
    if (!_parse_response_line(line_src, dr)) {
        goto error;
    }
    if (!_parse_headers(headers_src, scratch, (DeguHeaders *)dr)) {
        goto error;
    }
    return true;

error:
    return false;
}


/*******************************************************************************
 * Internal API: Formatting:
 *     _set_default_header()
 *     _validate_key()
 *     _format_headers()
 */

static bool
_set_default_header(PyObject *headers, PyObject *key, PyObject *val)
{
    if (!_check_headers(headers)) {
        return false;
    }
    PyObject *cur = PyDict_SetDefault(headers, key, val);
    if (cur == NULL) {
        return false;
    }
    if (val == cur) {
        return true;
    }
    int cmp = PyObject_RichCompareBool(val, cur, Py_EQ);
    if (cmp == 1) {
        return true;
    }
    if (cmp == 0) {
        PyErr_Format(PyExc_ValueError, "%R mismatch: %R != %R", key, val, cur);
    }
    return false;
}

static bool
_validate_key(PyObject *key)
{
    size_t i;
    uint8_t c;

    if (!PyUnicode_CheckExact(key)) {
        PyErr_Format(PyExc_TypeError,
            "key: need a <class 'str'>; got a %R: %R", Py_TYPE(key), key
        );
        return false;
    }
    if (PyUnicode_READY(key) != 0) {
        return false;
    }
    if (PyUnicode_GET_LENGTH(key) < 1) {
        PyErr_SetString(PyExc_ValueError, "key is empty");
        return false;
    }
    if (PyUnicode_MAX_CHAR_VALUE(key) != 127) {
        goto bad_key;
    }
    const uint8_t *key_buf = PyUnicode_1BYTE_DATA(key);
    const size_t key_len = (size_t)PyUnicode_GET_LENGTH(key);
    for (i = 0; i < key_len; i++) {
        c = key_buf[i];
        if (! (islower(c) || isdigit(c) || c == '-')) {
            goto bad_key;
        }
    }
    return true;

bad_key:
    PyErr_Format(PyExc_ValueError, "bad key: %R", key);
    return false;
}


static PyObject *
_format_headers(PyObject *headers)
{
    ssize_t pos = 0;
    ssize_t i = 0;
    PyObject *key = NULL;
    PyObject *val = NULL;
    PyObject *lines = NULL;
    PyObject *ret = NULL;

    if (!_check_headers(headers)) {
        goto error;
    }
    const ssize_t count = PyDict_Size(headers);
    if (count < 1) {
        if (count < 0) {
            Py_FatalError("_format_headers(): count < 0");
        }
        _SET_AND_INC(ret, str_empty);
    }
    else if (count == 1) {
        while (PyDict_Next(headers, &pos, &key, &val)) {
            if (! _validate_key(key)) {
                goto error;
            }
            _SET(ret, PyUnicode_FromFormat("%S: %S\r\n", key, val))
        }
    }
    else {
        _SET(lines, PyList_New(count))
        while (PyDict_Next(headers, &pos, &key, &val)) {
            if (! _validate_key(key)) {
                goto error;
            }
            PyList_SET_ITEM(lines, i,
                PyUnicode_FromFormat("%S: %S\r\n", key, val)
            );
            i++;
            key = val = NULL;
        }
        if (PyList_Sort(lines) != 0) {
            goto error;
        }
        _SET(ret, PyUnicode_Join(str_empty, lines))
    }
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(lines);
    return  ret;
}


static PyObject *
_format_request(_Src method_src, PyObject *uri, PyObject *headers)
{
    PyObject *method = NULL;
    PyObject *hstr = NULL;  /* str containing header lines */
    PyObject *str = NULL;  /* str version of request preamble */
    PyObject *ret = NULL;  /* bytes version of request preamble */

    _SET(method, _parse_method(method_src))
    _SET(hstr, _format_headers(headers))
    _SET(str,
        PyUnicode_FromFormat("%S %S HTTP/1.1\r\n%S\r\n", method, uri, hstr)
    )
    _SET(ret, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(method);
    Py_CLEAR(hstr);
    Py_CLEAR(str);
    return  ret;
}


static PyObject *
_format_response(PyObject *status, PyObject *reason, PyObject *headers)
{
    PyObject *hstr = NULL;  /* str containing header lines */
    PyObject *str = NULL;  /* str version of response preamble */
    PyObject *ret = NULL;  /* bytes version of response preamble */

    _SET(hstr, _format_headers(headers))
    _SET(str,
        PyUnicode_FromFormat("HTTP/1.1 %S %S\r\n%S\r\n", status, reason, hstr)
    )
    _SET(ret, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(hstr);
    Py_CLEAR(str);
    return  ret;
}



/*******************************************************************************
 * Internal API: namedtuple:
 *     _Bodies()
 *     _Request()
 *     _Response()
 *     _init_namedtuple()
 *     _init_all_namedtuples()
 */

/* Bodies */
static PyTypeObject BodiesType;
static PyStructSequence_Field BodiesFields[] = {
    {"Body", NULL},
    {"BodyIter", NULL},
    {"ChunkedBody", NULL},
    {"ChunkedBodyIter", NULL},
    {NULL},
};
static PyStructSequence_Desc BodiesDesc = {
    "Bodies",
    NULL,
    BodiesFields,  
    4
};
static PyObject *
_Bodies(PyObject *Body,
        PyObject *BodyIter,
        PyObject *ChunkedBody,
        PyObject *ChunkedBodyIter)
{
    PyObject *bodies = PyStructSequence_New(&BodiesType);
    if (bodies == NULL) {
        return NULL;
    }
    PyStructSequence_SET_ITEM(bodies, 0, Body);
    PyStructSequence_SET_ITEM(bodies, 1, BodyIter);
    PyStructSequence_SET_ITEM(bodies, 2, ChunkedBody);
    PyStructSequence_SET_ITEM(bodies, 3, ChunkedBodyIter);
    return bodies;
}

/* Request */
static PyTypeObject RequestType;
static PyStructSequence_Field RequestFields[] = {
    {"method", NULL},
    {"uri", NULL},
    {"script", NULL},
    {"path", NULL},
    {"query", NULL},
    {"headers", NULL},
    {"range", NULL},
    {"body", NULL},
    {NULL},
};
static PyStructSequence_Desc RequestDesc = {
    "Request",
    NULL,
    RequestFields,  
    8
};
static PyObject *
_Request(PyObject *method,
         PyObject *uri,
         PyObject *script,
         PyObject *path,
         PyObject *query,
         PyObject *headers,
         PyObject *range,
         PyObject *body)
{
    PyObject *request = PyStructSequence_New(&RequestType);
    if (request == NULL) {
        return NULL;
    }
    Py_INCREF(method);
    Py_INCREF(uri);
    Py_INCREF(script);
    Py_INCREF(path);
    Py_INCREF(query);
    Py_INCREF(headers);
    Py_INCREF(range);
    Py_INCREF(body);
    PyStructSequence_SET_ITEM(request, 0, method);
    PyStructSequence_SET_ITEM(request, 1, uri);
    PyStructSequence_SET_ITEM(request, 2, script);
    PyStructSequence_SET_ITEM(request, 3, path);
    PyStructSequence_SET_ITEM(request, 4, query);
    PyStructSequence_SET_ITEM(request, 5, headers);
    PyStructSequence_SET_ITEM(request, 6, range);
    PyStructSequence_SET_ITEM(request, 7, body);
    return request;
}

/* Response */
static PyTypeObject ResponseType;
static PyStructSequence_Field ResponseFields[] = {
    {"status", NULL},
    {"reason", NULL},
    {"headers", NULL},
    {"body", NULL},
    {NULL},
};
static PyStructSequence_Desc ResponseDesc = {
    "Response",
    NULL,
    ResponseFields,  
    4
};
static PyObject *
_Response(PyObject *status, PyObject *reason, PyObject *headers, PyObject *body)
{
    PyObject *response = PyStructSequence_New(&ResponseType);
    if (response == NULL) {
        return NULL;
    }
    Py_INCREF(status);
    Py_INCREF(reason);
    Py_INCREF(headers);
    Py_INCREF(body);
    PyStructSequence_SET_ITEM(response, 0, status);
    PyStructSequence_SET_ITEM(response, 1, reason);
    PyStructSequence_SET_ITEM(response, 2, headers);
    PyStructSequence_SET_ITEM(response, 3, body);
    return response;
}

/* _init_namedtuple(), _init_all_namedtuples() */
static bool
_init_namedtuple(PyObject *module, const char *name,
                 PyTypeObject *type, PyStructSequence_Desc *desc)
{
    if (PyStructSequence_InitType2(type, desc) != 0) {
        return false;
    }
    Py_INCREF(type);
    if (PyModule_AddObject(module, name, (PyObject *)type) != 0) {
        return false;
    }
    return true;
}

static bool
_init_all_namedtuples(PyObject *module)
{
    if (!_init_namedtuple(module, "BodiesType", &BodiesType, &BodiesDesc)) {
        return false;
    }
    if (!_init_namedtuple(module, "RequestType", &RequestType, &RequestDesc)) {
        return false;
    }
    if (!_init_namedtuple(module, "ResponseType", &ResponseType, &ResponseDesc)) {
        return false;
    }
    return true;
}


/*******************************************************************************
 * Public API: Parsing: Headers:
 *     parse_header_name()
 *     parse_content_length()
 *     parse_header_line()
 *     parse_headers()
 */
static PyObject *
parse_header_name(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "y#:parse_header_name", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return NULL;
    }
    if (src.len > MAX_KEY) {
        _value_error("header name too long: %R...",  _slice(src, 0, MAX_KEY));
        return NULL;
    }
    _SET(ret, PyUnicode_New((ssize_t)src.len, 127))
    _Dst dst = {PyUnicode_1BYTE_DATA(ret), src.len};
    if (!_parse_key(src, dst)) {
        goto error;
    }
    goto done;

error:
    Py_CLEAR(ret);

done:
    return ret;
}

static PyObject *
parse_content_length(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_content_length", &buf, &len)) {
        return NULL;
    }
    return _parse_content_length((_Src){buf, len});
}

static PyObject *
parse_range(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_range", &buf, &len)) {
        return NULL;
    }
    return _parse_range((_Src){buf, len});
}

static PyObject *
parse_headers(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    DeguHeaders dh = NEW_DEGU_HEADERS;

    if (!PyArg_ParseTuple(args, "y#:parse_headers", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    _Dst dst = _calloc_dst(MAX_KEY);
    if (dst.buf == NULL) {
        return NULL;
    }
    if (!_parse_headers(src, dst, &dh)) {
        goto error;
    }
    goto cleanup;

error:
    Py_CLEAR(dh.headers);

cleanup:
    if (dst.buf != NULL) {
        free(dst.buf);
    }
    Py_CLEAR(dh.content_length);
    Py_CLEAR(dh.range);
    return dh.headers;
}


/*******************************************************************************
 * Public API: Parsing: Requests:
 *     parse_method()
 *     parse_uri()
 *     parse_request_line()
 *     parse_request()
 */
static PyObject *
parse_method(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    if (!PyArg_ParseTuple(args, "s#:parse_method", &buf, &len)) {
        return NULL;
    }
    return _parse_method((_Src){buf, len});
}

static PyObject *
parse_uri(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (!PyArg_ParseTuple(args, "y#:parse_uri", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    if (!_parse_uri(src, &dr)) {
        goto error;
    }
    _SET(ret,
        PyTuple_Pack(4, dr.uri, dr.script, dr.path, dr.query)
    )
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_request(&dr);
    return ret;
}

static PyObject *
parse_request_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (!PyArg_ParseTuple(args, "y#:parse_request_line", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    if (!_parse_request_line(src, &dr)) {
        goto error;
    }
    _SET(ret,
        PyTuple_Pack(5, dr.method, dr.uri, dr.script, dr.path, dr.query)
    )
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_request(&dr);
    return ret;
}

static PyObject *
parse_request(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;

    if (!PyArg_ParseTuple(args, "y#:parse_request", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    _Dst scratch = _calloc_dst(MAX_KEY);
    if (scratch.buf == NULL) {
        return NULL;
    }
    if (!_parse_request(src, scratch, &dr)) {
        goto error;
    }
    _SET(ret,
        PyTuple_Pack(6, dr.method, dr.uri, dr.script, dr.path, dr.query, dr.headers)
    )
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    free(scratch.buf);
    return ret;
}



/*******************************************************************************
 * Public API: Parsing: Responses:
 *     parse_response_line()
 *     parse_response()
 */
static PyObject *
parse_response_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;
    if (!PyArg_ParseTuple(args, "y#:parse_response_line", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    if (!_parse_response_line(src, &dr)) {
        goto error;
    }
    if (dr.status == NULL || dr.reason == NULL) {
        Py_FatalError("parse_response_line");
        goto error;
    }
    _SET(ret, PyTuple_Pack(2, dr.status, dr.reason))
    goto done;

error:
    Py_CLEAR(ret);

done:
    _clear_degu_response(&dr);
    return ret;
}

static PyObject *
parse_response(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;

    if (!PyArg_ParseTuple(args, "y#:parse_response", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    _Dst scratch = _calloc_dst(MAX_KEY);
    if (scratch.buf == NULL) {
        return NULL;
    }
    if (!_parse_response(src, scratch, &dr)) {
        goto error;
    }
    _SET(ret, PyTuple_Pack(3, dr.status, dr.reason, dr.headers))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_response(&dr);
    free(scratch.buf);
    return ret;
}


/*******************************************************************************
 * Public API: Formatting:
 *     format_headers()
 *     format_request()
 *     format_response()
 */
static PyObject *
set_default_header(PyObject *self, PyObject *args)
{
    PyObject *headers = NULL;
    PyObject *key = NULL;
    PyObject *val = NULL;
    if (!PyArg_ParseTuple(args, "OUO:set_default_header",
            &headers, &key, &val)) {
        return NULL;
    }
    if (!_set_default_header(headers, key, val)) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
format_headers(PyObject *self, PyObject *args)
{
    PyObject *headers = NULL;
    if (!PyArg_ParseTuple(args, "O:format_headers", &headers)) {
        return NULL;
    }
    return _format_headers(headers);
}

static PyObject *
format_request(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *uri = NULL;
    PyObject *headers = NULL;

    if (!PyArg_ParseTuple(args, "s#UO:format_request", &buf, &len, &uri, &headers)) {
        return NULL;
    }
    _Src method_src = {buf, len};
    return _format_request(method_src, uri, headers);
}

static PyObject *
format_response(PyObject *self, PyObject *args)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;
    PyObject *headers = NULL;

    if (!PyArg_ParseTuple(args, "OUO:format_response", &status, &reason, &headers)) {
        return NULL;
    }
    return _format_response(status, reason, headers);
}


/*******************************************************************************
 * Public API: namedtuples:
 *     Response()
 */
static PyObject *
Bodies(PyObject *self, PyObject *args)
{
    PyObject *Body = NULL;
    PyObject *BodyIter = NULL;
    PyObject *ChunkedBody = NULL;
    PyObject *ChunkedBodyIter = NULL;
    if (!PyArg_ParseTuple(args, "OOOO:Bodies",
            &Body, &BodyIter, &ChunkedBody, &ChunkedBodyIter)) {
        return NULL;
    }
    Py_INCREF(Body);
    Py_INCREF(BodyIter);
    Py_INCREF(ChunkedBody);
    Py_INCREF(ChunkedBodyIter);
    return _Bodies(Body, BodyIter, ChunkedBody, ChunkedBodyIter);
}

static PyObject *
Request(PyObject *self, PyObject *args)
{
    PyObject *method = NULL;
    PyObject *uri = NULL;
    PyObject *script = NULL;
    PyObject *path = NULL;
    PyObject *query = NULL;
    PyObject *headers = NULL;
    PyObject *range = NULL;
    PyObject *body = NULL;
    if (!PyArg_ParseTuple(args, "UUOOOOOO:Request",
            &method, &uri, &script, &path, &query, &headers, &range, &body)) {
        return NULL;
    }
    return _Request(method, uri, script, path, query, headers, range, body);
}

static PyObject *
Response(PyObject *self, PyObject *args)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;
    PyObject *headers = NULL;
    PyObject *body = NULL;
    if (!PyArg_ParseTuple(args, "OUOO:Response",
            &status, &reason, &headers, &body)) {
        return NULL;
    }
    return _Response(status, reason, headers, body);
}


/*******************************************************************************
 * Public API: PyMethodDef table:
 */
static struct PyMethodDef degu_functions[] = {
    /* Header Parsing */
    {"parse_header_name", parse_header_name, METH_VARARGS,
        "parse_header_name(name)"},
    {"parse_content_length", parse_content_length, METH_VARARGS,
        "parse_content_length(value)"},
    {"parse_range", parse_range, METH_VARARGS, "parse_range(src)"},
    {"parse_headers", parse_headers, METH_VARARGS, "parse_headers(src)"},

    /* Request Parsing */
    {"parse_method", parse_method, METH_VARARGS, "parse_method(method)"},
    {"parse_uri", parse_uri, METH_VARARGS, "parse_uri(uri)"},
    {"parse_request_line", parse_request_line, METH_VARARGS,
        "parse_request_line(line)"},
    {"parse_request", parse_request, METH_VARARGS, "parse_request(preamble)"},

    /* Response Parsing */
    {"parse_response_line", parse_response_line, METH_VARARGS,
        "parse_response_line(line)"},
    {"parse_response", parse_response, METH_VARARGS, "parse_response(preamble)"},

    /* Formatting */
    {"set_default_header", set_default_header, METH_VARARGS,
        "set_default_header(headers, key, val)"},
    {"format_headers", format_headers, METH_VARARGS, "format_headers(headers)"},
    {"format_request", format_request, METH_VARARGS,
        "format_request(method, uri, headers)"},
    {"format_response", format_response, METH_VARARGS,
        "format_response(status, reason, headers)"},

    /* namedtuples */
    {"Bodies", Bodies, METH_VARARGS,
        "Bodies(Body, BodyIter, ChunkedBody, ChunkedBodyIter)"
    },
    {"Request", Request, METH_VARARGS,
        "Request(method, uri, script, path, query, headers, body)"
    },
    {"Response", Response, METH_VARARGS,
        "Response(status, reason, headers, body)"
    },

    {NULL, NULL, 0, NULL}
};


/*******************************************************************************
 * Reader:
 */
typedef struct {
    PyObject_HEAD
    bool closed;
    PyObject *shutdown;
    PyObject *recv_into;
    PyObject *bodies_Body;
    PyObject *bodies_ChunkedBody;
    uint8_t *scratch;
    uint64_t rawtell;
    uint8_t *buf;
    size_t len;
    size_t start;
    size_t stop;
} Reader;

static void
Reader_dealloc(Reader *self)
{
    Py_CLEAR(self->shutdown);
    Py_CLEAR(self->recv_into);
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
    PyObject *sock = NULL;
    PyObject *bodies = NULL;
    ssize_t len = DEFAULT_PREAMBLE;
    static char *keys[] = {"sock", "bodies", "size", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO|n:Reader",
            keys, &sock, &bodies, &len)) {
        return -1;
    }
    if (len < MIN_PREAMBLE || len > MAX_PREAMBLE) {
        PyErr_Format(PyExc_ValueError,
            "need %zd <= size <= %zd; got %zd",
            MIN_PREAMBLE, MAX_PREAMBLE, len
        );
        return -1;
    }
    _SET(self->shutdown,  _getcallable("sock", sock, str_shutdown))
    _SET(self->recv_into, _getcallable("sock", sock, str_recv_into))
    _SET(self->bodies_Body, _getcallable("bodies", bodies, str_Body))
    _SET(self->bodies_ChunkedBody,
        _getcallable("bodies", bodies, str_ChunkedBody)
    )
    _SET(self->scratch, _calloc_buf(MAX_KEY))
    self->len = (size_t)len;
    _SET(self->buf, _calloc_buf(self->len))
    self->rawtell = 0;
    self->start = 0;
    self->stop = 0;
    self->closed = false;
    return 0;

error:
    Reader_dealloc(self);
    return -1;
}


/*******************************************************************************
 * Reader: Internal API:
 */
static PyObject *
_Reader_Body(Reader *self, PyObject *content_length) {
    if (content_length == NULL) {
        Py_FatalError("_Reader_Body(): bad internal call");
    }
    return PyObject_CallFunctionObjArgs(
        self->bodies_Body, self, content_length, NULL
    );
}

static PyObject *
_Reader_ChunkedBody(Reader *self) {
    return PyObject_CallFunctionObjArgs(self->bodies_ChunkedBody, self, NULL);
}


static ssize_t
_Reader_recv_into(Reader *self, _Dst dst)
{
    PyObject *view = NULL;
    PyObject *int_size = NULL;
    size_t size;
    ssize_t ret = -1;

    if (_dst_isempty(dst) || dst.len > MAX_IO_SIZE) {
        Py_FatalError("_Reader_recv_into(): bad internal call");
    }
    _SET(view,
        PyMemoryView_FromMemory((char *)dst.buf, (ssize_t)dst.len, PyBUF_WRITE)
    )
    _SET(int_size,
        PyObject_CallFunctionObjArgs(self->recv_into, view, NULL)
    )

    /* sock.recv_into() must return an `int` */
    if (!PyLong_CheckExact(int_size)) {
        PyErr_Format(PyExc_TypeError,
            "need a <class 'int'>; recv_into() returned a %R: %R",
            Py_TYPE(int_size), int_size
        );
        goto error;
    }

    /* Convert to size_t, check for OverflowError */
    size = PyLong_AsSize_t(int_size);
    if (PyErr_Occurred()) {
        goto error;
    }

    /* sock.recv_into() must return (0 <= size <= dst.len) */
    if (size > dst.len) {
        PyErr_Format(PyExc_OSError,
            "need 0 <= size <= %zu; recv_into() returned %zu", dst.len, size
        );
        goto error;
    }

    /* Add this number into our running raw read total */
    self->rawtell += size;
    ret = (ssize_t)size;
    goto cleanup;

error:
    if (ret >= 0) {
        Py_FatalError(
            "_Reader_recv_into(): in error, but ret >= 0"
        );
    }

cleanup:
    Py_CLEAR(view);
    Py_CLEAR(int_size);
    return ret;
}

static _Src
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
    return (_Src){cur_buf, _min(size, cur_len)};
}

static _Src
_Reader_drain(Reader *self, const size_t size)
{
    _Src cur = _Reader_peek(self, size);
    self->start += cur.len;
    if (self->start == self->stop) {
        self->start = 0;
        self->stop = 0;
    }
    return  cur;
}

static _Src
_Reader_read_until(Reader *self, const size_t size, _Src end,
                   const bool always_drain, const bool strip_end)
{
    ssize_t index = -1;
    ssize_t added;

    if (end.buf == NULL || (always_drain && strip_end)) {
        Py_FatalError("_Reader_read_until(): bad internal call");
    }
    if (end.len == 0) {
        PyErr_SetString(PyExc_ValueError, "end cannot be empty");
        return NULL_Src;
    }
    _Dst dst = {self->buf, self->len};
    if (size < end.len || size > dst.len) {
        PyErr_Format(PyExc_ValueError,
            "need %zu <= size <= %zu; got %zd", end.len, dst.len, size
        );
        return NULL_Src;
    }

    /* First, see if end is in the current buffer content */
    _Src cur = _Reader_peek(self, size);
    if (cur.len >= end.len) {
        index = _find(cur, end);
        if (index >= 0) {
            goto found;
        }
        if (cur.len >= size) {
            if (cur.len != size) {
                Py_FatalError("_Reader_read_until(): cur.len >= size");
            }
            goto not_found;
        }
    }

    /* If needed, shift current buffer content */
    if (self->start > 0) {
        _move(dst, cur);
        self->start = 0;
        self->stop = cur.len;
    }

    /* Now read till found */
    while (self->stop < size) {
        added = _Reader_recv_into(self, _dst_slice(dst, self->stop, dst.len));
        if (added < 0) {
            return NULL_Src;
        }
        if (added == 0) {
            break;
        }
        self->stop += (size_t)added;
        index = _find(_Reader_peek(self, size), end);
        if (index >= 0) {
            goto found;
        }
    }

not_found:
    if (index >= 0) {
        Py_FatalError("_Reader_read_until(): not_found, but index >= 0");
    }
    if (always_drain) {
        return _Reader_drain(self, size);
    }
    _Src tmp = _Reader_peek(self, size);
    if (tmp.len == 0) {
        return tmp;
    }
    _value_error2(
        "%R not found in %R...", end, _slice(tmp, 0, _min(tmp.len, 32))
    );
    return NULL_Src;

found:
    if (index < 0) {
        Py_FatalError("_Reader_read_until(): found, but index < 0");
    }
    _Src src = _Reader_drain(self, (size_t)index + end.len);
    if (strip_end) {
        return _slice(src, 0, src.len - end.len);
    }
    return src;
}

static ssize_t
_Reader_readinto(Reader *self, _Dst dst)
{
    size_t start;
    ssize_t added;

    if (dst.buf == NULL || dst.len > MAX_IO_SIZE) {
        Py_FatalError("_Reader_readinto(): bad internal call");
    }
    _Src src = _Reader_drain(self, dst.len);
    if (src.len > 0) {
        _copy(dst, src);
    }
    start = src.len;
    while (start < dst.len) {
        added = _Reader_recv_into(self, _dst_slice(dst, start, dst.len));
        if (added < 0) {
            return -1;
        }
        if (added == 0) {
            break;
        }
        start += (size_t)added;
    }
    if (start > dst.len) {
        Py_FatalError("_Reader_readinto(): start > dst.len");
    }
    return (ssize_t)start;  
}


/*******************************************************************************
 * Reader: Public API:
 *     Reader.close()
 *     Reader.Body()
 *     Reader.ChunkedBody()
 *     Reader.rawtell()
 *     Reader.tell()
 *     Reader.expose()
 *     Reader.peek()
 *     Reader.drain()
 *     Reader.read_until()
 *     Reader.readline()
 *     Reader.read_request()
 *     Reader.read_response()
 *     Reader.read()
 *     Reader.readinto()
 */
static PyObject *
Reader_close(Reader *self)
{
    if (self->closed) {
        Py_RETURN_NONE;
    }
    self->closed = true;
    return PyObject_CallFunctionObjArgs(self->shutdown, int_SHUT_RDWR, NULL);
}

static PyObject *
Reader_Body(Reader *self, PyObject *args) {
    PyObject *content_length = NULL;
    if (!PyArg_ParseTuple(args, "O:Body", &content_length)) {
        return NULL;
    }
    return _Reader_Body(self, content_length);
}

static PyObject *
Reader_ChunkedBody(Reader *self) {
    return _Reader_ChunkedBody(self);
}

static PyObject *
Reader_rawtell(Reader *self) {
    return PyLong_FromUnsignedLongLong(self->rawtell);
}

static PyObject *
Reader_tell(Reader *self) {
    _Src cur = _Reader_peek(self, self->len);
    if (cur.len > self->rawtell) {
        Py_FatalError("Reader_tell(): cur.len > self->rawtell");
    }
    return PyLong_FromUnsignedLongLong(self->rawtell - cur.len);
}

static PyObject *
Reader_expose(Reader *self) {
    _Src rawbuf = {self->buf, self->len};
    return _tobytes(rawbuf);
}

static PyObject *
Reader_peek(Reader *self, PyObject *args) {
    size_t size = 0;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_peek(self, size));
}

static PyObject *
Reader_drain(Reader *self, PyObject *args) {
    size_t size = 0;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_drain(self, size));
}

static PyObject *
Reader_read_until(Reader *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"size", "end", "always_drain", "strip_end", NULL};
    size_t size = 0;
    uint8_t *buf = NULL;
    size_t len = 0;
    int always_drain = false;
    int strip_end = false;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "ny#|pp:read_until", keys,
            &size, &buf, &len, &always_drain, &strip_end)) {
        return NULL;
    }
    if (always_drain && strip_end) {
        PyErr_SetString(PyExc_ValueError,
            "`always_drain` and `strip_end` cannot both be True"
        );
        return NULL;
    }
    _Src end = {buf, len};
    return _tobytes(
        _Reader_read_until(self, size, end, always_drain, strip_end)
    );
}

static PyObject *
Reader_readline(Reader *self, PyObject *args)
{
    size_t size = 0;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_read_until(self, size, LF, true, false));
}

static PyObject *
Reader_read_request(Reader *self) {
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;

    _Src src = _Reader_read_until(self, self->len, CRLFCRLF, false, true);
    if (src.buf == NULL) {
        goto error;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "request preamble is empty");
        goto error;
    }
    if (!_parse_request(src, (_Dst){self->scratch, MAX_KEY}, &dr)) {
        goto error;
    }
    const uint8_t bodyflags = (dr.flags & 3);
    if (bodyflags == 0) {
        _SET_AND_INC(dr.body, Py_None)
    }
    else if (bodyflags == 1) {
        _SET(dr.body, _Reader_Body(self, dr.content_length))
    }
    else if (bodyflags == 2) {
        _SET(dr.body, _Reader_ChunkedBody(self))
    }
    _SET(ret,
        _Request(dr.method, dr.uri, dr.script, dr.path, dr.query, dr.headers, dr.range, dr.body)
    )
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_request(&dr);
    return ret;
}


static PyObject *
Reader_read_response(Reader *self, PyObject *args)
{
    const uint8_t *method_buf = NULL;
    size_t method_len = 0;
    PyObject *method = NULL;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;

    /* Parse args, validate the request method */
    if (!PyArg_ParseTuple(args, "s#:read_response", &method_buf, &method_len)) {
        return NULL;
    }
    _SET(method, _parse_method((_Src){method_buf, method_len}))

    /* Reader.search() will drain up to the end of the preamble */
    _Src src = _Reader_read_until(self, self->len, CRLFCRLF, false, true);
    if (src.buf == NULL) {
        goto error;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "response preamble is empty");
        goto error;
    }

    /* Parse response line and header lines */
    if (!_parse_response(src, (_Dst){self->scratch, MAX_KEY}, &dr)) {
        goto error;
    }

    /* Construct the body:
     *
     * The 2 low bits in dr.flags are for content-length and transfer_encoding,
     * so we test (dr.flags & 3).  This allows additional flags to be added in
     * the future without breaking this logic.
     */
    const uint8_t bodyflags = (dr.flags & 3);
    if (method == str_HEAD || bodyflags == 0) {
        _SET_AND_INC(dr.body, Py_None)
    }
    else if (bodyflags == 1) {
        _SET(dr.body, _Reader_Body(self, dr.content_length))
    }
    else if (bodyflags == 2) {
        _SET(dr.body, _Reader_ChunkedBody(self))
    }
    _SET(ret, _Response(dr.status, dr.reason, dr.headers, dr.body))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(method);
    _clear_degu_response(&dr);
    return ret;
}

static PyObject *
Reader_read(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    if (size < 0 || size > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "need 0 <= size <= %zu; got %zd", MAX_IO_SIZE, size
        );
        return NULL;
    }
    _SET(ret, PyBytes_FromStringAndSize(NULL, size))
    _Dst dst = {(uint8_t *)PyBytes_AS_STRING(ret), (size_t)size};
    const ssize_t total = _Reader_readinto(self, dst);
    if (total < 0) {
        goto error;
    }
    if (total < size) {
        if (_PyBytes_Resize(&ret, total) != 0) {
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
Reader_readinto(Reader *self, PyObject *args)
{
    Py_buffer pybuf;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "w*", &pybuf)) {
        goto error;
    }
    if (pybuf.len < 1 || pybuf.len > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "need 1 <= len(buf) <= %zu; got %zd", MAX_IO_SIZE, pybuf.len
        );
        goto error;
    }
    _Dst dst = {pybuf.buf, (size_t)pybuf.len};
    const ssize_t total = _Reader_readinto(self, dst);
    if (total < 0) {
        goto error;
    }
    _SET(ret, PyLong_FromSsize_t(total))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    PyBuffer_Release(&pybuf);
    return ret;
}


/*******************************************************************************
 * Reader: PyMethodDef, PyTypeObject:
 */
static PyMethodDef Reader_methods[] = {
    {"close", (PyCFunction)Reader_close, METH_NOARGS, "close()"},
    {"Body", (PyCFunction)Reader_Body, METH_VARARGS,
        "Body(content_length)"
    },
    {"ChunkedBody", (PyCFunction)Reader_ChunkedBody, METH_NOARGS,
        "ChunkedBody()"
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
    {"read_response", (PyCFunction)Reader_read_response, METH_VARARGS,
        "read_response(method)"
    },

    {"expose", (PyCFunction)Reader_expose, METH_NOARGS, "expose()"},
    {"peek", (PyCFunction)Reader_peek, METH_VARARGS, "peek(size)"},
    {"drain", (PyCFunction)Reader_drain, METH_VARARGS, "drain(size)"},
    {"read_until", (PyCFunction)Reader_read_until, METH_VARARGS | METH_KEYWORDS,
        "read_until(size, end, always_drain=False, stip_end=False)"
    },
    {"readline", (PyCFunction)Reader_readline, METH_VARARGS, "readline(size)"},
    {"read", (PyCFunction)Reader_read, METH_VARARGS, "read(size)"},
    {"readinto", (PyCFunction)Reader_readinto, METH_VARARGS, "readinto(buf)"},

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


/*******************************************************************************
 * Writer:
 */
typedef struct {
    PyObject_HEAD
    bool closed;
    PyObject *shutdown;
    PyObject *send;
    PyObject *length_types;
    PyObject *chunked_types;
    uint64_t tell;
} Writer;

static void
Writer_dealloc(Writer *self)
{
    Py_CLEAR(self->shutdown);
    Py_CLEAR(self->send);
    Py_CLEAR(self->length_types);
    Py_CLEAR(self->chunked_types);
}

static int
Writer_init(Writer *self, PyObject *args, PyObject *kw)
{
    int ret = 0;
    PyObject *sock = NULL;
    PyObject *bodies = NULL;
    PyObject *Body = NULL;
    PyObject *BodyIter = NULL;
    PyObject *ChunkedBody = NULL;
    PyObject *ChunkedBodyIter = NULL;
    static char *keys[] = {"sock", "bodies", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO:Writer", keys,
            &sock, &bodies)) {
        goto error;
    }

    self->closed = false;
    self->tell = 0;
    _SET(self->shutdown,  _getcallable("sock", sock, str_shutdown))
    _SET(self->send,      _getcallable("sock", sock, str_send))
    _SET(Body,            PyObject_GetAttr(bodies, str_Body))
    _SET(BodyIter,        PyObject_GetAttr(bodies, str_BodyIter))
    _SET(ChunkedBody,     PyObject_GetAttr(bodies, str_ChunkedBody))
    _SET(ChunkedBodyIter, PyObject_GetAttr(bodies, str_ChunkedBodyIter))
    _SET(self->length_types, PyTuple_Pack(2, Body, BodyIter))
    _SET(self->chunked_types, PyTuple_Pack(2, ChunkedBody, ChunkedBodyIter))
    goto cleanup;
error:
    ret = -1;
    Writer_dealloc(self);
cleanup:
    Py_CLEAR(Body);
    Py_CLEAR(BodyIter);
    Py_CLEAR(ChunkedBody);
    Py_CLEAR(ChunkedBodyIter);
    return ret;
}


/*******************************************************************************
 * Writer: Internal API:
 *     _Writer_write()
 *     _Writer_set_default_headers()
 */


static ssize_t
_Writer_write1(Writer *self, _Src src)
{
    PyObject *view = NULL;
    PyObject *int_size = NULL;
    size_t size;
    ssize_t ret = -2;

    if (src.buf == NULL || src.len == 0 || src.len > MAX_IO_SIZE) {
        Py_FatalError("_Writer_write1(): bad internal call");
    }
    _SET(view,
        PyMemoryView_FromMemory((char *)src.buf, (ssize_t)src.len, PyBUF_READ)
    )
    _SET(int_size, PyObject_CallFunctionObjArgs(self->send, view, NULL))
    if (!PyLong_CheckExact(int_size)) {
        PyErr_Format(PyExc_TypeError,
            "need a <class 'int'>; send() returned a %R: %R",
            Py_TYPE(int_size), int_size
        );
        goto error;
    }
    size = PyLong_AsSize_t(int_size);
    if (PyErr_Occurred()) {
        goto error;
    }
    if (size > src.len) {
        PyErr_Format(PyExc_OSError,
            "need 0 <= size <= %zu; send() returned %zu", src.len, size
        );
        goto error;
    }
    ret = (ssize_t)size;
    goto cleanup;

error:
    ret = -1;

cleanup:
    Py_CLEAR(view);
    Py_CLEAR(int_size);
    if (ret < 0 && ret != -1) {
        Py_FatalError("_Writer_write1(): ret < 0 && ret != -1");
    }
    return ret;
}

static ssize_t
_Writer_write(Writer *self, _Src src)
{
    size_t total = 0;
    ssize_t wrote;

    while (total < src.len) {
        wrote = _Writer_write1(self, _slice(src, total, src.len));
        if (wrote < 0) {
            return -1;
        }
        if (wrote == 0) {
            break;
        }
        total += (size_t)wrote;
    }
    if (total != src.len) {
        PyErr_Format(PyExc_OSError,
            "expected %zu; send() returned %zu", src.len, total
        );
        return -1;
    }
    self->tell += total;
    return (ssize_t)total;
}

static bool
_set_default_content_length(PyObject *headers, PyObject *val)
{
    if (val == NULL) {
        return false;
    }
    bool result = _set_default_header(headers, key_content_length, val);
    Py_CLEAR(val);
    return result;
}

static bool
_Writer_set_default_headers(Writer *self, PyObject *headers, PyObject *body)
{
    ssize_t len;
    PyObject *val;

    if (body == Py_None) {
        return true;
    }
    if (PyBytes_CheckExact(body)) {
        len = PyBytes_GET_SIZE(body);
        val = PyLong_FromSsize_t(len);
        return _set_default_content_length(headers, val);
    }
    if (PyObject_IsInstance(body, self->length_types)) {
        val = PyObject_GetAttr(body, str_content_length);
        return _set_default_content_length(headers, val);
    }
    if (PyObject_IsInstance(body, self->chunked_types)) {
        return _set_default_header(headers, key_transfer_encoding, str_chunked);
    }
    PyErr_Format(PyExc_TypeError, "bad body type: %R: %R", Py_TYPE(body), body);
    return false;
}


static int64_t
_Writer_write_combined(Writer *self, _Src src1, _Src src2)
{
    const size_t len = src1.len + src2.len;
    uint8_t *buf = _calloc_buf(len);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, src1.buf, src1.len);
    memcpy(buf + src1.len, src2.buf, src2.len);
    _Src src = (_Src){buf, len};
    int64_t total = _Writer_write(self, src);
    free(buf);
    return total;
}


static int64_t
_Writer_write_output(Writer *self, _Src preamble, PyObject *body)
{
    if (body == Py_None) {
        return _Writer_write(self, preamble);
    }
    if (PyBytes_CheckExact(body)) {
        return _Writer_write_combined(self, preamble, _frombytes(body));
    }

    if (_Writer_write(self, preamble) < 0) {
        return -1;
    }

    const uint64_t orig_tell = self->tell;
    PyObject *int_total = NULL;
    uint64_t total;
    int64_t ret = -2;

    _SET(int_total, PyObject_CallMethodObjArgs(body, str_write_to, self, NULL))
    if (!PyLong_CheckExact(int_total)) {
        PyErr_Format(PyExc_TypeError,
            "need a <class 'int'>; write_to() returned a %R: %R",
            Py_TYPE(int_total), int_total
        );
        goto error;
    }
    total = PyLong_AsUnsignedLongLong(int_total);
    if (PyErr_Occurred()) {
        goto error;
    }
    if (orig_tell + total != self->tell) {
        PyErr_Format(PyExc_ValueError,
            "%llu bytes were written, but write_to() returned %llu",
            (self->tell - orig_tell), total
        );
        goto error;
    }
    ret = (int64_t)(total + preamble.len);
    goto cleanup;

error:
    ret = -1;

cleanup:
    Py_CLEAR(int_total);
    if (ret < 0 && ret != -1) {
        Py_FatalError("_Writer_write_output(): ret < 0 && ret != -1");
    }
    return ret;
}




/*******************************************************************************
 * Writer: Public API:
 *     Writer.close()
 *     Writer.tell()
 *     Writer.write()
 *     Writer.flush()
 */
static PyObject *
Writer_close(Writer *self)
{
    if (self->closed) {
        Py_RETURN_NONE;
    }
    self->closed = true;
    return PyObject_CallFunctionObjArgs(self->shutdown, int_SHUT_RDWR, NULL);
}

static PyObject *
Writer_tell(Writer *self) {
    return PyLong_FromUnsignedLongLong(self->tell);
}

static PyObject *
Writer_write(Writer *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    if (!PyArg_ParseTuple(args, "y#:write", &buf, &len)) {
        return NULL;
    }
    _Src src = {buf, len};
    const ssize_t total = _Writer_write(self, src);
    if (total < 0) {
        return NULL;
    }
    return PyLong_FromSsize_t(total);
}

static PyObject *
Writer_flush(Writer *self)
{
    Py_RETURN_NONE;
}

static PyObject *
Writer_write_output(Writer *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *body = NULL;
    int64_t total;

    if (!PyArg_ParseTuple(args, "y#O", &buf, &len, &body)) {
        return NULL;
    }
    _Src preamble_src = {buf, len};
    total = _Writer_write_output(self, preamble_src, body);
    if (total < 0) {
        return NULL;
    }
    return PyLong_FromLongLong(total);
}

static PyObject *
Writer_set_default_headers(Writer *self, PyObject *args) {
    PyObject *headers = NULL;
    PyObject *body = NULL;
    if (!PyArg_ParseTuple(args, "OO", &headers, &body)) {
        return NULL;
    }
    if (!_Writer_set_default_headers(self, headers, body)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


static PyObject *
Writer_write_request(Writer *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *uri = NULL;
    PyObject *headers = NULL;
    PyObject *body = NULL;
    PyObject *preamble = NULL;
    int64_t total = -1;

    if (!PyArg_ParseTuple(args, "s#UOO:", &buf, &len, &uri, &headers, &body)) {
        return NULL;
    }
    if (!_Writer_set_default_headers(self, headers, body)) {
        return NULL;
    }
    _Src method_src = {buf, len};
    _SET(preamble, _format_request(method_src, uri, headers))
    total = _Writer_write_output(self, _frombytes(preamble), body);
    goto cleanup;

error:

cleanup:
    Py_CLEAR(preamble);
    if (total <= 0) {
        return NULL;
    }
    return PyLong_FromLongLong(total);
}

static PyObject *
Writer_write_response(Writer *self, PyObject *args)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;
    PyObject *headers = NULL;
    PyObject *body = NULL;
    PyObject *preamble = NULL;
    int64_t total = -1;

    if (!PyArg_ParseTuple(args, "OUOO:", &status, &reason, &headers, &body)) {
        return NULL;
    }
    if (!_Writer_set_default_headers(self, headers, body)) {
        return NULL;
    }
    total = 0;
    _SET(preamble, _format_response(status, reason, headers))
    total = _Writer_write_output(self, _frombytes(preamble), body);
    goto cleanup;

error:

cleanup:
    Py_CLEAR(preamble);
    if (total <= 0) {
        return NULL;
    }
    return PyLong_FromLongLong(total);
}


/*******************************************************************************
 * Writer: PyMethodDef, PyTypeObject:
 */
static PyMethodDef Writer_methods[] = {
    {"close", (PyCFunction)Writer_close, METH_NOARGS, "close()"},
    {"tell", (PyCFunction)Writer_tell, METH_NOARGS, "tell()"},
    {"flush", (PyCFunction)Writer_flush, METH_NOARGS, "flush()"},
    {"write", (PyCFunction)Writer_write, METH_VARARGS, "write(buf)"},

    {"write_output", (PyCFunction)Writer_write_output, METH_VARARGS,
        "write_output(preamble, body)"},
    {"set_default_headers", (PyCFunction)Writer_set_default_headers, METH_VARARGS,
        "set_default_headers(headers, body)"},
    {"write_request", (PyCFunction)Writer_write_request, METH_VARARGS,
        "write_request(method, uri, headers, body)"},
    {"write_response", (PyCFunction)Writer_write_response, METH_VARARGS,
        "write_response(status, reason, headers, body)"},
    {NULL}
};

static PyTypeObject WriterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "degu._base.Writer",          /* tp_name */
    sizeof(Writer),               /* tp_basicsize */
    0,                            /* tp_itemsize */
    (destructor)Writer_dealloc,   /* tp_dealloc */
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
    "Writer(sock, bodies)",       /* tp_doc */
    0,                            /* tp_traverse */
    0,                            /* tp_clear */
    0,                            /* tp_richcompare */
    0,                            /* tp_weaklistoffset */
    0,                            /* tp_iter */
    0,                            /* tp_iternext */
    Writer_methods,               /* tp_methods */
    0,                            /* tp_members */
    0,                            /* tp_getset */
    0,                            /* tp_base */
    0,                            /* tp_dict */
    0,                            /* tp_descr_get */
    0,                            /* tp_descr_set */
    0,                            /* tp_dictoffset */
    (initproc)Writer_init,        /* tp_init */
    0,                            /* tp_alloc */
    0,                            /* tp_new */
};



/*******************************************************************************
 * Module Init:
 */
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
    PyObject *module = PyModule_Create(&degu);
    if (module == NULL) {
        return NULL;
    }
    if (!_init_all_namedtuples(module)) {
        return NULL;
    }

    ReaderType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ReaderType) < 0) {
        return NULL;
    }
    Py_INCREF(&ReaderType);
    PyModule_AddObject(module, "Reader", (PyObject *)&ReaderType);

    RangeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&RangeType) < 0) {
        return NULL;
    }
    Py_INCREF(&RangeType);
    PyModule_AddObject(module, "Range", (PyObject *)&RangeType);

    WriterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&WriterType) < 0) {
        return NULL;
    }
    Py_INCREF(&WriterType);
    PyModule_AddObject(module, "Writer", (PyObject *)&WriterType);

    /* Init integer constants */
    PyModule_AddIntMacro(module, _MAX_LINE_SIZE);
    PyModule_AddIntMacro(module, MIN_PREAMBLE);
    PyModule_AddIntMacro(module, DEFAULT_PREAMBLE);
    PyModule_AddIntMacro(module, MAX_PREAMBLE);

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

    /* socket methods */
    _SET(str_shutdown,  PyUnicode_InternFromString("shutdown"))
    _SET(str_recv_into, PyUnicode_InternFromString("recv_into"))
    _SET(str_send,      PyUnicode_InternFromString("send"))
    _SET(str_write_to,  PyUnicode_InternFromString("write_to"))

    /* bodies attributes */
    _SET(str_Body,            PyUnicode_InternFromString("Body"))
    _SET(str_BodyIter,        PyUnicode_InternFromString("BodyIter"))
    _SET(str_ChunkedBody,     PyUnicode_InternFromString("ChunkedBody"))
    _SET(str_ChunkedBodyIter, PyUnicode_InternFromString("ChunkedBodyIter"))

    _SET(str_content_length, PyUnicode_InternFromString("content_length"))
    _SET(key_content_length, PyUnicode_InternFromString("content-length"))
    _SET(key_content_type, PyUnicode_InternFromString("content-type"))
    _SET(key_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _SET(str_chunked, PyUnicode_InternFromString("chunked"))
    _SET(key_range, PyUnicode_InternFromString("range"))
    _SET(val_application_json, PyUnicode_InternFromString("application/json"))

    _SET(str_crlf, PyUnicode_InternFromString("\r\n"))
    _SET(str_empty, PyUnicode_InternFromString(""))

    _SET(int_SHUT_RDWR, PyLong_FromLong(SHUT_RDWR))

    return module;

error:
    return NULL;
}

