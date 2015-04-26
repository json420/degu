/*
 * degu: an embedded HTTP server and client library
 * Copyright (C) 2014-2015 Novacut Inc
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

#include "_base.h"


/******************************************************************************
 * PyObject globals (largely for performance and memory efficiency).
 ******************************************************************************/

/* EmptyPreambleError exception */
static PyObject *EmptyPreambleError = NULL;
static PyObject *bodies = NULL;

/* Interned `str` for fast attribute lookup */
static PyObject *attr_recv_into        = NULL;  //  'recv_into'
static PyObject *attr_send             = NULL;  //  'send'
static PyObject *attr_readinto         = NULL;  //  'readinto'
static PyObject *attr_write            = NULL;  //  'write'
static PyObject *attr_readline         = NULL;  //  'readline'


/* Non-interned `str` used for header keys */
static PyObject *key_content_length    = NULL;  //  'content-length'
static PyObject *key_transfer_encoding = NULL;  //  'transfer-encoding'
static PyObject *key_content_type      = NULL;  //  'content-type'
static PyObject *key_range             = NULL;  //  'range'

/* Non-interned `str` used for header values */
static PyObject *val_chunked           = NULL;  //  'chunked'
static PyObject *val_application_json  = NULL;  //  'application/json'

/* Other non-interned `str` used for parsed values, etc */
static PyObject *str_GET               = NULL;  //  'GET'
static PyObject *str_PUT               = NULL;  //  'PUT'
static PyObject *str_POST              = NULL;  //  'POST'
static PyObject *str_HEAD              = NULL;  //  'HEAD'
static PyObject *str_DELETE            = NULL;  //  'DELETE'
static PyObject *str_OK                = NULL;  //  'OK'
static PyObject *str_crlf              = NULL;  //  '\r\n'
static PyObject *str_empty             = NULL;  //  ''

/* Other misc PyObject */
static PyObject *bytes_empty           = NULL;  //  b''
static PyObject *bytes_CRLF            = NULL;  //  b'\r\n'
static PyObject *int_MAX_LINE_SIZE     = NULL;  //  4096


/* _init_all_globals(): called by PyInit__base() */
static bool
_init_all_globals(PyObject *module)
{
    /* Init EmptyPreambleError exception */
    _SET(EmptyPreambleError,
        PyErr_NewException("degu._base.EmptyPreambleError", PyExc_ConnectionError, NULL)
    )
    _ADD_MODULE_ATTR(module, "EmptyPreambleError", EmptyPreambleError)

    /* Init interned attribute names */
    _SET(attr_recv_into,       PyUnicode_InternFromString("recv_into"))
    _SET(attr_send,            PyUnicode_InternFromString("send"))
    _SET(attr_readinto,        PyUnicode_InternFromString("readinto"))
    _SET(attr_write,           PyUnicode_InternFromString("write"))
    _SET(attr_readline,        PyUnicode_InternFromString("readline"))

    /* Init non-interned header keys */
    _SET(key_content_length,    PyUnicode_FromString("content-length"))
    _SET(key_transfer_encoding, PyUnicode_FromString("transfer-encoding"))
    _SET(key_content_type,      PyUnicode_FromString("content-type"))
    _SET(key_range,             PyUnicode_FromString("range"))

    /* Init non-interned header values */
    _SET(val_chunked,          PyUnicode_FromString("chunked"))
    _SET(val_application_json, PyUnicode_FromString("application/json"))

    /* Init other non-interned strings */
    _SET(str_GET,    PyUnicode_FromString("GET"))
    _SET(str_PUT,    PyUnicode_FromString("PUT"))
    _SET(str_POST,   PyUnicode_FromString("POST"))
    _SET(str_HEAD,   PyUnicode_FromString("HEAD"))
    _SET(str_DELETE, PyUnicode_FromString("DELETE"))
    _SET(str_OK,     PyUnicode_FromString("OK"))
    _SET(str_crlf,   PyUnicode_FromString("\r\n"))
    _SET(str_empty,  PyUnicode_FromString(""))

    /* Init misc objects */
    _SET(bytes_empty, PyBytes_FromStringAndSize(NULL, 0))
    _SET(bytes_CRLF,  PyBytes_FromStringAndSize("\r\n", 2))
    _SET(int_MAX_LINE_SIZE, PyLong_FromLong(_MAX_LINE_SIZE))

    return true;

error:
    return false;
}


/******************************************************************************
 * DeguSrc static globals.
 ******************************************************************************/
_DEGU_SRC_CONSTANT(LF, "\n")
_DEGU_SRC_CONSTANT(CRLF, "\r\n")
_DEGU_SRC_CONSTANT(CRLFCRLF, "\r\n\r\n")
_DEGU_SRC_CONSTANT(SPACE, " ")
_DEGU_SRC_CONSTANT(SLASH, "/")
_DEGU_SRC_CONSTANT(SPACE_SLASH, " /")
_DEGU_SRC_CONSTANT(QMARK, "?")
_DEGU_SRC_CONSTANT(SEP, ": ")
_DEGU_SRC_CONSTANT(REQUEST_PROTOCOL, " HTTP/1.1")
_DEGU_SRC_CONSTANT(RESPONSE_PROTOCOL, "HTTP/1.1 ")
_DEGU_SRC_CONSTANT(GET, "GET")
_DEGU_SRC_CONSTANT(PUT, "PUT")
_DEGU_SRC_CONSTANT(POST, "POST")
_DEGU_SRC_CONSTANT(HEAD, "HEAD")
_DEGU_SRC_CONSTANT(DELETE, "DELETE")
_DEGU_SRC_CONSTANT(OK, "OK")
_DEGU_SRC_CONSTANT(CONTENT_LENGTH, "content-length")
_DEGU_SRC_CONSTANT(TRANSFER_ENCODING, "transfer-encoding")
_DEGU_SRC_CONSTANT(CHUNKED, "chunked")
_DEGU_SRC_CONSTANT(RANGE, "range")
_DEGU_SRC_CONSTANT(CONTENT_TYPE, "content-type")
_DEGU_SRC_CONSTANT(APPLICATION_JSON, "application/json")
_DEGU_SRC_CONSTANT(BYTES_EQ, "bytes=")
_DEGU_SRC_CONSTANT(MINUS, "-")
_DEGU_SRC_CONSTANT(SEMICOLON, ";")
_DEGU_SRC_CONSTANT(EQUALS, "=")


/***************    BEGIN GENERATED TABLES    *********************************/
static const uint8_t _NAME[256] = {
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

static const uint8_t _NUMBER[256] = {
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
 * LOWER  1 00000001  b'-0123456789abcdefghijklmnopqrstuvwxyz'
 * UPPER  2 00000010  b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
 * URI    4 00000100  b'/?'
 * PATH   8 00001000  b'+.:_~'
 * QUERY 16 00010000  b'%&='
 * SPACE 32 00100000  b' '
 * VALUE 64 01000000  b'"\'()*,;[]'
 */
#define KEY_MASK    254  // 11111110 ~(LOWER)
#define VAL_MASK    128  // 10000000 ~(LOWER|UPPER|PATH|QUERY|URI|SPACE|VALUE)
#define URI_MASK    224  // 11100000 ~(LOWER|UPPER|PATH|QUERY|URI)
#define PATH_MASK   244  // 11110100 ~(LOWER|UPPER|PATH)
#define QUERY_MASK  228  // 11100100 ~(LOWER|UPPER|PATH|QUERY)
#define REASON_MASK 220  // 11011100 ~(LOWER|UPPER|SPACE)
#define EXTKEY_MASK 252  // 11111100 ~(LOWER|UPPER)
#define EXTVAL_MASK 180  // 10110100 ~(LOWER|UPPER|PATH|VALUE)
static const uint8_t _FLAG[256] = {
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
    128,128,128,128,128,128,128,128,
     32,128, 64,128,128, 16, 16, 64, //  ' '       '"'            '%'  '&'  "'"
     64, 64, 64,  8, 64,  1,  8,  4, //  '('  ')'  '*'  '+'  ','  '-'  '.'  '/'
      1,  1,  1,  1,  1,  1,  1,  1, //  '0'  '1'  '2'  '3'  '4'  '5'  '6'  '7'
      1,  1,  8, 64,128, 16,128,  4, //  '8'  '9'  ':'  ';'       '='       '?'
    128,  2,  2,  2,  2,  2,  2,  2, //       'A'  'B'  'C'  'D'  'E'  'F'  'G'
      2,  2,  2,  2,  2,  2,  2,  2, //  'H'  'I'  'J'  'K'  'L'  'M'  'N'  'O'
      2,  2,  2,  2,  2,  2,  2,  2, //  'P'  'Q'  'R'  'S'  'T'  'U'  'V'  'W'
      2,  2,  2, 64,128, 64,128,  8, //  'X'  'Y'  'Z'  '['       ']'       '_'
    128,  1,  1,  1,  1,  1,  1,  1, //       'a'  'b'  'c'  'd'  'e'  'f'  'g'
      1,  1,  1,  1,  1,  1,  1,  1, //  'h'  'i'  'j'  'k'  'l'  'm'  'n'  'o'
      1,  1,  1,  1,  1,  1,  1,  1, //  'p'  'q'  'r'  's'  't'  'u'  'v'  'w'
      1,  1,  1,128,128,128,  8,128, //  'x'  'y'  'z'                 '~'
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


/******************************************************************************
 * Internal functions for working with DeguSrc and DeguDst memory buffers.
 ******************************************************************************/
static inline bool
_isempty(DeguSrc src)
{
    if (src.buf == NULL || src.len == 0) {
        return true;
    }
    return false;
}

static DeguSrc
_slice(DeguSrc src, const size_t start, const size_t stop)
{
    if (_isempty(src) || start > stop || stop > src.len) {
        Py_FatalError("_slice(): bad internal call");
    }
    return (DeguSrc){src.buf + start, stop - start};
}

static inline bool
_equal(DeguSrc a, DeguSrc b) {
    if (a.len == b.len && memcmp(a.buf, b.buf, a.len) == 0) {
        return true;
    }
    return false;
}

static inline ssize_t
_find(DeguSrc haystack, DeguSrc needle)
{
    uint8_t *ptr = memmem(haystack.buf, haystack.len, needle.buf, needle.len);
    if (ptr == NULL) {
        return -1;
    }
    return ptr - haystack.buf;
}

static inline size_t
_search(DeguSrc haystack, DeguSrc needle)
{
    uint8_t *ptr = memmem(haystack.buf, haystack.len, needle.buf, needle.len);
    if (ptr == NULL) {
        return haystack.len;
    }
    return (size_t)(ptr - haystack.buf);
}

static PyObject *
_tostr(DeguSrc src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyUnicode_FromKindAndData(
        PyUnicode_1BYTE_KIND, src.buf, (ssize_t)src.len
    );
}

static PyObject *
_tobytes(DeguSrc src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)src.buf, (ssize_t)src.len);
}

static DeguSrc
_frombytes(PyObject *bytes)
{
    if (bytes == NULL || !PyBytes_CheckExact(bytes)) {
        Py_FatalError("_frombytes(): bad internal call");
    }
    return (DeguSrc){
        (uint8_t *)PyBytes_AS_STRING(bytes),
        (size_t)PyBytes_GET_SIZE(bytes)
    };
}

static DeguSrc
_frompybuf(Py_buffer *pybuf)
{
    if (pybuf->buf == NULL || pybuf->len < 1) {
        Py_FatalError("_frompybuf(): bad internal call");
    }
    if (PyBuffer_IsContiguous(pybuf, 'C') != 1) {
        Py_FatalError("_frompybuf(): buffer is not C-contiguous");
    }
    return (DeguSrc){pybuf->buf, (size_t)pybuf->len};
}

static DeguDst
_dst_frombytes(PyObject *bytes)
{
    if (bytes == NULL || !PyBytes_CheckExact(bytes)) {
        Py_FatalError("_frombytes(): bad internal call");
    }
    return (DeguDst){
        (uint8_t *)PyBytes_AS_STRING(bytes),
        (size_t)PyBytes_GET_SIZE(bytes)
    };
}

static void
_value_error(const char *format, DeguSrc src)
{
    PyObject *tmp = _tobytes(src);
    if (tmp != NULL) {
        PyErr_Format(PyExc_ValueError, format, tmp);
    }
    Py_CLEAR(tmp);
}

static void
_value_error2(const char *format, DeguSrc src1, DeguSrc src2)
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
_decode(DeguSrc src, const uint8_t mask, const char *format)
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
        bits |= _FLAG[c];
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
_dst_isempty(DeguDst dst)
{
    if (dst.buf == NULL || dst.len == 0) {
        return true;
    }
    return false;
}

static DeguDst
_dst_slice(DeguDst dst, const size_t start, const size_t stop)
{
    if (_dst_isempty(dst) || start > stop || stop > dst.len) {
        Py_FatalError("_dst_slice(): bad internal call");
    }
    return (DeguDst){dst.buf + start, stop - start};
}

static DeguSrc
_slice_src_from_dst(DeguDst dst, const size_t start, const size_t stop)
{
    if (_dst_isempty(dst) || start > stop || stop > dst.len) {
        Py_FatalError("_dst_slice(): bad internal call");
    }
    return (DeguSrc){dst.buf + start, stop - start};
}

static void
_move(DeguDst dst, DeguSrc src)
{
    if (_dst_isempty(dst) || _isempty(src) || dst.len < src.len) {
        Py_FatalError("_move(): bad internal call");
    }
    memmove(dst.buf, src.buf, src.len);
}

static size_t
_copy(DeguDst dst, DeguSrc src)
{
    if (dst.buf == NULL || src.buf == NULL || dst.len < src.len) {
        Py_FatalError("_copy(): bad internal call");
    }
    memcpy(dst.buf, src.buf, src.len);
    return src.len;
}

static DeguDst
_calloc_dst(const size_t len)
{
    if (len == 0) {
        Py_FatalError("_call_dst(): bad internal call");
    }
    uint8_t *buf = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (buf == NULL) {
        PyErr_NoMemory();
        return NULL_DeguDst;
    }
    return (DeguDst){buf, len};
}

static DeguDst
_dst_frompybuf(Py_buffer *pybuf)
{
    if (pybuf->buf == NULL || pybuf->len < 1) {
        Py_FatalError("_frompybuf(): bad internal call");
    }
    if (PyBuffer_IsContiguous(pybuf, 'C') != 1) {
        Py_FatalError("_frompybuf(): buffer is not C-contiguous");
    }
    if (pybuf->readonly) {
        Py_FatalError("_frompybuf(): buffer is read-only");
    }
    return (DeguDst){pybuf->buf, (size_t)pybuf->len};
}


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
    if (len == 0) {
        Py_FatalError("_call_buf(): bad internal call");
    }
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
_getcallable(const char *label, PyObject *obj, PyObject *name)
{
    PyObject *attr = PyObject_GetAttr(obj, name);
    if (attr == NULL) {
        return NULL;
    }
    if (! PyCallable_Check(attr)) {
        Py_CLEAR(attr);
        PyErr_Format(PyExc_TypeError, "%s.%S() is not callable", label, name);
    }
    return attr;
}



/******************************************************************************
 * C equivalent of Python namedtuple (PyStructSequence).
 ******************************************************************************/

/* Bodies namedtuple */
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
_Bodies(PyObject *arg0, PyObject *arg1, PyObject *arg2, PyObject *arg3)
{
    PyObject *ret = PyStructSequence_New(&BodiesType);
    if (ret != NULL) {
        Py_INCREF(arg0);  PyStructSequence_SET_ITEM(ret, 0, arg0);
        Py_INCREF(arg1);  PyStructSequence_SET_ITEM(ret, 1, arg1);
        Py_INCREF(arg2);  PyStructSequence_SET_ITEM(ret, 2, arg2);
        Py_INCREF(arg3);  PyStructSequence_SET_ITEM(ret, 3, arg3);
    }
    return ret;
}

static PyObject *
Bodies(PyObject *self, PyObject *args)
{
    PyObject *arg0 = NULL;  // Body
    PyObject *arg1 = NULL;  // BodyIter
    PyObject *arg2 = NULL;  // ChunkedBody
    PyObject *arg3 = NULL;  // ChunkedBodyIter

    if (!PyArg_ParseTuple(args, "OOOO:Bodies", &arg0, &arg1, &arg2, &arg3)) {
        return NULL;
    }
    return _Bodies(arg0, arg1, arg2, arg3);
}


/* Request namedtuple */
static PyTypeObject RequestType;
static PyStructSequence_Field RequestFields[] = {
    {"method", NULL},
    {"uri", NULL},
    {"headers", NULL},
    {"body", NULL},
    {"script", NULL},
    {"path", NULL},
    {"query", NULL},
    {NULL},
};
static PyStructSequence_Desc RequestDesc = {
    "Request",
    NULL,
    RequestFields,  
    7
};

static PyObject *
_Request(PyObject *arg0,  // method
         PyObject *arg1,  // uri
         PyObject *arg2,  // headers
         PyObject *arg3,  // body
         PyObject *arg4,  // script
         PyObject *arg5,  // path
         PyObject *arg6)  // query
{
    PyObject *request = PyStructSequence_New(&RequestType);
    if (request == NULL) {
        return NULL;
    }
    PyObject *ret = PyStructSequence_New(&RequestType);
    if (ret != NULL) {
        Py_INCREF(arg0);  PyStructSequence_SET_ITEM(ret, 0, arg0);
        Py_INCREF(arg1);  PyStructSequence_SET_ITEM(ret, 1, arg1);
        Py_INCREF(arg2);  PyStructSequence_SET_ITEM(ret, 2, arg2);
        Py_INCREF(arg3);  PyStructSequence_SET_ITEM(ret, 3, arg3);
        Py_INCREF(arg4);  PyStructSequence_SET_ITEM(ret, 4, arg4);
        Py_INCREF(arg5);  PyStructSequence_SET_ITEM(ret, 5, arg5);
        Py_INCREF(arg6);  PyStructSequence_SET_ITEM(ret, 6, arg6);
    }
    return ret;
}

static PyObject *
Request(PyObject *self, PyObject *args)
{
    PyObject *arg0 = NULL;  // method
    PyObject *arg1 = NULL;  // uri
    PyObject *arg2 = NULL;  // headers
    PyObject *arg3 = NULL;  // body
    PyObject *arg4 = NULL;  // script
    PyObject *arg5 = NULL;  // path
    PyObject *arg6 = NULL;  // query

    if (!PyArg_ParseTuple(args, "OOOOOOO:Request",
            &arg0, &arg1, &arg2, &arg3,  &arg4, &arg5, &arg6)) {
        return NULL;
    }
    return _Request(arg0, arg1, arg2, arg3, arg4, arg5, arg6);
}


/* Response namedtuple */
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
_Response(PyObject *arg0, PyObject *arg1, PyObject *arg2, PyObject *arg3)
{
    PyObject *ret = PyStructSequence_New(&ResponseType);
    if (ret != NULL) {
        Py_INCREF(arg0);  PyStructSequence_SET_ITEM(ret, 0, arg0);
        Py_INCREF(arg1);  PyStructSequence_SET_ITEM(ret, 1, arg1);
        Py_INCREF(arg2);  PyStructSequence_SET_ITEM(ret, 2, arg2);
        Py_INCREF(arg3);  PyStructSequence_SET_ITEM(ret, 3, arg3);
    }
    return ret;
}

static PyObject *
Response(PyObject *self, PyObject *args)
{
    PyObject *arg0 = NULL;  // status
    PyObject *arg1 = NULL;  // reason
    PyObject *arg2 = NULL;  // headers
    PyObject *arg3 = NULL;  // body

    if (!PyArg_ParseTuple(args, "OOOO:Response", &arg0, &arg1, &arg2, &arg3)) {
        return NULL;
    }
    return _Response(arg0, arg1, arg2, arg3);
}


/* _init_namedtuple(): initialize one module namedtuple  */
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


/* _init_all_namedtuples(): initialize all module named-tuples */
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


/******************************************************************************
 * Python `int` validation and conversion.
 ******************************************************************************/
static inline bool
_validate_int(const char *name, PyObject *obj)
{
    if (!PyLong_CheckExact(obj)) {
        PyErr_Format(PyExc_TypeError,
            "%s: need a <class 'int'>; got a %R: %R", name, Py_TYPE(obj), obj
        );
        return false;
    }
    return true;
}

static int64_t
_validate_length(const char *name, PyObject *obj)
{
    if (! _validate_int(name, obj)) {
        return -1;
    }
    if (PyErr_Occurred()) {
        Py_FatalError("_validate_length(): PyErr_Occurred()");
    }
    const uint64_t length = PyLong_AsUnsignedLongLong(obj);
    if (PyErr_Occurred() || length > MAX_LENGTH) {
        PyErr_Format(PyExc_ValueError,
            "need 0 <= %s <= %llu; got %R", name, MAX_LENGTH, obj
        );
        return -1;
    }
    return (int64_t)length;
}

static ssize_t
_validate_size(const char *name, PyObject *obj, const size_t max_size)
{
    if (! _validate_int(name, obj)) {
        return -1;
    }
    const size_t size = PyLong_AsSize_t(obj);
    if (PyErr_Occurred() || size > max_size) {
        PyErr_Clear();
        PyErr_Format(PyExc_ValueError,
            "need 0 <= %s <= %zu; got %R", name, max_size, obj
        );
        return -1;
    }
    return (ssize_t)size;
}

static ssize_t
_validate_read_size(const char *name, PyObject *obj, const uint64_t remaining)
{
    if (obj == Py_None) {
        if (remaining > MAX_IO_SIZE) {
            PyErr_Format(PyExc_ValueError,
                "would exceed max read size: %llu > %zu", remaining, MAX_IO_SIZE
            );
            return -1;
        }
        return (ssize_t)remaining;
    }
    return _validate_size(name, obj, MAX_IO_SIZE);
}


/******************************************************************************
 * Helper for clearing DeguHeaders, DeguRequest, DeguResponse, DeguChunk.
 ******************************************************************************/
static void
_clear_degu_headers(DeguHeaders *dh)
{
    Py_CLEAR(dh->headers);
    Py_CLEAR(dh->body);
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
}

static void
_clear_degu_response(DeguResponse *dr)
{
    _clear_degu_headers((DeguHeaders *)dr);
    Py_CLEAR(dr->status);
    Py_CLEAR(dr->reason);
}

static void
_clear_degu_chunk(DeguChunk *dc)
{
    Py_CLEAR(dc->key);
    Py_CLEAR(dc->val);
    Py_CLEAR(dc->data);
    dc->size = 0;
}


/******************************************************************************
 * Range object
 ******************************************************************************/
static PyObject *
Range_New(uint64_t start, uint64_t stop)
{
    Range *self = PyObject_New(Range, &RangeType);
    if (self == NULL) {
        return NULL;
    }
    self->start = start;
    self->stop = stop;
    return (PyObject *)PyObject_INIT(self, &RangeType);
}
 
static void
Range_dealloc(Range *self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Range_init(Range *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"start", "stop", NULL};
    PyObject *arg0 = NULL;
    PyObject *arg1 = NULL;
    int64_t start, stop;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO:Range", keys, &arg0, &arg1)) {
        return -1;
    }
    start = _validate_length("start", arg0);
    if (start < 0) {
        return -1;
    }
    stop = _validate_length("stop", arg1);
    if (stop < 0) {
        return -1;
    }
    if (start >= stop) {
        PyErr_Format(PyExc_ValueError,
            "need start < stop; got %lld >= %lld", start, stop
        );
        return -1;
    }
    self->start = (uint64_t)start;
    self->stop = (uint64_t)stop;
    return 0;
}

static PyObject *
Range_repr(Range *self)
{
    return PyUnicode_FromFormat("Range(%llu, %llu)", self->start, self->stop);
}

static PyObject *
Range_str(Range *self)
{
    return PyUnicode_FromFormat("bytes=%llu-%llu",
        self->start, self->stop - 1
    );
}

static PyObject *
_Range_as_tuple(Range *self)
{
    PyObject *start = NULL;
    PyObject *stop = NULL;
    PyObject *ret = NULL;

    _SET(start, PyLong_FromUnsignedLongLong(self->start))
    _SET(stop, PyLong_FromUnsignedLongLong(self->stop))
    _SET(ret, PyTuple_Pack(2, start, stop))

error:
    Py_CLEAR(start);  // Always cleared, whether or not there was an error
    Py_CLEAR(stop);   // Same as above
    return ret;
}

static PyObject *
Range_richcompare(Range *self, PyObject *other, int op)
{
    PyObject *this = NULL;
    PyObject *ret = NULL;

    if (PyTuple_CheckExact(other) || Py_TYPE(other) == &RangeType) {
        _SET(this, _Range_as_tuple(self))
    }
    else if (PyUnicode_CheckExact(other)) {
        _SET(this, Range_str(self))
    }
    else {
        return Py_NotImplemented;
    }
    _SET(ret, PyObject_RichCompare(this, other, op))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(this);
    return ret;  
}


/*******************************************************************************
 * Internal API: Parsing: Headers:
 *     _parse_key()
 *     _parse_val()
 *     _parse_content_length()
 *     _parse_header_line()
 *     _parse_headers()
 */
static bool
_parse_key(DeguSrc src, DeguDst dst)
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
        r |= dst.buf[i] = _NAME[src.buf[i]];
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
_parse_val(DeguSrc src)
{
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header value is empty");
        return NULL; 
    }
    return _decode(src, VAL_MASK, "bad bytes in header value: %R");
}

static int64_t
_parse_decimal(DeguSrc src)
{
    uint64_t accum;
    uint8_t n, err;
    size_t i;

    if (src.len < 1 || src.len > MAX_CL_LEN) {
        return -1;
    }
    accum = err = _NUMBER[src.buf[0]];
    for (i = 1; i < src.len; i++) {
        n = _NUMBER[src.buf[i]];
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
    return (int64_t)accum;
}

static void
_set_content_length_error(DeguSrc src, const int64_t value)
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

static int64_t
_parse_content_length(DeguSrc src)
{
    const int64_t value = _parse_decimal(src);
    if (value < 0) {
        _set_content_length_error(src, value);
    }
    return value;
}

static PyObject *
parse_content_length(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_content_length", &buf, &len)) {
        return NULL;
    }
    const int64_t value = _parse_content_length((DeguSrc){buf, len});
    if (value < 0) {
        return NULL;
    }
    return PyLong_FromLongLong(value);
}

static PyObject *
_parse_range(DeguSrc src)
{
    ssize_t index;
    int64_t start, end;

    if (src.len < 9 || src.len > 39 || !_equal(_slice(src, 0, 6), BYTES_EQ)) {
        goto bad_range;
    }
    DeguSrc inner = _slice(src, 6, src.len);
    index = _find(inner, MINUS);
    if (index < 1) {
        goto bad_range;
    }
    start = _parse_decimal(_slice(inner, 0, (size_t)index));
    end = _parse_decimal(_slice(inner, (size_t)index + 1, inner.len));
    if (start < 0 || end < start || (uint64_t)end >= MAX_LENGTH) {
        goto bad_range;
    }
    return Range_New((uint64_t)start, (uint64_t)end + 1);

bad_range:
    _value_error("bad range: %R", src);
    return NULL;
}

static bool
_parse_header_line(DeguSrc src, DeguDst scratch, DeguHeaders *dh)
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
    DeguSrc rawkey = _slice(src, 0, keystop);
    DeguSrc valsrc = _slice(src, valstart, src.len);
    if (! _parse_key(rawkey, scratch)) {
        goto error;
    }
    DeguSrc keysrc = {scratch.buf, rawkey.len};

    /* Validate header value (with special handling and fast-paths) */
    if (_equal(keysrc, CONTENT_LENGTH)) {
        int64_t length = _parse_content_length(valsrc);
        if (length < 0) {
            goto error;
        }
        dh->content_length = (uint64_t)length;
        dh->flags |= 1;
        _SET_AND_INC(key, key_content_length)
        _SET(val, PyLong_FromUnsignedLongLong(dh->content_length))
    }
    else if (_equal(keysrc, TRANSFER_ENCODING)) {
        if (! _equal(valsrc, CHUNKED)) {
            _value_error("bad transfer-encoding: %R", valsrc);
            goto error;
        }
        _SET_AND_INC(key, key_transfer_encoding)
        _SET_AND_INC(val, val_chunked)
        dh->flags |= 2;
    }
    else if (_equal(keysrc, RANGE)) {
        _SET_AND_INC(key, key_range)
        _SET(val, _parse_range(valsrc))
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
_parse_headers(DeguSrc src, DeguDst scratch, DeguHeaders *dh)
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
_parse_method(DeguSrc src)
{
    PyObject *method = NULL;
    if (_equal(src, GET)) {
        method = str_GET;
    }
    else if (_equal(src, PUT)) {
        method = str_PUT;
    }
    if (_equal(src, POST)) {
        method = str_POST;
    }
    else if (_equal(src, HEAD)) {
        method = str_HEAD;
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
_parse_path_component(DeguSrc src)
{
    return _decode(src, PATH_MASK, "bad bytes in path component: %R");
}

static PyObject *
_parse_path(DeguSrc src)
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
_parse_query(DeguSrc src)
{
    return _decode(src, QUERY_MASK, "bad bytes in query: %R");
}

static bool
_parse_uri(DeguSrc src, DeguRequest *dr)
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
_parse_request_line(DeguSrc line, DeguRequest *dr)
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
    DeguSrc protocol = _slice(line, line.len - 9, line.len);
    if (! _equal(protocol, REQUEST_PROTOCOL)) {
        _value_error("bad protocol in request line: %R", protocol);
        goto error;
    }

    /* Now we'll work with line[0:-9]
     *     "GET / HTTP/1.1"[0:-9]
     *      ^^^^^
     */
    DeguSrc src = _slice(line, 0, line.len - protocol.len);

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
    DeguSrc method_src = _slice(src, 0, method_stop);
    DeguSrc uri_src = _slice(src, uri_start, src.len);

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
_create_body(PyObject *rfile, DeguHeaders *dh) 
{
    const uint8_t bodyflags = (dh->flags & 3);
    if (bodyflags == 0) {
        _SET_AND_INC(dh->body, Py_None)
    }
    else if (bodyflags == 1) {
        _SET(dh->body, Body_New(rfile, dh->content_length))
    }
    else if (bodyflags == 2) {
        _SET(dh->body, ChunkedBody_New(rfile))
    }
    return true;

error:
    return false;
}

static PyObject *
_parse_request(DeguSrc src, PyObject *rfile, DeguDst scratch)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    PyObject *ret = NULL;

    /* Check for empty premable */
    if (src.len == 0) {
        PyErr_SetString(EmptyPreambleError, "request preamble is empty");
        goto error;
    }

    /* Parse request preamble */
    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguSrc line_src = _slice(src, 0, stop);
    DeguSrc headers_src = _slice(src, start, src.len);
    if (!_parse_request_line(line_src, &dr)) {
        goto error;
    }
    if (!_parse_headers(headers_src, scratch, (DeguHeaders *)&dr)) {
        goto error;
    }
    /* Create request body */
    if (!_create_body(rfile, (DeguHeaders *)&dr)) {
        goto error;
    }

    /* Create Response namedtuple */
    _SET(ret,
        _Request(
            dr.method, dr.uri, dr.headers, dr.body, dr.script, dr.path, dr.query
        )
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
    DeguSrc src = {buf, len};
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
    PyObject *rfile = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "y#O:parse_request", &buf, &len, &rfile)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguDst scratch = _calloc_dst(MAX_KEY);
    if (scratch.buf == NULL) {
        return NULL;
    }
    _SET(ret, _parse_request(src, rfile, scratch))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    if (scratch.buf != NULL) {
        free(scratch.buf);
    }
    return ret;
}


/*******************************************************************************
 * Internal API: Parsing: Response:
 *     _parse_status()
 *     _parse_reason()
 *     _parse_response_line()
 *     _parse_response()
 */
static inline PyObject *
_parse_status(DeguSrc src)
{
    uint8_t n, err;
    unsigned long accum;

    if (src.len != 3) {
        _value_error("bad status length: %R", src);
        return NULL;
    }
    n = _NUMBER[src.buf[0]];  err  = n;  accum   = n * 100u;
    n = _NUMBER[src.buf[1]];  err |= n;  accum  += n * 10u;
    n = _NUMBER[src.buf[2]];  err |= n;  accum  += n;
    if ((err & 240) != 0 || accum < 100 || accum > 599) {
        _value_error("bad status: %R", src);
        return NULL;
    }
    return PyLong_FromUnsignedLong(accum);
}

static inline PyObject *
_parse_reason(DeguSrc src)
{
    if (_equal(src, OK)) {
        Py_XINCREF(str_OK);
        return str_OK;
    }
    return _decode(src, REASON_MASK, "bad reason: %R");
}

static bool
_parse_response_line(DeguSrc src, DeguResponse *dr)
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
    DeguSrc pcol = _slice(src, 0, 9);
    DeguSrc sp = _slice(src, 12, 13);
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

static PyObject *
_parse_response(DeguSrc method, DeguSrc src, PyObject *rfile, DeguDst scratch)
{
    DeguResponse dr = NEW_DEGU_RESPONSE;
    PyObject *m = NULL; 
    PyObject *ret = NULL;

    _SET(m, _parse_method(method))
    if (src.len == 0) {
        PyErr_SetString(EmptyPreambleError, "response preamble is empty");
        goto error;
    }

    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguSrc line_src = _slice(src, 0, stop);
    DeguSrc headers_src = _slice(src, start, src.len);
    if (!_parse_response_line(line_src, &dr)) {
        goto error;
    }
    if (!_parse_headers(headers_src, scratch, (DeguHeaders *)&dr)) {
        goto error;
    }
    /* Create request body */
    if (m == str_HEAD) {
        _SET_AND_INC(dr.body, Py_None);
    }
    else if (!_create_body(rfile, (DeguHeaders *)&dr)) {
        goto error;
    }

    /* Create namedtuple */
    _SET(ret, _Response(dr.status, dr.reason, dr.headers, dr.body))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(m);
    _clear_degu_response(&dr);
    return ret;
    
}


/******************************************************************************
 * Chunk line parsing.
 ******************************************************************************/
static bool
_parse_chunk_size(DeguSrc src, DeguChunk *dc)
{
    size_t accum;
    uint8_t n, err;
    size_t i;

    if (src.len > 7) {
        _value_error("chunk_size is too long: %R...", _slice(src, 0, 7));
        return false;
    }
    if (src.len < 1 || (src.buf[0] == 48 && src.len != 1)) {
        goto bad_chunk_size;
    }
    accum = err = _NUMBER[src.buf[0]] & 239;
    for (i = 1; i < src.len; i++) {
        n = _NUMBER[src.buf[i]] & 239;
        err |= n;
        accum *= 16;
        accum += n;
    }
    if ((err & 240) != 0) {
        goto bad_chunk_size;
    }
    if (accum > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "need chunk_size <= %zu; got %zu", MAX_IO_SIZE, accum
        );
        return false;
    }
    dc->size = accum;
    return true;

bad_chunk_size:
    _value_error("bad chunk_size: %R", src);
    return false;
}

static PyObject *
parse_chunk_size(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_chunk_size", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguChunk dc = NEW_DEGU_CHUNK;
    if (! _parse_chunk_size(src, &dc)) {
        return NULL;
    }
    return PyLong_FromSize_t(dc.size);
}

static inline PyObject *
_parse_chunk_extkey(DeguSrc src)
{
    return _decode(src, EXTKEY_MASK, "bad chunk extension key: %R");
}

static inline PyObject *
_parse_chunk_extval(DeguSrc src)
{
    return _decode(src, EXTVAL_MASK, "bad chunk extension value: %R");
}

static bool
_parse_chunk_ext(DeguSrc src, DeguChunk *dc)
{
    ssize_t index;
    size_t key_stop, val_start;

    if (src.len < 3) {
        goto bad_chunk_ext;
    }
    index = _find(src, EQUALS);
    if (index < 0) {
        goto bad_chunk_ext;
    }
    key_stop = (size_t)index;
    val_start = key_stop + EQUALS.len;
    DeguSrc keysrc = _slice(src, 0, key_stop);
    DeguSrc valsrc = _slice(src, val_start, src.len);
    if (keysrc.len == 0 || valsrc.len == 0) {
        goto bad_chunk_ext;
    }
    _SET(dc->key, _parse_chunk_extkey(keysrc))
    _SET(dc->val, _parse_chunk_extval(valsrc))
    return true;

error:
    return false;

bad_chunk_ext:
    _value_error("bad chunk extension: %R", src);
    return false;
}

static PyObject *
parse_chunk_extension(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "y#:parse_chunk_extension", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguChunk dc = NEW_DEGU_CHUNK;
    if (_parse_chunk_ext(src, &dc)) {
        ret = PyTuple_Pack(2, dc.key, dc.val);
    }
    _clear_degu_chunk(&dc);
    return ret;
}

static bool
_parse_chunk(DeguSrc src, DeguChunk *dc)
{
    size_t size_stop, ext_start;

    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "b'\\r\\n' not found in b''...");
        return false;
    }
    size_stop = _search(src, SEMICOLON);
    DeguSrc size_src = _slice(src, 0, size_stop);
    if (! _parse_chunk_size(size_src, dc)) {
        return false;
    }
    if (size_stop < src.len) {
        ext_start = size_stop + SEMICOLON.len;
        DeguSrc ext_src = _slice(src, ext_start, src.len);
        if (! _parse_chunk_ext(ext_src, dc)) {
            return false;
        }
    }
    return true;
}

static PyObject *
parse_chunk(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *size = NULL;
    PyObject *ext = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "y#:parse_chunk", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguChunk dc = NEW_DEGU_CHUNK;
    if (! _parse_chunk(src, &dc)) {
        goto error;
    }
    _SET(size, PyLong_FromSize_t(dc.size))
    if (dc.key == NULL && dc.val == NULL) {
        _SET_AND_INC(ext, Py_None)
    }
    else {
        if (dc.key == NULL || dc.val == NULL) {
            Py_FatalError("parse_chunk(): dc.key == NULL || dc.val == NULL");
        }
        _SET(ext, PyTuple_Pack(2, dc.key, dc.val))
    }
    if (size == NULL || ext == NULL) {
        Py_FatalError("parse_chunk(): size == NULL || ext == NULL");
    }
    _SET(ret, PyTuple_Pack(2, size, ext))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(size);
    Py_CLEAR(ext);
    _clear_degu_chunk(&dc);
    return ret;
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
    uint8_t bits;

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
    for (bits = i = 0; i < key_len; i++) {
        bits |= _FLAG[key_buf[i]];
    }
    if (bits == 0) {
        Py_FatalError("_validate_key(): bits == 0");
    }
    if ((bits & KEY_MASK) != 0) {
        goto bad_key;
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
_format_request(DeguSrc method_src, PyObject *uri, PyObject *headers)
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
    DeguSrc src = {buf, len};
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return NULL;
    }
    if (src.len > MAX_KEY) {
        _value_error("header name too long: %R...",  _slice(src, 0, MAX_KEY));
        return NULL;
    }
    _SET(ret, PyUnicode_New((ssize_t)src.len, 127))
    DeguDst dst = {PyUnicode_1BYTE_DATA(ret), src.len};
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
parse_range(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (!PyArg_ParseTuple(args, "y#:parse_range", &buf, &len)) {
        return NULL;
    }
    return _parse_range((DeguSrc){buf, len});
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
    DeguSrc src = {buf, len};
    DeguDst dst = _calloc_dst(MAX_KEY);
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
    return _parse_method((DeguSrc){buf, len});
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
    DeguSrc src = {buf, len};
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
    DeguSrc src = {buf, len};
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
    const uint8_t *method_buf = NULL;
    size_t method_len = 0;
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *rfile = NULL;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "s#y#O:parse_response",
            &method_buf, &method_len, &buf, &len, &rfile)) {
        return NULL;
    }
    DeguSrc method = {method_buf, method_len};
    DeguSrc src = {buf, len};
    DeguDst scratch = _calloc_dst(MAX_KEY);
    if (scratch.buf == NULL) {
        return NULL;
    }
    _SET(ret, _parse_response(method, src, rfile, scratch))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    if (scratch.buf != NULL) {
        free(scratch.buf);
    }
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
    DeguSrc method_src = {buf, len};
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

static PyObject *
_format_chunk(DeguChunk *dc)
{
    PyObject *str = NULL;
    PyObject *bytes = NULL;

    if (dc->key == NULL && dc->val == NULL) {
        _SET(str, PyUnicode_FromFormat("%x\r\n", dc->size))
    }
    else {
        if (dc->key == NULL || dc->val == NULL) {
            Py_FatalError("_format_chunk(): bad internal call");
        }
        _SET(str,
            PyUnicode_FromFormat("%x;%S=%S\r\n", dc->size, dc->key, dc->val)
        )
    }
    _SET(bytes, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(bytes);

cleanup:
    Py_CLEAR(str);
    return bytes;
}

static bool
_unpack_chunk(DeguChunk *dc, PyObject *chunk)
{
    if (chunk == NULL || dc->key != NULL || dc->val != NULL || dc->data != NULL || dc->size != 0) {
        Py_FatalError("_unpack_chunk(): bad internal call");
    }
    PyObject *ext = NULL;
    bool ret = true;

    /* chunk itself */
    if (! PyTuple_CheckExact(chunk)) {
        PyErr_Format(PyExc_TypeError,
            "chunk must be a <class 'tuple'>; got a %R", Py_TYPE(chunk)
        );
        goto error;
    }
    if (PyTuple_GET_SIZE(chunk) != 2) {
        PyErr_Format(PyExc_ValueError,
            "chunk must be a 2-tuple; got a %zd-tuple", PyTuple_GET_SIZE(chunk)
        );
        goto error;
    }

    /* chunk[0]: extension */
    _SET(ext, PyTuple_GET_ITEM(chunk, 0))
    if (ext != Py_None) {
        if (! PyTuple_CheckExact(ext)) {
            PyErr_Format(PyExc_TypeError,
                "chunk[0] must be a <class 'tuple'>; got a %R",
                Py_TYPE(ext)
            );
            goto error;
        }
        if (PyTuple_GET_SIZE(ext) != 2) {
            PyErr_Format(PyExc_ValueError,
                "chunk[0] must be a 2-tuple; got a %zd-tuple",
                PyTuple_GET_SIZE(ext)
            );
            goto error;
        }
        _SET_AND_INC(dc->key, PyTuple_GET_ITEM(ext, 0))
        _SET_AND_INC(dc->val, PyTuple_GET_ITEM(ext, 1))
    }

    /* chunk[1]: data */
    _SET_AND_INC(dc->data, PyTuple_GET_ITEM(chunk, 1))
    if (! PyBytes_CheckExact(dc->data)) {
        PyErr_Format(PyExc_TypeError,
            "chunk[1] must be a <class 'bytes'>; got a %R", Py_TYPE(dc->data)
        );
        goto error;
    }
    dc->size = (size_t)PyBytes_GET_SIZE(dc->data);
    if (dc->size > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "need len(chunk[1]) <= %zu; got %zu", MAX_IO_SIZE, dc->size
        );
        goto error;
    }
    goto cleanup;

error:
    ret = false;
    _clear_degu_chunk(dc);

cleanup:
    return ret;
}

static PyObject *
_pack_chunk(DeguChunk *dc)
{
    PyObject *ext = NULL;
    PyObject *ret = NULL;

    if (dc->data == NULL || ! PyBytes_CheckExact(dc->data)) {
        Py_FatalError("_pack_chunk(): bad internal call");
    }
    if (PyBytes_GET_SIZE(dc->data) == (ssize_t)dc->size + 2) {
        if (_PyBytes_Resize(&(dc->data), (ssize_t)dc->size) != 0) {
            goto error;
        }
    }
    if (PyBytes_GET_SIZE(dc->data) != (ssize_t)dc->size) {
        Py_FatalError("_pack_chunk(): bad internal call");
    }   
    if (dc->key == NULL && dc->val == NULL) {
        _SET_AND_INC(ext, Py_None)
    }
    else {
        if (dc->key == NULL || dc->val == NULL) {
            Py_FatalError("parse_chunk(): dc->key == NULL || dc->val == NULL");
        }
        _SET(ext, PyTuple_Pack(2, dc->key, dc->val))
    }
    _SET(ret, PyTuple_Pack(2, ext, dc->data))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(ext);
    return ret;
}

static PyObject *
format_chunk(PyObject *self, PyObject *args)
{
    PyObject *chunk = NULL;

    DeguChunk dc = NEW_DEGU_CHUNK;

    if (!PyArg_ParseTuple(args, "O:format_chunk", &chunk)) {
        return NULL;
    }
    if (! _unpack_chunk(&dc, chunk)) {
        return NULL;
    }
    return _format_chunk(&dc);
}

/******************************************************************************
 * Helper for calling sock.recv_into(), rfile.readinto().
 ******************************************************************************/
static inline ssize_t
_recv_into(PyObject *method, DeguDst dst)
{
    PyObject *view = NULL;
    PyObject *int_size = NULL;
    ssize_t size = -2;

    if (_dst_isempty(dst) || dst.len > MAX_IO_SIZE) {
        Py_FatalError("_recv_into(): bad internal call");
    }
    _SET(view,
        PyMemoryView_FromMemory((char *)dst.buf, (ssize_t)dst.len, PyBUF_WRITE)
    )
    _SET(int_size, PyObject_CallFunctionObjArgs(method, view, NULL))
    size = _validate_size("received", int_size, dst.len);
    goto cleanup;

error:
    size = -1;

cleanup:
    Py_CLEAR(view);
    Py_CLEAR(int_size);
    return size;
}

static bool
_readinto(PyObject *method, DeguDst dst)
{
    size_t start = 0;
    ssize_t received;

    while (start < dst.len) {
        received = _recv_into(method, _dst_slice(dst, start, dst.len));
        if (received < 0) {
            return false;
        }
        if (received == 0) {
            break;
        }
        start += (size_t)received;
    }
    if (start != dst.len) {
        PyErr_Format(PyExc_ValueError,
            "expected to read %zu bytes, but received %zu", dst.len, start
        );
        return false;
    }
    return true;
}

static bool
_readinto_from(PyObject *robj, DeguDst dst)
{
    if (Py_TYPE(robj) == &ReaderType) {
        return _Reader_readinto((Reader *)robj, dst);
    }
    return _readinto(robj, dst);
}

static inline ssize_t
_send(PyObject *method, DeguSrc src)
{
    PyObject *view = NULL;
    PyObject *int_size = NULL;
    ssize_t size = -2;

    if (_isempty(src) || src.len > MAX_IO_SIZE) {
        Py_FatalError("_send(): bad internal call");
    }
    _SET(view,
        PyMemoryView_FromMemory((char *)src.buf, (ssize_t)src.len, PyBUF_READ)
    )
    _SET(int_size, PyObject_CallFunctionObjArgs(method, view, NULL))
    size = _validate_size("sent", int_size, src.len);
    goto cleanup;

error:
    size = -1;

cleanup:
    Py_CLEAR(view);
    Py_CLEAR(int_size);
    return size;
}

static ssize_t
_write(PyObject *method, DeguSrc src)
{
    size_t start = 0;
    ssize_t sent;

    while (start < src.len) {
        sent = _send(method, _slice(src, start, src.len));
        if (sent < 0) {
            return -1;
        }
        if (sent == 0) {
            break;
        }
        start += (size_t)sent;
    }
    if (start != src.len) {
        PyErr_Format(PyExc_ValueError,
            "expected to write %zu bytes, but sent %zu", src.len, start
        );
        return -2;
    }
    return (ssize_t)start;
}

static ssize_t
_write_to(PyObject *wobj, DeguSrc src)
{
    if (Py_TYPE(wobj) == &WriterType) {
        return _Writer_write((Writer *)wobj, src);
    }
    return _write(wobj, src);
}


static bool
_readchunkline(PyObject *readline, DeguChunk *dc)
{
    if (readline == NULL) {
        Py_FatalError("_readchunkline(): bad internal call");
    }
    if (dc->key != NULL || dc->val != NULL || dc->data != NULL || dc->size != 0) {
        Py_FatalError("_readchunkline(): also bad internal call");
    }

    PyObject *line = NULL;
    bool success = true;

    /* Read and parse chunk line */
    _SET(line, PyObject_CallFunctionObjArgs(readline, int_MAX_LINE_SIZE, NULL))
    if (! PyBytes_CheckExact(line)) {
        PyErr_Format(PyExc_TypeError,
            "need a <class 'bytes'>; readline() returned a %R", Py_TYPE(line)
        );
        goto error;
    }
    DeguSrc src = _frombytes(line);
    if (src.len > _MAX_LINE_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "readline() returned too many bytes: %zu > %zu",
            src.len, _MAX_LINE_SIZE
        );
        goto error;
    }
    if (src.len < 2 || !_equal(_slice(src, src.len - 2, src.len), CRLF)) {
        if (src.len == 0) {
            _value_error("%R not found in b''...", CRLF);
        }
        else {
            _value_error2("%R not found in %R...",
                CRLF, _slice(src, 0, _min(src.len, 32))
            );
        }
        goto error;
    }
    if (! _parse_chunk(_slice(src, 0, src.len - 2), dc)) {
        goto error;
    }

    goto cleanup;

error:
    success = false;

cleanup:
    Py_CLEAR(line);
    return success;
}

static bool
_readchunk_from(PyObject *robj, PyObject *readline, DeguChunk *dc)
{

    if (Py_TYPE(robj) == &ReaderType) {
        if (! _Reader_readchunkline((Reader *)robj, dc)) {
            goto error;
        }
    }
    else {
        if (! _readchunkline(readline, dc)) {
            goto error;
        }
    }

    const ssize_t size = (ssize_t)dc->size + 2;
    _SET(dc->data, PyBytes_FromStringAndSize(NULL, size))
    DeguDst dst = _dst_frombytes(dc->data);
    if (! _readinto_from(robj, dst)) {
        goto error;
    }
    DeguSrc end = _slice_src_from_dst(dst, dst.len - 2, dst.len);
    if (! _equal(end, CRLF)) {
        _value_error("bad chunk data termination: %R", end);
        goto error;
    }
    return true;

error:
    _clear_degu_chunk(dc);
    return false;
}

static PyObject *
_get_robj(PyObject *rfile)
{
    PyObject *robj = NULL;

    if (Py_TYPE(rfile) == &ReaderType) {
        _SET_AND_INC(robj, rfile)
    }
    else {
        _SET(robj, _getcallable("rfile", rfile, attr_readinto))
    }
    return robj;

error:
    Py_CLEAR(robj);
    return robj;
}

static PyObject *
_get_readline(PyObject *rfile)
{
    PyObject *robj = NULL;

    if (Py_TYPE(rfile) == &ReaderType) {
        _SET_AND_INC(robj, rfile)
    }
    else {
        _SET(robj, _getcallable("rfile", rfile, attr_readline))
    }
    return robj;

error:
    Py_CLEAR(robj);
    return robj;
}

static PyObject *
_get_wobj(PyObject *wfile)
{
    PyObject *wobj = NULL;

    if (Py_TYPE(wfile) == &WriterType) {
        _SET_AND_INC(wobj, wfile)
    }
    else {
        _SET(wobj, _getcallable("wfile", wfile, attr_write))
    }
    return wobj;

error:
    Py_CLEAR(wobj);
    return wobj;
}

static PyObject *
readchunk(PyObject *self, PyObject *args)
{
    PyObject *rfile = NULL;
    PyObject *robj = NULL;
    PyObject *readline = NULL;
    PyObject *ret = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;

    if (!PyArg_ParseTuple(args, "O:readchunk", &rfile)) {
        return NULL;
    }
    _SET(robj, _get_robj(rfile))
    _SET(readline, _get_readline(rfile))
    if (! _readchunk_from(robj, readline, &dc)) {
        goto error;
    }
    _SET(ret, _pack_chunk(&dc))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_chunk(&dc);
    Py_CLEAR(robj);
    Py_CLEAR(readline);
    return ret;
}

static ssize_t
_writechunk_to(PyObject *wobj, DeguChunk *dc)
{
    PyObject *line = NULL;
    ssize_t total = 0;
    ssize_t wrote;

    _SET(line, _format_chunk(dc))
    DeguSrc src = _frombytes(line);
    wrote = _write_to(wobj, src);
    if (wrote < 0) {
        goto error;
    }
    total += wrote;

    DeguSrc data = _frombytes(dc->data);
    if (data.len > 0) {
        wrote = _write_to(wobj, data);
        if (wrote < 0) {
            goto error;
        }
        total += wrote;
    }

    if (data.len == dc->size) {
        wrote = _write_to(wobj, CRLF);
        if (wrote < 0) {
            goto error;
        }
        total += wrote;  
    }
    else if (data.len != dc->size + 2) {
        Py_FatalError("_write_chunk(): also bad internal call");
    }
    goto cleanup;

error:
    total = -1;

cleanup:
    Py_CLEAR(line);
    return total;
}

static PyObject *
write_chunk(PyObject *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *chunk = NULL;
    PyObject *wobj = NULL;
    PyObject *ret = NULL;
    ssize_t total;
    DeguChunk dc = NEW_DEGU_CHUNK;

    if (!PyArg_ParseTuple(args, "OO:write_chunk", &wfile, &chunk)) {
        return NULL;
    }
    _SET(wobj, _get_wobj(wfile))
    if (! _unpack_chunk(&dc, chunk)) {
        goto error;
    }
    total = _writechunk_to(wobj, &dc);
    if (total < 0) {
        goto error;
    }
    _SET(ret, PyLong_FromSsize_t(total))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(wobj);
    _clear_degu_chunk(&dc);
    return ret;
}


/******************************************************************************
 * Reader object
 ******************************************************************************/
static void
Reader_dealloc(Reader *self)
{
    Py_CLEAR(self->recv_into);
    if (self->scratch != NULL) {
        free(self->scratch);
        self->scratch = NULL;
    }
    if (self->buf != NULL) {
        free(self->buf);
        self->buf = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);  // Oops, make sure to do this!
}

static int
Reader_init(Reader *self, PyObject *args, PyObject *kw)
{
    PyObject *sock = NULL;
    ssize_t len = DEFAULT_PREAMBLE;
    static char *keys[] = {"sock", "size", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kw, "O|n:Reader", keys, &sock,  &len)) {
        return -1;
    }
    if (len < MIN_PREAMBLE || len > MAX_PREAMBLE) {
        PyErr_Format(PyExc_ValueError,
            "need %zd <= size <= %zd; got %zd",
            MIN_PREAMBLE, MAX_PREAMBLE, len
        );
        return -1;
    }
    _SET(self->recv_into, _getcallable("sock", sock, attr_recv_into))
    _SET(self->scratch, _calloc_buf(MAX_KEY))
    self->len = (size_t)len;
    _SET(self->buf, _calloc_buf(self->len))
    self->rawtell = 0;
    self->start = 0;
    self->stop = 0;
    self->closed = false;
    return 0;

error:
    return -1;
}

static DeguSrc
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
    return (DeguSrc){cur_buf, _min(size, cur_len)};
}

static DeguSrc
_Reader_drain(Reader *self, const size_t size)
{
    DeguSrc cur = _Reader_peek(self, size);
    self->start += cur.len;
    if (self->start == self->stop) {
        self->start = 0;
        self->stop = 0;
    }
    return  cur;
}

static DeguSrc
_Reader_read_until(Reader *self, const size_t size, DeguSrc end,
                   const bool readline)
{
    ssize_t index = -1;
    ssize_t added;

    if (_isempty(end)) {
        Py_FatalError("_Reader_read_until(): bad internal call");
    }
    DeguDst dst = {self->buf, self->len};
    if (size < end.len || size > dst.len) {
        PyErr_Format(PyExc_ValueError,
            "need %zu <= size <= %zu; got %zd", end.len, dst.len, size
        );
        return NULL_DeguSrc;
    }

    /* First, see if end is in the current buffer content */
    DeguSrc cur = _Reader_peek(self, size);
    if (cur.len >= end.len) {
        index = _find(cur, end);
        if (index >= 0) {
            goto found;
        }
        if (cur.len >= size) {
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
        added = _recv_into(self->recv_into, _dst_slice(dst, self->stop, dst.len));
        if (added < 0) {
            return NULL_DeguSrc;
        }
        if (added == 0) {
            break;
        }
        self->stop += (size_t)added;
        self->rawtell += (uint64_t)added;
        index = _find(_Reader_peek(self, size), end);
        if (index >= 0) {
            goto found;
        }
    }

not_found:
    if (index >= 0) {
        Py_FatalError("_Reader_read_until(): not_found, but index >= 0");
    }
    if (readline) {
        return _Reader_drain(self, size);
    }
    DeguSrc tmp = _Reader_peek(self, size);
    if (tmp.len == 0) {
        return tmp;
    }
    _value_error2(
        "%R not found in %R...", end, _slice(tmp, 0, _min(tmp.len, 32))
    );
    return NULL_DeguSrc;

found:
    if (index < 0) {
        Py_FatalError("_Reader_read_until(): found, but index < 0");
    }
    DeguSrc src = _Reader_drain(self, (size_t)index + end.len);
    if (readline) {
        return src;
    }
    return _slice(src, 0, src.len - end.len);
}

static bool
_Reader_readinto(Reader *self, DeguDst dst)
{
    DeguSrc cur = _Reader_drain(self, dst.len);
    if (cur.len > 0) {
        _copy(dst, cur);
    }
    if (_readinto(self->recv_into, _dst_slice(dst, cur.len, dst.len))) {
        self->rawtell += dst.len;
        return true;
    }
    return false;
}

static PyObject *
_Reader_read(Reader *self, const ssize_t size)
{
    PyObject *ret = NULL;

    if (size < 0 || size > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "need 0 <= size <= %zu; got %zd", MAX_IO_SIZE, size
        );
        return NULL;
    }
    if (size == 0) {
        _SET_AND_INC(ret, bytes_empty)
        goto cleanup;
    }
    _SET(ret, PyBytes_FromStringAndSize(NULL, size))
    DeguDst dst = _dst_frombytes(ret);
    if (! _Reader_readinto(self, dst)) {
        goto error;
    }
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    return ret;
}

static PyObject *
Reader_rawtell(Reader *self) {
    return PyLong_FromUnsignedLongLong(self->rawtell);
}

static PyObject *
Reader_tell(Reader *self) {
    DeguSrc cur = _Reader_peek(self, self->len);
    if (cur.len > self->rawtell) {
        Py_FatalError("Reader_tell(): cur.len > self->rawtell");
    }
    return PyLong_FromUnsignedLongLong(self->rawtell - cur.len);
}

static PyObject *
Reader_expose(Reader *self) {
    DeguSrc rawbuf = {self->buf, self->len};
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
Reader_read_until(Reader *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"size", "end", "readline", NULL};
    size_t size = 0;
    uint8_t *buf = NULL;
    size_t len = 0;
    int readline = false;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "ny#|p:read_until", keys,
            &size, &buf, &len, &readline)) {
        return NULL;
    }
    DeguSrc end = {buf, len};
    if (end.len == 0) {
        PyErr_SetString(PyExc_ValueError, "end cannot be empty");
        return NULL;
    }
    return _tobytes(_Reader_read_until(self, size, end, readline));
}

static PyObject *
Reader_readline(Reader *self, PyObject *args)
{
    size_t size = 0;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_read_until(self, size, LF, true));
}

static PyObject *
Reader_read_request(Reader *self) {
    PyObject *ret = NULL;

    DeguSrc src = _Reader_read_until(self, self->len, CRLFCRLF, false);
    if (src.buf == NULL) {
        goto error;
    }
    DeguDst scratch = {self->scratch, MAX_KEY};
    _SET(ret, _parse_request(src, (PyObject *)self, scratch))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    return ret;
}


static PyObject *
Reader_read_response(Reader *self, PyObject *args)
{
    const uint8_t *method_buf = NULL;
    size_t method_len = 0;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "s#:read_response", &method_buf, &method_len)) {
        return NULL;
    }
    DeguSrc method = {method_buf, method_len};
    DeguSrc src = _Reader_read_until(self, self->len, CRLFCRLF, false);
    if (src.buf == NULL) {
        goto error;
    }
    DeguDst scratch = {self->scratch, MAX_KEY};
    _SET(ret, _parse_response(method, src, (PyObject *)self, scratch))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    return ret;
}

static bool
_Reader_readchunkline(Reader *self, DeguChunk *dc) {
    DeguSrc line = _Reader_read_until(self, 4096, CRLF, false);
    if (line.buf == NULL) {
        goto error;
    }
    if (! _parse_chunk(line, dc)) {
        goto error;
    }
    return true;

error:
    return false;
}

static PyObject *
Reader_readchunk(Reader *self)
{
    PyObject *ret = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;

    if (_readchunk_from((PyObject *)self, NULL, &dc)) {
        ret =  _pack_chunk(&dc);
    }
    _clear_degu_chunk(&dc);
    return ret;
}

static PyObject *
Reader_read(Reader *self, PyObject *args)
{
    ssize_t size = -1;
    if (!PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _Reader_read(self, size);
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
    DeguDst dst = _dst_frompybuf(&pybuf);
    if (! _Reader_readinto(self, dst)) {
        goto error;
    }
    _SET(ret, PyLong_FromSize_t(dst.len))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    PyBuffer_Release(&pybuf);
    return ret;
}


/******************************************************************************
 * Writer object.
 ******************************************************************************/
static void
Writer_dealloc(Writer *self)
{
    Py_CLEAR(self->send);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Writer_init(Writer *self, PyObject *args, PyObject *kw)
{
    int ret = 0;
    PyObject *sock = NULL;
    static char *keys[] = {"sock", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "O:Writer", keys, &sock)) {
        goto error;
    }
    self->tell = 0;
    _SET(self->send,      _getcallable("sock", sock, attr_send))
    goto cleanup;

error:
    ret = -1;

cleanup:
    return ret;
}

static ssize_t
_Writer_write(Writer *self, DeguSrc src)
{
    const ssize_t wrote = _write(self->send, src);
    if (wrote > 0) {
        self->tell += (uint64_t)wrote;
    }
    return wrote;
}

static bool
_set_content_length(PyObject *headers, const uint64_t content_length)
{
    PyObject *val = PyLong_FromUnsignedLongLong(content_length);
    if (val == NULL) {
        return false;
    }
    const bool result = _set_default_header(headers, key_content_length, val);
    Py_CLEAR(val);
    return result;
}

static bool
_set_transfer_encoding(PyObject *headers)
{
    return _set_default_header(headers, key_transfer_encoding, val_chunked);
}

static bool
_set_output_headers(PyObject *headers, PyObject *body)
{
    if (body == Py_None) {
        return true;
    }
    if (PyBytes_CheckExact(body)) {
        return _set_content_length(headers, (uint64_t)PyBytes_GET_SIZE(body));
    }
    if (Py_TYPE(body) == &BodyType) {
        return _set_content_length(headers, ((Body *)body)->content_length);
    }
    if (Py_TYPE(body) == &BodyIterType) {
        return _set_content_length(headers, ((BodyIter *)body)->content_length);
    }
    if (Py_TYPE(body) == &ChunkedBodyType) {
        return _set_transfer_encoding(headers);
    }
    if (Py_TYPE(body) == &ChunkedBodyIterType) {
        return _set_transfer_encoding(headers);
    }
    PyErr_Format(PyExc_TypeError, "bad body type: %R: %R", Py_TYPE(body), body);
    return false;
}

static PyObject *
set_output_headers(PyObject *self, PyObject *args)
{
    PyObject *headers = NULL;
    PyObject *body = NULL;

    if (!PyArg_ParseTuple(args, "OO:set_output_headers", &headers, &body)) {
        return NULL;
    }
    if (! _set_output_headers(headers, body)) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static int64_t
_Writer_write_combined(Writer *self, DeguSrc src1, DeguSrc src2)
{
    const size_t len = src1.len + src2.len;
    if (len == 0) {
        return 0;
    }
    DeguDst dst = _calloc_dst(len);
    if (dst.buf == NULL) {
        return -1;
    }
    _copy(dst, src1);
    _copy(_dst_slice(dst, src1.len, dst.len), src2);
    const int64_t wrote = _Writer_write(self, (DeguSrc){dst.buf, dst.len});
    free(dst.buf);
    return wrote;
}


static int64_t
_Writer_write_output(Writer *self, DeguSrc preamble, PyObject *body)
{
    if (PyBytes_CheckExact(body)) {
        return _Writer_write_combined(self, preamble, _frombytes(body));
    }

    const uint64_t origtell = self->tell;
    uint64_t total = 0;
    int64_t wrote;
    int64_t ret = -2;
    PyObject *rfile = (PyObject *)self;

    /* Write the preamble */
    wrote = _Writer_write(self, preamble);
    if (wrote < 0) {
        goto error;
    }
    total += (uint64_t)wrote;

    if (body == Py_None) {
        wrote = 0;
    }
    else if (PyBytes_CheckExact(body)) {
        wrote = _Writer_write(self, _frombytes(body));
    }
    else if (Py_TYPE(body) == &BodyType) {
        wrote = _Body_write_to((Body *)body, rfile);
    }
    else if (Py_TYPE(body) == &ChunkedBodyType) {
        wrote = _ChunkedBody_write_to((ChunkedBody *)body, rfile);
    }
    else if (Py_TYPE(body) == &BodyIterType) {
        wrote = _BodyIter_write_to((BodyIter *)body, rfile);
    }
    else if (Py_TYPE(body) == &ChunkedBodyIterType) {
        wrote = _ChunkedBodyIter_write_to((ChunkedBodyIter *)body, rfile);
    }
    else {
        PyErr_Format(PyExc_TypeError,
            "bad body type: %R: %R", Py_TYPE(body), body
        );
        goto error;
    }
    if (wrote < 0) {
        goto error;
    }
    total += (uint64_t)wrote;

    /* Sanity check */
    if (origtell + total != self->tell) {
        PyErr_Format(PyExc_ValueError,
            "%llu + %llu != %llu", origtell, total, self->tell
        );
        goto error;
    }
    ret = (int64_t)total;
    goto cleanup;

error:
    ret = -1;

cleanup:
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
Writer_tell(Writer *self) {
    return PyLong_FromUnsignedLongLong(self->tell);
}

static PyObject *
Writer_write(Writer *self, PyObject *args)
{
    Py_buffer pybuf;

    if (!PyArg_ParseTuple(args, "y*:write", &pybuf)) {
        return NULL;
    }
    DeguSrc src = _frompybuf(&pybuf);
    const ssize_t total = _Writer_write(self, src);
    PyBuffer_Release(&pybuf);
    if (total >= 0) {
        return PyLong_FromSsize_t(total);
    }
    return NULL;
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
    DeguSrc preamble_src = {buf, len};
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
    if (! _set_output_headers(headers, body)) {
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
    if (! _set_output_headers(headers, body)) {
        return NULL;
    }
    DeguSrc method_src = {buf, len};
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
    if (! _set_output_headers(headers, body)) {
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


/******************************************************************************
 * Shared internal API for *Body*() objects.
 ******************************************************************************/
static bool
_check_body_state(const char *name, const uint8_t state, const uint8_t max_state)
{
    if (max_state >= BODY_CONSUMED) {
        Py_FatalError("_check_state(): bad internal call");
    }
    if (state <= max_state) {
        return true;
    }
    if (state == BODY_STARTED) {
        PyErr_Format(PyExc_ValueError,
            "%s.state == BODY_STARTED, cannot start another operation", name
        );
    }
    else if (state == BODY_CONSUMED) {
        PyErr_Format(PyExc_ValueError,
            "%s.state == BODY_CONSUMED, already consumed", name
        );
    }
    else if (state == BODY_ERROR) {
        PyErr_Format(PyExc_ValueError,
            "%s.state == BODY_ERROR, cannot be used", name
        );
    }
    else {
        Py_FatalError("_check_state(): invalid state");
    }
    return false;
}


/******************************************************************************
 * Body object.
 ******************************************************************************/
static void
Body_dealloc(Body *self)
{
    Py_CLEAR(self->rfile);
    Py_CLEAR(self->robj);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static bool
_Body_fill_args(Body *self, PyObject *rfile, const uint64_t content_length)
{
    if (rfile == NULL || content_length > MAX_LENGTH) {
        Py_FatalError("_Body_fill_args(): bad internal call");
    }
    _SET_AND_INC(self->rfile, rfile)
    _SET(self->robj, _get_robj(rfile))
    if (Py_TYPE(rfile) == &ReaderType) {
        self->fastpath = true;
    }
    else {
        self->fastpath = false;
    }
    self->remaining = self->content_length = content_length;
    self->state = BODY_READY;
    self->chunked = false;
    return true;

error:
    Py_CLEAR(self->rfile);
    Py_CLEAR(self->robj);
    return false;
}

static PyObject *
Body_New(PyObject *rfile, const uint64_t content_length)
{
    Body *self = PyObject_New(Body, &BodyType);
    if (self == NULL) {
        return NULL;
    }
    self->rfile = NULL;
    self->robj = NULL;
    self->state = BODY_ERROR;
    if (! _Body_fill_args(self, rfile, content_length)) {
        PyObject_Del((PyObject *)self);
        return NULL;
    }
    return (PyObject *)PyObject_INIT(self, &BodyType);
}

static int
Body_init(Body *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"rfile", "content_length", NULL};
    PyObject *rfile = NULL;
    PyObject *content_length = NULL;
    int64_t _content_length;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO:Body", keys,
                &rfile, &content_length)) {
        goto error;
    }
    _content_length = _validate_length("content_length", content_length);
    if (_content_length < 0) {
        goto error;
    }
    if (! _Body_fill_args(self, rfile, (uint64_t)_content_length)) {
        goto error;
    }
    return 0;

error:
    self->state = BODY_ERROR;
    return -1;
}

static bool
_Body_readinto(Body *self, DeguDst dst)
{
    if (dst.len > self->remaining) {
        Py_FatalError("_Body_readinto(): bad internal call");
    }
    if (_readinto_from(self->robj, dst)) {
        self->remaining -= dst.len;
        return true;
    }
    self->state = BODY_ERROR;
    return false;
}

static int64_t
_Body_write_to(Body *self, PyObject *wfile)
{
    PyObject *wobj = NULL;
    size_t iosize, size;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;
    uint8_t *dst_buf = NULL;

    if (! _check_body_state("Body", self->state, BODY_READY)) {
        goto error;
    }
    self->state = BODY_STARTED;
    if (self->remaining == 0) {
        self->state = BODY_CONSUMED;
        return 0;
    }

    _SET(wobj, _get_wobj(wfile))
    iosize = _min(IO_SIZE, self->remaining);
    dst_buf = _calloc_buf(iosize);
    DeguDst dst = {dst_buf, iosize};
    if (dst.buf == NULL) {
        goto error;
    }
    while (self->remaining > 0) {
        size = _min(dst.len, self->remaining);
        if (! _Body_readinto(self, _dst_slice(dst, 0, size))) {
            goto error;
        }
        wrote = _write_to(wobj, _slice_src_from_dst(dst, 0, size));
        if (wrote < 0) {
            goto error;
        }
        total += (uint64_t)wrote;
    }
    self->state = BODY_CONSUMED;
    ret = (int64_t)total;
    goto cleanup;

error:
    ret = -1;
    self->state = BODY_ERROR;

cleanup:
    Py_CLEAR(wobj);
    if (dst_buf != NULL) {
        free(dst_buf);
    }
    return ret;
}

static PyObject *
Body_write_to(Body *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "O", &wfile)) {
        return NULL;
    }
    const int64_t total = _Body_write_to(self, wfile);
    if (total >= 0) {
        ret = PyLong_FromLongLong(total);
    }
    return ret;
}

static PyObject *
_Body_read(Body *self, const size_t max_size)
{
    const size_t size = _min(max_size, self->remaining);
    PyObject *ret = NULL;

    if (! _check_body_state("Body", self->state, BODY_STARTED)) {
        return NULL;
    }
    if (self->remaining == 0) {
        self->state = BODY_CONSUMED;
    }
    else {
        self->state = BODY_STARTED;
    }
    if (size == 0) {
        _SET_AND_INC(ret, bytes_empty)
        return ret;
    }
    _SET(ret, PyBytes_FromStringAndSize(NULL, (ssize_t)size))
    DeguDst dst = _dst_frombytes(ret);
    if (_Body_readinto(self, dst)) {
        return ret;
    }

error:
    Py_CLEAR(ret);
    self->state = BODY_ERROR;
    return ret;
}

static PyObject *
Body_read(Body *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"size", NULL};
    PyObject *pysize = Py_None;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "|O", keys, &pysize)) {
        return NULL;
    }
    const ssize_t size = _validate_read_size("size", pysize, self->remaining);
    if (size < 0) {
        return NULL;
    }
    PyObject *ret = _Body_read(self, (size_t)size);
    if (pysize == Py_None && ret != NULL) {
        self->state = BODY_CONSUMED;
    }
    return ret;
}

static PyObject *
Body_repr(Body *self)
{
    return PyUnicode_FromFormat("Body(<rfile>, %llu)", self->content_length);
}

static PyObject *
Body_iter(Body *self)
{
    if (! _check_body_state("Body", self->state, BODY_READY)) {
        return NULL;
    }
    self->state = BODY_STARTED;
    PyObject *ret = (PyObject *)self;
    Py_INCREF(ret);
    return ret;
}

static PyObject *
Body_next(Body *self)
{
    if (self->remaining == 0) {
        self->state = BODY_CONSUMED;
        return NULL;
    }
    return _Body_read(self, IO_SIZE);
}


/******************************************************************************
 * ChunkedBody object
 ******************************************************************************/
static void
ChunkedBody_dealloc(ChunkedBody *self)
{
    Py_CLEAR(self->rfile);
    Py_CLEAR(self->robj);
    Py_CLEAR(self->readline);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static bool
_ChunkedBody_fill_args(ChunkedBody *self, PyObject *rfile)
{
    if (rfile == NULL) {
        Py_FatalError("_ChunkedBody_fill_args(): bad internal call");
    }
    _SET_AND_INC(self->rfile, rfile)
    _SET(self->robj, _get_robj(rfile))
    _SET(self->readline, _get_readline(rfile))
    if (Py_TYPE(rfile) == &ReaderType) {
        self->fastpath = true;
    }
    else {
        self->fastpath = false;
    }
    self->state = BODY_READY;
    self->chunked = true;
    return true;

error:
    Py_CLEAR(self->rfile);
    Py_CLEAR(self->robj);
    Py_CLEAR(self->readline);
    return false;
}

static PyObject *
ChunkedBody_New(PyObject *rfile)
{
    ChunkedBody *self = PyObject_New(ChunkedBody, &ChunkedBodyType);
    if (self == NULL) {
        return NULL;
    }
    self->rfile = NULL;
    self->robj = NULL;
    self->readline = NULL;
    self->state = BODY_ERROR;
    if (! _ChunkedBody_fill_args(self, rfile)) {
        PyObject_Del((PyObject *)self);
        return NULL;
    }
    return (PyObject *)PyObject_INIT(self, &ChunkedBodyType);
}

static int
ChunkedBody_init(ChunkedBody *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"rfile", NULL};
    PyObject *rfile = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kw, "O:ChunkedBody", keys, &rfile)) {
        goto error;
    }
    if (! _ChunkedBody_fill_args(self, rfile)) {
        goto error;
    }
    return 0;

error:
    self->state = BODY_ERROR;
    return -1;
}

static bool
_ChunkedBody_readchunk(ChunkedBody *self, DeguChunk *dc)
{
    if (! _check_body_state("ChunkedBody", self->state, BODY_STARTED)) {
        return false;
    }
    self->state = BODY_STARTED;
    if (! _readchunk_from(self->robj, self->readline, dc)) {
        goto error;
    }
    if (dc->size == 0) {
        self->state = BODY_CONSUMED;
    }
    return true;

error:
    self->state = BODY_ERROR;
    return false;
}

static PyObject *
ChunkedBody_readchunk(ChunkedBody *self)
{
    DeguChunk dc = NEW_DEGU_CHUNK;
    PyObject *ret = NULL;

    if (! _check_body_state("ChunkedBody", self->state, BODY_STARTED)) {
        return NULL;
    }
    self->state = BODY_STARTED;
    if (! _ChunkedBody_readchunk(self, &dc)) {
        goto error;
    }
    _SET(ret, _pack_chunk(&dc))
    goto cleanup;

error:
    self->state = BODY_ERROR;
    Py_CLEAR(ret);

cleanup:
    _clear_degu_chunk(&dc);
    return ret;
}

static DeguSrc
_shrink_chunk_data(PyObject *data)
{
    DeguSrc src = _frombytes(data);
    return _slice(src, 0, src.len - 2);
}

static PyObject *
ChunkedBody_read(ChunkedBody *self)
{
    PyObject *list = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;
    size_t total = 0, start = 0;
    PyObject *ret = NULL;
    ssize_t i;

    if (! _check_body_state("ChunkedBody", self->state, BODY_STARTED)) {
        return NULL;
    }
    self->state = BODY_STARTED;
    _SET(list, PyList_New(0))
    while (total <= MAX_IO_SIZE) {
        if (! _ChunkedBody_readchunk(self, &dc)) {
            goto error; 
        }
        total += dc.size;
        if (dc.size == 0) {
            break;
        }
        if (PyList_Append(list, dc.data) != 0) {
            goto error;
        }
        _clear_degu_chunk(&dc);
    }
    if (total > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "chunks exceed MAX_IO_SIZE: %zu > %zu", total, MAX_IO_SIZE
        );
        goto error;
    }

    _SET(ret, PyBytes_FromStringAndSize(NULL, (ssize_t)total))
    DeguDst dst = _dst_frombytes(ret);
    const ssize_t count = PyList_GET_SIZE(list);
    for (i = 0; i < count; i++) {
        start += _copy(
            _dst_slice(dst, start, dst.len),
            _shrink_chunk_data(PyList_GetItem(list, i))
        );
    }
    self->state = BODY_CONSUMED;
    goto cleanup;
    
error:
    self->state = BODY_ERROR;
    Py_CLEAR(ret);
    
cleanup:
    Py_CLEAR(list);
    _clear_degu_chunk(&dc);
    return ret;
}

static int64_t
_ChunkedBody_write_to(ChunkedBody *self, PyObject *wfile)
{
    if (! _check_body_state("ChunkedBody", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;

    PyObject *wobj = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;    

    _SET(wobj, _get_wobj(wfile))
    while (self->state < BODY_CONSUMED) {
        if (! _ChunkedBody_readchunk(self, &dc)) {
            goto error; 
        }
        wrote = _writechunk_to(wobj, &dc);
        if (wrote < 0) {
            goto error;
        }
        total += (uint64_t)wrote;
        _clear_degu_chunk(&dc);
    }
    self->state = BODY_CONSUMED;
    ret = (int64_t)total;
    goto cleanup;

error:
    ret = -1;
    self->state = BODY_ERROR;

cleanup:
    Py_CLEAR(wobj);
    _clear_degu_chunk(&dc);
    return ret;
}

static PyObject *
ChunkedBody_write_to(ChunkedBody *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    const int64_t total = _ChunkedBody_write_to(self, wfile);
    if (total >= 0) {
        ret = PyLong_FromLongLong(total);
    }
    return ret;
}

static PyObject *
ChunkedBody_repr(ChunkedBody *self)
{
    return PyUnicode_FromString("ChunkedBody(<rfile>)");
}

static PyObject *
ChunkedBody_iter(ChunkedBody *self)
{
    if (! _check_body_state("ChunkedBody", self->state, BODY_READY)) {
        return NULL;
    }
    self->state = BODY_STARTED;
    PyObject *ret = (PyObject *)self;
    Py_INCREF(ret);
    return ret;
}

static PyObject *
ChunkedBody_next(ChunkedBody *self)
{
    if (self->state == BODY_CONSUMED) {
        return NULL;
    }
    return ChunkedBody_readchunk(self);
}


/******************************************************************************
 * BodyIter object
 ******************************************************************************/
static void
BodyIter_dealloc(BodyIter *self)
{
    Py_CLEAR(self->source);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
BodyIter_init(BodyIter *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"source", "content_length", NULL};
    PyObject *source = NULL;
    PyObject *content_length = NULL;
    int64_t _content_length;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO:BodyIter", keys,
            &source, &content_length)) {
        goto error;
    }
    _SET_AND_INC(self->source, source)
    _content_length = _validate_length("content_length", content_length);
    if (_content_length < 0) {
        goto error;
    }
    self->content_length = (uint64_t)_content_length;
    self->state = BODY_READY;
    return 0;

error:
    return -1;
}

static PyObject *
BodyIter_repr(BodyIter *self)
{
    return PyUnicode_FromFormat(
        "BodyIter(<source>, %llu)", self->content_length
    );
}

static int64_t
_BodyIter_write_to(BodyIter *self, PyObject *wfile)
{
    if (! _check_body_state("BodyIter", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;

    PyObject *wobj = NULL;
    PyObject *iterator = NULL;
    PyObject *part = NULL;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;

    _SET(wobj, _get_wobj(wfile))
    _SET(iterator, PyObject_GetIter(self->source))
    while ((part = PyIter_Next(iterator))) {
        if (! PyBytes_CheckExact(part)) {
            PyErr_Format(PyExc_TypeError,
                "need a <class 'bytes'>; source contains a %R", Py_TYPE(part)
            );
            goto error;
        }
        wrote = _write_to(wobj, _frombytes(part));
        if (wrote < 0) {
            goto error;
        }
        total += (uint64_t)wrote;
        if (total > self->content_length) {
             PyErr_Format(PyExc_ValueError,
                "exceeds content_length: %llu > %llu",
                total, self->content_length
            );
            goto error;
        }
        Py_CLEAR(part);
    }
    if (total != self->content_length) {
         PyErr_Format(PyExc_ValueError,
            "deceeds content_length: %llu < %llu", total, self->content_length
        );
        goto error;
    }
    self->state = BODY_CONSUMED;
    ret = (int64_t)total;
    goto cleanup;

error:
    ret = -1;
    self->state = BODY_ERROR;

cleanup:
    Py_CLEAR(wobj);
    Py_CLEAR(iterator);
    Py_CLEAR(part);
    return ret;
}

static PyObject *
BodyIter_write_to(BodyIter *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    const int64_t total = _BodyIter_write_to(self, wfile);
    if (total >= 0) {
        ret = PyLong_FromLongLong(total);
    }
    return ret;
}


/******************************************************************************
 * ChunkedBodyIter object
 ******************************************************************************/
static void
ChunkedBodyIter_dealloc(ChunkedBodyIter *self)
{
    Py_CLEAR(self->source);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ChunkedBodyIter_init(ChunkedBodyIter *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"source", NULL};
    PyObject *source = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kw, "O:ChunkedBodyIter", keys, &source)) {
        goto error;
    }
    _SET_AND_INC(self->source, source)
    self->state = BODY_READY;
    return 0;

error:
    return -1;
}

static PyObject *
ChunkedBodyIter_repr(ChunkedBodyIter *self)
{
    return PyUnicode_FromString("ChunkedBodyIter(<source>)");
}

static int64_t
_ChunkedBodyIter_write_to(ChunkedBodyIter *self, PyObject *wfile)
{
    if (! _check_body_state("ChunkedBodyIter", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;

    PyObject *wobj = NULL;
    PyObject *iterator = NULL;
    PyObject *chunk = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;
    bool empty = false;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;    

    _SET(wobj, _get_wobj(wfile))
    _SET(iterator, PyObject_GetIter(self->source))
    while ((chunk = PyIter_Next(iterator))) {
        if (empty) {
            PyErr_SetString(PyExc_ValueError,
                "additional chunk after empty chunk data"
            );
            goto error;
        }
        if (! _unpack_chunk(&dc, chunk)) {
            goto error;
        }
        if (dc.size == 0) {
            empty = true;
        }
        wrote = _writechunk_to(wobj, &dc);
        if (wrote < 0) {
            goto error;
        }
        total += (uint64_t)wrote;
        Py_CLEAR(chunk);
        _clear_degu_chunk(&dc);
    }
    if (! empty) {
        PyErr_SetString(PyExc_ValueError, "final chunk data was not empty");
        goto error;
    }
    self->state = BODY_CONSUMED;
    ret = (int64_t)total;
    goto cleanup;

error:
    ret = -1;
    self->state = BODY_ERROR;

cleanup:
    Py_CLEAR(wobj);
    Py_CLEAR(iterator);
    Py_CLEAR(chunk);
    _clear_degu_chunk(&dc);
    return ret;
}

static PyObject *
ChunkedBodyIter_write_to(ChunkedBodyIter *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    const int64_t total = _ChunkedBodyIter_write_to(self, wfile);
    if (total >= 0) {
        ret = PyLong_FromLongLong(total);
    }
    return ret;
}




/*******************************************************************************
 * Module Init:
 */
static bool
_init_all_types(PyObject *module)
{
    RangeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&RangeType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Range", (PyObject *)&RangeType)

    ReaderType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ReaderType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Reader", (PyObject *)&ReaderType)

    WriterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&WriterType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Writer", (PyObject *)&WriterType)

    BodyType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&BodyType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Body", (PyObject *)&BodyType)

    ChunkedBodyType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ChunkedBodyType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "ChunkedBody", (PyObject *)&ChunkedBodyType)

    BodyIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&BodyIterType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "BodyIter", (PyObject *)&BodyIterType)

    ChunkedBodyIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ChunkedBodyIterType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "ChunkedBodyIter", (PyObject *)&ChunkedBodyIterType)

    if (! _init_all_namedtuples(module)) {
        goto error;
    }
    _SET(bodies,
        _Bodies(
            (PyObject *)&BodyType,
            (PyObject *)&BodyIterType,
            (PyObject *)&ChunkedBodyType,
            (PyObject *)&ChunkedBodyIterType
        )
    )
    _ADD_MODULE_ATTR(module, "bodies", bodies)
    return true;

error:
    return false;
}

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
    if (! _init_all_globals(module)) {
        return NULL;
    }
    if (! _init_all_types(module)) {
        return NULL;
    }
    PyModule_AddIntMacro(module, _MAX_LINE_SIZE);
    PyModule_AddIntMacro(module, MIN_PREAMBLE);
    PyModule_AddIntMacro(module, DEFAULT_PREAMBLE);
    PyModule_AddIntMacro(module, MAX_PREAMBLE);
    PyModule_AddIntMacro(module, MAX_IO_SIZE);
    PyModule_AddIntMacro(module, BODY_READY);
    PyModule_AddIntMacro(module, BODY_STARTED);
    PyModule_AddIntMacro(module, BODY_CONSUMED);
    PyModule_AddIntMacro(module, BODY_ERROR);
    return module;
}

