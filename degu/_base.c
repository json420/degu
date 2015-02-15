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
#include <sys/socket.h>

#define _MAX_LINE_SIZE 4096
#define MIN_PREAMBLE 4096
#define MAX_PREAMBLE 65536
#define DEFAULT_PREAMBLE 32768
#define MAX_KEY 32
#define MAX_CL_LEN 16

/* `degu.base.EmptyPreambleError` */
static PyObject *degu_EmptyPreambleError = NULL;

/* Pre-built global Python object for performance */
static PyObject *str_close = NULL;              //  'close'
static PyObject *str_shutdown = NULL;           //  'shutdown'
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

static PyObject *int_SHUT_RDWR = NULL;  // socket.SHUT_RDWR (2)

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



/*******************************************************************************
 * Internal API: Macros:
 *     _SET()
 *     _SET_AND_INC()
 *     _SET_ITEM()
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

#define _SET_ITEM(dict, key, val) \
    if (PyDict_SetItem(dict, key, val) != 0) { \
        goto error; \
    }


/*******************************************************************************
 * Internal API: Misc:
 *     _min()
 *     _calloc_buf()
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


/*******************************************************************************
 * Internal API: DeguBuf:
 *     _isempty()
 *     _slice()
 *     _equal()
 *     _find()
 *     _tostr()
 *     _tobytes()
 *     _value_error()
 *     _value_error2()
 *     _decode()
 */
typedef struct {
    const uint8_t *buf;
    const size_t len;
} DeguBuf;

static DeguBuf NULL_DeguBuf = {NULL, 0}; 

#define _DEGU_BUF_CONSTANT(name, text) \
    static DeguBuf name = {(uint8_t *)text, sizeof(text) - 1}; 

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

static inline bool
_isempty(DeguBuf src)
{
    if (src.buf == NULL || src.len == 0) {
        return true;
    }
    return false;
}

static DeguBuf
_slice(DeguBuf src, const size_t start, const size_t stop)
{
    if (_isempty(src) || start > stop || stop > src.len) {
        Py_FatalError("_slice(): bad internal call");
    }
    return (DeguBuf){src.buf + start, stop - start};
}

static bool
_equal(DeguBuf a, DeguBuf b) {
    if (a.buf == NULL || _isempty(b)) {
        Py_FatalError("_equal(): bad internal call");
    }
    if (a.len == b.len && memcmp(a.buf, b.buf, a.len) == 0) {
        return true;
    }
    return false;
}

static size_t
_find(DeguBuf haystack, DeguBuf needle)
{
    const uint8_t *ptr;
    if (_isempty(haystack) || _isempty(needle)) {
        Py_FatalError("_find(): empty *haystack* or empty *needle*");
    }
    ptr = memmem(haystack.buf, haystack.len, needle.buf, needle.len);
    if (ptr == NULL) {
        return haystack.len;
    }
    return ptr - haystack.buf;
}

static PyObject *
_tostr(DeguBuf src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyUnicode_FromKindAndData(PyUnicode_1BYTE_KIND, src.buf, src.len);
}

static PyObject *
_tobytes(DeguBuf src)
{
    if (src.buf == NULL) {
        return NULL;
    }
    return PyBytes_FromStringAndSize((const char *)src.buf, src.len);
}

static void
_value_error(const char *format, DeguBuf src)
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

static PyObject *
_decode(DeguBuf src, const uint8_t mask, const char *format)
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
        _value_error(format, src);
        goto error;
    }
    goto done;

error:
    Py_CLEAR(dst);

done:
    return dst;
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
     ((DeguHeaders){NULL, NULL, 0})

#define NEW_DEGU_REQUEST \
     ((DeguRequest){NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL})

#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, 0, NULL, NULL, NULL})

static void
_clear_degu_headers(DeguHeaders *dh)
{
    Py_CLEAR(dh->headers);
    Py_CLEAR(dh->content_length);
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
 * Internal API: Parsing: Headers:
 *     _parse_key()
 *     _parse_val()
 *     _parse_content_length()
 *     _parse_header_line()
 *     _parse_headers()
 */
static bool
_parse_key(DeguBuf src, uint8_t *dst_buf)
{
    uint8_t r;
    size_t i;
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return false; 
    }
    if (src.len > MAX_KEY) {
        _value_error("header name too long: %R...", _slice(src, 0, MAX_KEY));
        return false;
    }
    for (r = i = 0; i < src.len; i++) {
        r |= dst_buf[i] = _NAMES[src.buf[i]];
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
_parse_val(DeguBuf src)
{
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header value is empty");
        return NULL; 
    }
    return _decode(src, VALUE_MASK, "bad bytes in header value: %R");
}

static PyObject *
_parse_content_length(DeguBuf src)
{
    uint64_t accum;
    uint8_t flags, c;
    size_t i;
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "content-length is empty");
        return NULL; 
    }
    if (src.len > MAX_CL_LEN) {
        _value_error("content-length too long: %R...",
            _slice(src, 0, MAX_CL_LEN)
        );
        return NULL; 
    }
    for (accum = flags = i = 0; i < src.len; i++) {
        accum *= 10;
        c = src.buf[i];
        flags |= _FLAGS[c];
        accum += (c - 48);
    }
    if (flags == 0) {
        Py_FatalError("_parse_content_length(): flags == 0");
    }
    if ((flags & DIGIT_MASK) != 0) {
        _value_error("bad bytes in content-length: %R", src);
        return NULL;
    }
    if (src.buf[0] == 48 && src.len != 1) {
        _value_error("content-length has leading zero: %R", src);
        return NULL;
    }
    return PyLong_FromUnsignedLongLong(accum);
}

static bool
_parse_header_line(DeguBuf src, uint8_t *scratch, DeguHeaders *dh)
{
    size_t keystop, valstart;
    bool success = true;
    PyObject *key = NULL;
    PyObject *val = NULL;

    /* Split header line, validate & casefold header name */
    if (src.len < 4) {
        _value_error("header line too short: %R", src);
        goto error;
    }
    keystop = _find(src, SEP);
    if (keystop == src.len) {
        _value_error("bad header line: %R", src);
        goto error;
    }
    valstart = keystop + SEP.len;
    DeguBuf rawkey = _slice(src, 0, keystop);
    DeguBuf valsrc = _slice(src, valstart, src.len);
    if (! _parse_key(rawkey, scratch)) {
        goto error;
    }
    DeguBuf keysrc = {scratch, rawkey.len};

    /* Validate header value (with special handling and fast-paths) */
    if (_equal(keysrc, CONTENT_LENGTH)) {
        _SET_AND_INC(key, str_content_length)
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
        _SET_AND_INC(key, str_transfer_encoding)
        _SET_AND_INC(val, str_chunked)
        dh->flags |= 2;
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
_parse_headers(DeguBuf src, uint8_t *scratch, DeguHeaders *dh)
{
    size_t start, stop;

    _SET(dh->headers, PyDict_New())
    start = 0;
    while (start < src.len) {
        stop = start + _find(_slice(src, start, src.len), CRLF);
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
        _value_error("bad HTTP method: %R", src);
    }
    else {
        Py_INCREF(method);
    }
    return method;
}

static inline PyObject *
_parse_path_component(DeguBuf src)
{
    return _decode(src, PATH_MASK, "bad bytes in path component: %R");
}

static PyObject *
_parse_path(DeguBuf src)
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
        stop = start + _find(_slice(src, start, src.len), SLASH);
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
    Py_CLEAR(component);

cleanup:
    if (component != NULL) {
        Py_FatalError("_parse_path(): component != NULL");
    }
    return path;
}

static inline PyObject *
_parse_query(DeguBuf src)
{
    return _decode(src, QUERY_MASK, "bad bytes in query: %R");
}

static bool
_parse_uri(DeguBuf src, DeguRequest *dr)
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
    path_stop = _find(src, QMARK);
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
_parse_request_line(DeguBuf line, DeguRequest *dr)
{
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
    DeguBuf protocol = _slice(line, line.len - 9, line.len);
    if (! _equal(protocol, REQUEST_PROTOCOL)) {
        _value_error("bad protocol in request line: %R", protocol);
        goto error;
    }

    /* Now we'll work with line[0:-9]
     *     "GET / HTTP/1.1"[0:-9]
     *      ^^^^^
     */
    DeguBuf src = _slice(line, 0, line.len - protocol.len);

    /* Search for method terminating space, plus start of uri:
     *     "GET /"
     *         ^^
     */
    method_stop = _find(src, SPACE_SLASH);
    if (method_stop >= src.len) {
        _value_error("bad request line: %R", line);
        goto error;
    }
    uri_start = method_stop + 1;
    DeguBuf method_src = _slice(src, 0, method_stop);
    DeguBuf uri_src = _slice(src, uri_start, src.len);

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
_parse_request(DeguBuf src, uint8_t *scratch, DeguRequest *dr)
{
    const size_t stop = _find(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguBuf line_src = _slice(src, 0, stop);
    DeguBuf headers_src = _slice(src, start, src.len);
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
static inline PyObject *
_parse_status(DeguBuf src)
{
    uint8_t d, err;
    unsigned long accum;

    if (src.len != 3) {
        _value_error("bad status length: %R", src);
        return NULL;
    }
    d = src.buf[0];    err =  (d < 49 || d > 53);    accum =  (d - 48) * 100;
    d = src.buf[1];    err |= (d < 48 || d > 57);    accum += (d - 48) *  10;
    d = src.buf[2];    err |= (d < 48 || d > 57);    accum += (d - 48);
    if (err || accum < 100 || accum > 599) {
        _value_error("bad status: %R", src);
        return NULL;
    }
    return PyLong_FromUnsignedLong(accum);
}

static inline PyObject *
_parse_reason(DeguBuf src)
{
    if (_equal(src, OK)) {
        Py_XINCREF(str_OK);
        return str_OK;
    }
    return _decode(src, REASON_MASK, "bad reason: %R");
}

static bool
_parse_response_line(DeguBuf src, DeguResponse *dr)
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
    DeguBuf pcol = _slice(src, 0, 9);
    DeguBuf sp = _slice(src, 12, 13);
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
_parse_response(DeguBuf src, uint8_t *scratch, DeguResponse *dr)
{
    const size_t stop = _find(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguBuf line_src = _slice(src, 0, stop);
    DeguBuf headers_src = _slice(src, start, src.len);
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
 *     _validate_key()
 *     _format_headers()
 */
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
    if (PyUnicode_MAX_CHAR_VALUE(key) != 127) {
        goto bad_key;
    }
    const uint8_t *key_buf = PyUnicode_1BYTE_DATA(key);
    const ssize_t key_len = PyUnicode_GET_LENGTH(key);
    if (key_len < 1) {
        if (key_len < 0) {
            Py_FatalError("_validate_key(): key < 0");
        }
        PyErr_SetString(PyExc_ValueError, "key is empty");
        return false;
    }
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

    if (!PyDict_CheckExact(headers)) {
        PyErr_Format(PyExc_TypeError,
            "headers: need a <class 'dict'>; got a %R: %R",
            Py_TYPE(headers), headers
        );
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
    {"body", NULL},
    {NULL},
};
static PyStructSequence_Desc RequestDesc = {
    "Request",
    NULL,
    RequestFields,  
    7
};
static PyObject *
_Request(PyObject *method,
         PyObject *uri,
         PyObject *script,
         PyObject *path,
         PyObject *query,
         PyObject *headers,
         PyObject *body)
{
    PyObject *request = PyStructSequence_New(&RequestType);
    if (request == NULL) {
        return NULL;
    }
    PyStructSequence_SET_ITEM(request, 0, method);
    PyStructSequence_SET_ITEM(request, 1, uri);
    PyStructSequence_SET_ITEM(request, 2, script);
    PyStructSequence_SET_ITEM(request, 3, path);
    PyStructSequence_SET_ITEM(request, 4, query);
    PyStructSequence_SET_ITEM(request, 5, headers);
    PyStructSequence_SET_ITEM(request, 6, body);
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
    PyObject *dst = NULL;
    uint8_t *dst_buf;

    if (!PyArg_ParseTuple(args, "y#:parse_header_name", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return NULL;
    }
    if (src.len > MAX_KEY) {
        _value_error("header name too long: %R...",  _slice(src, 0, MAX_KEY));
        return NULL;
    }

    _SET(dst, PyUnicode_New(src.len, 127))
    dst_buf = PyUnicode_1BYTE_DATA(dst);
    if (!_parse_key(src, dst_buf)) {
        goto error;
    }
    goto done;

error:
    Py_CLEAR(dst);

done:
    return dst;
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
parse_headers(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    uint8_t *scratch = NULL;
    DeguHeaders dh = NEW_DEGU_HEADERS;
    if (!PyArg_ParseTuple(args, "y#:parse_headers", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    _SET(scratch, _calloc_buf(MAX_KEY))
    if (!_parse_headers(src, scratch, &dh)) {
        goto error;
    }
    goto cleanup;
error:
    Py_CLEAR(dh.headers);
cleanup:
    if (scratch != NULL) {
        free(scratch);
        scratch = NULL;
    }
    Py_CLEAR(dh.content_length);
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
    return _parse_method((DeguBuf){buf, len});
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
    DeguBuf src = {buf, len};
    if (!_parse_uri(src, &dr)) {
        goto error;
    }
    _SET(ret, PyDict_New())
    _SET_ITEM(ret, str_uri, dr.uri)
    _SET_ITEM(ret, str_script, dr.script)
    _SET_ITEM(ret, str_path, dr.path)
    _SET_ITEM(ret, str_query, dr.query)
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
    DeguBuf src = {buf, len};
    if (!_parse_request_line(src, &dr)) {
        goto error;
    }
    _SET(ret, PyDict_New())
    _SET_ITEM(ret, str_method, dr.method)
    _SET_ITEM(ret, str_uri, dr.uri)
    _SET_ITEM(ret, str_script, dr.script)
    _SET_ITEM(ret, str_path, dr.path)
    _SET_ITEM(ret, str_query, dr.query)
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
    uint8_t *scratch = NULL;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (!PyArg_ParseTuple(args, "y#:parse_request", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    _SET(scratch, _calloc_buf(MAX_KEY))
    if (!_parse_request(src, scratch, &dr)) {
        goto error;
    }
    _SET(ret, PyDict_New())
    _SET_ITEM(ret, str_method, dr.method)
    _SET_ITEM(ret, str_uri, dr.uri)
    _SET_ITEM(ret, str_script, dr.script)
    _SET_ITEM(ret, str_path, dr.path)
    _SET_ITEM(ret, str_query, dr.query)
    _SET_ITEM(ret, str_headers, dr.headers)
    goto cleanup;
error:
    Py_CLEAR(ret);
cleanup:
    if (scratch != NULL) {
        free(scratch);
        scratch = NULL;
    }
    _clear_degu_request(&dr);
    return ret;
}

static PyObject *
parse_request2(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    uint8_t *scratch = NULL;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (!PyArg_ParseTuple(args, "y#:parse_request", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    _SET(scratch, _calloc_buf(MAX_KEY))
    if (!_parse_request(src, scratch, &dr)) {
        goto error;
    }
    _SET(ret,
        _Request(dr.method, dr.uri, dr.script, dr.path, dr.query, dr.headers, dr.body)
    )
    goto cleanup;
error:
    _clear_degu_request(&dr);
cleanup:
    if (scratch != NULL) {
        free(scratch);
        scratch = NULL;
    }
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
    if (!PyArg_ParseTuple(args, "s#:parse_response_line", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    if (!_parse_response_line(src, &dr)) {
        goto error;
    }
    if (dr.status == NULL || dr.reason == NULL) {
        Py_FatalError("parse_response_line");
        goto error;
    }
    _SET(ret, PyTuple_New(2))
    PyTuple_SET_ITEM(ret, 0, dr.status);
    PyTuple_SET_ITEM(ret, 1, dr.reason);
    goto done;
error:
    _clear_degu_response(&dr);
done:
    return ret;
}

static PyObject *
parse_response(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    uint8_t *scratch = NULL;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;
    if (!PyArg_ParseTuple(args, "y#:parse_response", &buf, &len)) {
        return NULL;
    }
    DeguBuf src = {buf, len};
    _SET(scratch, _calloc_buf(MAX_KEY))
    if (!_parse_response(src, scratch, &dr)) {
        goto error;
    }
    _SET(ret, PyTuple_New(3))
    PyTuple_SET_ITEM(ret, 0, dr.status);
    PyTuple_SET_ITEM(ret, 1, dr.reason);
    PyTuple_SET_ITEM(ret, 2, dr.headers);
    goto cleanup;
error:
    _clear_degu_response (&dr);
cleanup:
    if (scratch != NULL) {
        free(scratch);
        scratch = NULL;
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
    PyObject *method = NULL;
    PyObject *uri = NULL;
    PyObject *headers = NULL;
    PyObject *hstr = NULL;
    PyObject *str = NULL;  /* str version of request preamble */
    PyObject *ret = NULL;  /* bytes version of request preamble */

    if (!PyArg_ParseTuple(args, "UUO:format_request", &method, &uri, &headers)) {
        return NULL;
    }
    _SET(hstr, _format_headers(headers))
    _SET(str,
        PyUnicode_FromFormat("%S %S HTTP/1.1\r\n%S\r\n", method, uri, hstr)
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

static PyObject *
format_response(PyObject *self, PyObject *args)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;
    PyObject *headers = NULL;
    PyObject *hstr = NULL;
    PyObject *str = NULL;  /* str version of response preamble */
    PyObject *ret = NULL;  /* bytes version of response preamble */

    if (!PyArg_ParseTuple(args, "OUO:format_response", &status, &reason, &headers)) {
        return NULL;
    }
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
    PyObject *body = NULL;
    if (!PyArg_ParseTuple(args, "UUOOOOO:Request",
            &method, &uri, &script, &path, &query, &headers, &body)) {
        return NULL;
    }
    Py_INCREF(method);
    Py_INCREF(uri);
    Py_INCREF(script);
    Py_INCREF(path);
    Py_INCREF(query);
    Py_INCREF(headers);
    Py_INCREF(body);
    return _Request(method, uri, script, path, query, headers, body);
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
    Py_INCREF(status);
    Py_INCREF(reason);
    Py_INCREF(headers);
    Py_INCREF(body);
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
    {"parse_headers", parse_headers, METH_VARARGS, "parse_headers(src)"},

    /* Request Parsing */
    {"parse_method", parse_method, METH_VARARGS, "parse_method(method)"},
    {"parse_uri", parse_uri, METH_VARARGS, "parse_uri(uri)"},
    {"parse_request_line", parse_request_line, METH_VARARGS,
        "parse_request_line(line)"},
    {"parse_request", parse_request, METH_VARARGS, "parse_request(preamble)"},
    {"parse_request2", parse_request2, METH_VARARGS, "parse_request2(preamble)"},

    /* Response Parsing */
    {"parse_response_line", parse_response_line, METH_VARARGS,
        "parse_response_line(line)"},
    {"parse_response", parse_response, METH_VARARGS, "parse_response(preamble)"},

    /* Formatting */
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
    PyObject *sock_close;
    PyObject *sock_shutdown;
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
    Py_CLEAR(self->sock_close);
    Py_CLEAR(self->sock_shutdown);
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
    PyObject *sock = NULL;
    PyObject *bodies = NULL;
    ssize_t len = DEFAULT_PREAMBLE;
    static char *keys[] = {"sock", "bodies", "size", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kw, "OO|n:Reader", keys, &sock, &bodies, &len)) {
        return -1;
    }
    if (len < MIN_PREAMBLE || len > MAX_PREAMBLE) {
        PyErr_Format(PyExc_ValueError,
            "need %zd <= size <= %zd; got %zd",
            MIN_PREAMBLE, MAX_PREAMBLE, len
        );
        return -1;
    }
    _SET(self->sock_close, PyObject_GetAttr(sock, str_close))
    if (!PyCallable_Check(self->sock_close)) {
        PyErr_SetString(PyExc_TypeError, "sock.close() is not callable");
        goto error;
    }
    _SET(self->sock_shutdown, PyObject_GetAttr(sock, str_shutdown))
    if (!PyCallable_Check(self->sock_shutdown)) {
        PyErr_SetString(PyExc_TypeError, "sock.shutdown() is not callable");
        goto error;
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
    self->len = len;
    _SET(self->buf, _calloc_buf(self->len))
    self->rawtell = 0;
    self->start = 0;
    self->stop = 0;
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
            "need a <class 'int'>; recv_into() returned a %R: %R",
            Py_TYPE(int_size), int_size
        );
        ret = -2;
        goto error;
    }

    /* Convert to ssize_t, check for OverflowError */
    size = PyLong_AsSsize_t(int_size);
    if (PyErr_Occurred()) {
        ret = -3;
        goto error;
    }

    /* sock.recv_into() must return (0 <= size <= len) */
    if (size < 0 || size > len) {
        PyErr_Format(PyExc_IOError,
            "need 0 <= size <= %zd; recv_into() returned %zd", len, size
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
            "_Reader_recv_into(): in error, but ret >= 0"
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

    /* Now read till found */
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


/*******************************************************************************
 * Reader: Public API:
 *     Reader.close()
 *     Reader.shutdown()
 *     Reader.Body()
 *     Reader.ChunkedBody()
 *     Reader.rawtell()
 *     Reader.tell()
 *     Reader.expose()
 *     Reader.peek()
 *     Reader.drain()
 *     Reader.fill_until()
 *     Reader.search()
 *     Reader.readline()
 *     Reader.read_request()
 *     Reader.read_response()
 *     Reader.read()
 */
static PyObject *
Reader_close(Reader *self)
{
    return PyObject_CallFunctionObjArgs(self->sock_close, NULL);
}

static PyObject *
Reader_shutdown(Reader *self)
{
    return PyObject_CallFunctionObjArgs(self->sock_shutdown,
        int_SHUT_RDWR, NULL
    );
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
    return PyLong_FromSize_t(self->rawtell);
}

static PyObject *
Reader_tell(Reader *self) {
    DeguBuf cur = _Reader_peek(self, self->len);
    return PyLong_FromSize_t(self->rawtell - cur.len);
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
Reader_read_request(Reader *self) {
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;

    DeguBuf src = _Reader_search(self, self->len, CRLFCRLF, false, false);
    if (src.buf == NULL) {
        goto error;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "request preamble is empty");
        goto error;
    }
    if (!_parse_request(src, self->scratch, &dr)) {
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
    _SET(ret, PyDict_New())
    _SET_ITEM(ret, str_method, dr.method)
    _SET_ITEM(ret, str_uri, dr.uri)
    _SET_ITEM(ret, str_script, dr.script)
    _SET_ITEM(ret, str_path, dr.path)
    _SET_ITEM(ret, str_query, dr.query)
    _SET_ITEM(ret, str_headers, dr.headers)
    _SET_ITEM(ret, str_body, dr.body)
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    _clear_degu_request(&dr);
    return ret;
}

static PyObject *
Reader_read_request2(Reader *self) {
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;

    DeguBuf src = _Reader_search(self, self->len, CRLFCRLF, false, false);
    if (src.buf == NULL) {
        goto error;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "request preamble is empty");
        goto error;
    }
    if (!_parse_request(src, self->scratch, &dr)) {
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
        _Request(dr.method, dr.uri, dr.script, dr.path, dr.query, dr.headers, dr.body)
    )
    goto cleanup;

error:
    _clear_degu_request(&dr);

cleanup:
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
    if (!PyArg_ParseTuple(args, "s#:", &method_buf, &method_len)) {
        return NULL;
    }
    _SET(method, _parse_method((DeguBuf){method_buf, method_len}))

    /* Reader.search() will drain up to the end of the preamble */
    DeguBuf src = _Reader_search(self, self->len, CRLFCRLF, false, false);
    if (src.buf == NULL) {
        goto error;
    }
    if (src.len == 0) {
        PyErr_SetString(degu_EmptyPreambleError, "response preamble is empty");
        goto error;
    }

    /* Parse response line and header lines */
    if (!_parse_response(src, self->scratch, &dr)) {
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
    _clear_degu_response(&dr);

cleanup:
    Py_CLEAR(method);
    Py_CLEAR(dr.content_length);
    return ret;
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
Reader_readinto(Reader *self, PyObject *args)
{
    Py_buffer dst;
    size_t start;
    ssize_t added;
    PyObject *ret = NULL;

    if (!PyArg_ParseTuple(args, "w*", &dst)) {
        return NULL;
    }
    if (dst.len < 1) {
        PyErr_SetString(PyExc_ValueError, "dst cannot be empty");
        goto error;
    }
    DeguBuf src = _Reader_drain(self, dst.len);
    if (src.len > dst.len) {
        Py_FatalError("_Reader_readinto(): src.len > dst.len");
    }
    if (src.len > 0) {
        memcpy(dst.buf, src.buf, src.len);
    }
    start = src.len;
    while (start < dst.len) {
        added = _Reader_sock_recv_into(self,
            (uint8_t *)dst.buf + start, dst.len - start
        );
        if (added < 0) {
            goto error;
        }
        if (added == 0) {
            break;
        }
        start += added;
    }
    if (start > dst.len) {
        Py_FatalError("_Reader_readinto(): start > dst.len");
    }
    _SET(ret, PyLong_FromSize_t(start))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    PyBuffer_Release(&dst);
    return ret;
}


/*******************************************************************************
 * Reader: PyMethodDef, PyTypeObject:
 */
static PyMethodDef Reader_methods[] = {
    {"close", (PyCFunction)Reader_close, METH_NOARGS, "close()"},
    {"shutdown", (PyCFunction)Reader_shutdown, METH_NOARGS, "shutdown()"},
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
    {"read_request2", (PyCFunction)Reader_read_request2, METH_NOARGS,
        "read_request2()"
    },
    {"read_response", (PyCFunction)Reader_read_response, METH_VARARGS,
        "read_response(method)"
    },

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
    PyObject *module = NULL;

    ReaderType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ReaderType) < 0)
        return NULL;

    module = PyModule_Create(&degu);
    if (module == NULL) {
        return NULL;
    }
    if (!_init_all_namedtuples(module)) {
        return NULL;
    }
    Py_INCREF(&ReaderType);
    PyModule_AddObject(module, "Reader", (PyObject *)&ReaderType);

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

    /* Init global Python `int` and `str` objects we need for performance */
    _SET(str_close, PyUnicode_InternFromString("close"))
    _SET(str_shutdown, PyUnicode_InternFromString("shutdown"))
    _SET(str_recv_into, PyUnicode_InternFromString("recv_into"))
    _SET(str_Body, PyUnicode_InternFromString("Body"))
    _SET(str_ChunkedBody, PyUnicode_InternFromString("ChunkedBody"))
    _SET(str_content_length, PyUnicode_InternFromString("content-length"))
    _SET(str_transfer_encoding, PyUnicode_InternFromString("transfer-encoding"))
    _SET(str_chunked, PyUnicode_InternFromString("chunked"))
    _SET(str_crlf, PyUnicode_InternFromString("\r\n"))
    _SET(str_empty, PyUnicode_InternFromString(""))

    _SET(str_method, PyUnicode_InternFromString("method"))
    _SET(str_uri, PyUnicode_InternFromString("uri"))
    _SET(str_script, PyUnicode_InternFromString("script"))
    _SET(str_path, PyUnicode_InternFromString("path"))
    _SET(str_query, PyUnicode_InternFromString("query"))
    _SET(str_headers, PyUnicode_InternFromString("headers"))
    _SET(str_body, PyUnicode_InternFromString("body"))

    _SET(int_SHUT_RDWR, PyLong_FromLong(SHUT_RDWR))

    return module;

error:
    return NULL;
}

