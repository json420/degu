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
 * PyObject globals.
 ******************************************************************************/

/* EmptyPreambleError exception */
static PyObject *EmptyPreambleError = NULL;

/* Default Bodies namedtuple instance */
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
static PyObject *key_content_range     = NULL;  //  'content-range'

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
static PyObject *str_empty             = NULL;  //  ''

/* Other misc PyObject */
static PyObject *bytes_empty           = NULL;  //  b''
static PyObject *bytes_CRLF            = NULL;  //  b'\r\n'
static PyObject *int_MAX_LINE_LEN      = NULL;  //  4096

/* PyModule_AddIntMacro() wont work for this on 32-bit systems */
static PyObject *int_MAX_LENGTH        = NULL;  // 9999999999999999ull


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
    _SET(key_content_range,     PyUnicode_FromString("content-range"))

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
    _SET(str_empty,  PyUnicode_FromString(""))

    /* Init misc objects */
    _SET(bytes_empty, PyBytes_FromStringAndSize(NULL, 0))
    _SET(bytes_CRLF,  PyBytes_FromStringAndSize("\r\n", 2))
    _SET(int_MAX_LINE_LEN, PyLong_FromLong(MAX_LINE_LEN))

    /* Can't use PyModule_AddIntMacro() for this on 32-bit systems */
    _SET(int_MAX_LENGTH, PyLong_FromUnsignedLongLong(MAX_LENGTH))
    _ADD_MODULE_ATTR(module, "MAX_LENGTH", int_MAX_LENGTH)

    return true;

error:
    return false;
}


/******************************************************************************
 * DeguSrc globals
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
_DEGU_SRC_CONSTANT(CONTENT_RANGE, "content-range")
_DEGU_SRC_CONSTANT(CONTENT_TYPE, "content-type")
_DEGU_SRC_CONSTANT(APPLICATION_JSON, "application/json")
_DEGU_SRC_CONSTANT(BYTES_EQ, "bytes=")
_DEGU_SRC_CONSTANT(BYTES_SP, "bytes ")
_DEGU_SRC_CONSTANT(MINUS, "-")
_DEGU_SRC_CONSTANT(SEMICOLON, ";")
_DEGU_SRC_CONSTANT(EQUALS, "=")


/******************************************************************************
 * namedtuples (PyStructSequence)
 ******************************************************************************/
#define _SET_NAMEDTUPLE_ITEM(tup, index, value) \
    if (value == NULL) { \
        Py_FatalError("_SET_NAMEDTUPLE_ITEM(): value == NULL"); \
    } \
    Py_INCREF(value); \
    PyStructSequence_SET_ITEM(tup, index, value);


/* Bodies namedtuple */
static PyTypeObject BodiesType;
static PyStructSequence_Field BodiesFields[] = {
    {"Body", NULL},
    {"BodyIter", NULL},
    {"ChunkedBody", NULL},
    {"ChunkedBodyIter", NULL},
    {NULL},
};
static PyStructSequence_Desc BodiesDesc = {"Bodies", NULL, BodiesFields, 4};

static PyObject *
_Bodies(PyObject *arg0, PyObject *arg1, PyObject *arg2, PyObject *arg3)
{
    PyObject *ret = PyStructSequence_New(&BodiesType);
    if (ret != NULL) {
        _SET_NAMEDTUPLE_ITEM(ret, 0, arg0)
        _SET_NAMEDTUPLE_ITEM(ret, 1, arg1)
        _SET_NAMEDTUPLE_ITEM(ret, 2, arg2)
        _SET_NAMEDTUPLE_ITEM(ret, 3, arg3)
    }
    return ret;
}

/* FIXME: change order to Body, ChunkedBody, BodyIter, ChunkedBodyIter */
static PyObject *
Bodies(PyObject *self, PyObject *args)
{
    PyObject *arg0 = NULL;  // Body
    PyObject *arg1 = NULL;  // BodyIter
    PyObject *arg2 = NULL;  // ChunkedBody
    PyObject *arg3 = NULL;  // ChunkedBodyIter

    if (! PyArg_ParseTuple(args, "OOOO:Bodies", &arg0, &arg1, &arg2, &arg3)) {
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
static PyStructSequence_Desc RequestDesc = {"Request", NULL, RequestFields, 7};

static PyObject *
_Request(DeguRequest *dr)
{
    PyObject *ret = PyStructSequence_New(&RequestType);
    if (ret != NULL) {
        _SET_NAMEDTUPLE_ITEM(ret, 0, dr->method)
        _SET_NAMEDTUPLE_ITEM(ret, 1, dr->uri)
        _SET_NAMEDTUPLE_ITEM(ret, 2, dr->headers)
        _SET_NAMEDTUPLE_ITEM(ret, 3, dr->body)
        _SET_NAMEDTUPLE_ITEM(ret, 4, dr->script)
        _SET_NAMEDTUPLE_ITEM(ret, 5, dr->path)
        _SET_NAMEDTUPLE_ITEM(ret, 6, dr->query)
    }
    return ret;
}

static PyObject *
Request(PyObject *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OOOOOOO:Request",
            &dr.method, &dr.uri, &dr.headers, &dr.body,
            &dr.script, &dr.path, &dr.query)) {
        return NULL;
    }
    return _Request(&dr);
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
    "Response", NULL, ResponseFields, 4
};

static PyObject *
_Response(DeguResponse *dr)
{
    PyObject *ret = PyStructSequence_New(&ResponseType);
    if (ret != NULL) {
        _SET_NAMEDTUPLE_ITEM(ret, 0, dr->status)
        _SET_NAMEDTUPLE_ITEM(ret, 1, dr->reason)
        _SET_NAMEDTUPLE_ITEM(ret, 2, dr->headers)
        _SET_NAMEDTUPLE_ITEM(ret, 3, dr->body)
    }
    return ret;
}

static PyObject *
Response(PyObject *self, PyObject *args)
{
    DeguResponse dr = NEW_DEGU_RESPONSE;
    if (! PyArg_ParseTuple(args, "OOOO:Response",
            &dr.status, &dr.reason, &dr.headers, &dr.body)) {
        return NULL;
    }
    return _Response(&dr);
}


/* namedtuple init helper functions  */
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


/******************************************************************************
 * Python object validation and conversion
 ******************************************************************************/
static void
_type_error(const char *name, PyTypeObject *need, PyObject *got)
{
    PyErr_Format(PyExc_TypeError, "%s: need a %R; got a %R: %R",
        name, (PyObject *)need, Py_TYPE(got), got
    );
}

static bool
_check_type(const char *name, PyObject *obj, PyTypeObject *type) {
    if (Py_TYPE(obj) == type) {
        return true;
    }
    PyErr_Format(PyExc_TypeError,
        "%s: need a %R; got a %R: %R", name, (PyObject *)type, Py_TYPE(obj), obj
    );
    return false;
}

static bool
_check_type2(const char *name, PyObject *obj, PyTypeObject *type) {
    if (Py_TYPE(obj) == type) {
        return true;
    }
    PyErr_Format(PyExc_TypeError,
        "%s: need a %R; got a %R", name, (PyObject *)type, Py_TYPE(obj)
    );
    return false;
}

static inline bool
_check_int(const char *name, PyObject *obj)
{
    return _check_type(name, obj, &PyLong_Type);
}

static ssize_t
_get_size(const char *name, PyObject *obj, const size_t min, const size_t max)
{
    if (min > max || max > MAX_IO_SIZE) {
        Py_FatalError("_get_size(): min > max || max > MAX_IO_SIZE");
    }
    if (! _check_int(name, obj)) {
        return -1;
    }
    const size_t size = PyLong_AsSize_t(obj);
    if (PyErr_Occurred() || size < min || size > max) {
        PyErr_Clear();
        PyErr_Format(PyExc_ValueError,
            "need %zu <= %s <= %zu; got %R", min, name, max, obj
        );
        return -1;
    }
    return (ssize_t)size;
}

static ssize_t
_get_read_size(const char *name, PyObject *obj, const uint64_t remaining)
{
    if (obj != Py_None) {
        return _get_size(name, obj, 0, MAX_IO_SIZE);
    }
    if (remaining > MAX_IO_SIZE) {
        PyErr_Format(PyExc_ValueError,
            "would exceed max read size: %llu > %zu", remaining, MAX_IO_SIZE
        );
        return -1;
    }
    return (ssize_t)remaining;
}

static int64_t
_get_length(const char *name, PyObject *obj)
{
    if (! _check_int(name, obj)) {
        return -1;
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

static inline bool
_check_dict(const char *name, PyObject *obj)
{
    return _check_type(name, obj, &PyDict_Type);
}

static bool
_check_tuple(const char *name, PyObject *obj, ssize_t len)
{
    if (! _check_type2(name, obj, &PyTuple_Type)) {
        return false;
    }
    if (PyTuple_GET_SIZE(obj) != len) {
        PyErr_Format(PyExc_ValueError,
            "%s: need a %zd-tuple; got a %zd-tuple",
            name, len, PyTuple_GET_SIZE(obj)
        );
        return false;
    }
    return true;
}

static inline bool
_check_bytes(const char *name, PyObject *obj)
{
    return _check_type2(name, obj, &PyBytes_Type);
}

static ssize_t
_get_bytes_len(const char *name, PyObject *obj, const size_t max_len)
{
    if (max_len > MAX_IO_SIZE) {
        Py_FatalError("_get_bytes_len(): max_len > MAX_IO_SIZE");
    }
    if (! _check_bytes(name, obj)) {
        return -1;
    }
    const size_t len = (size_t)PyBytes_GET_SIZE(obj);
    if (len > max_len) {
        PyErr_Format(PyExc_ValueError,
            "need len(%s) <= %zu; got %zu", name, max_len, len
        );
        return -1;
    }
    return (ssize_t)len;
}

static bool
_check_headers(PyObject *headers)
{
    return _check_dict("headers", headers);
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

static bool
_check_str(const char *name, PyObject *obj)
{
    if (! _check_type(name, obj, &PyUnicode_Type)) {
        return false;
    }
    if (PyUnicode_READY(obj) != 0) {
        return false;
    }
    if (PyUnicode_MAX_CHAR_VALUE(obj) != 127) {
        PyErr_Format(PyExc_ValueError, "%s: contains non-ASCII: %R", name, obj);
        return false;
    }
    return true;
}


/******************************************************************************
 * Internal API for working with DeguSrc and DeguDst memory buffers
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
    // FIXME: should we allow slices of an empty src?
    if (src.buf == NULL || start > stop || stop > src.len) {
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
_find(DeguSrc src, DeguSrc end)
{
    const uint8_t *ptr = memmem(src.buf, src.len, end.buf, end.len);
    if (ptr == NULL) {
        return -1;
    }
    return ptr - src.buf;
}

static ssize_t
_find_in_slice(DeguSrc src, const size_t start, const size_t stop, DeguSrc end)
{
    ssize_t index = _find(_slice(src, start, stop), end);
    if (index < 0) {
        return -1;
    }
    return index + (ssize_t)start;
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

static inline DeguSrc
_src_from_str(const char *name, PyObject *obj)
{
    if (! _check_str(name, obj)) {
        return NULL_DeguSrc;
    }
    return (DeguSrc){
        PyUnicode_1BYTE_DATA(obj),
        (size_t)PyUnicode_GET_LENGTH(obj)
    };
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

static inline DeguDst
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

static inline size_t
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


/******************************************************************************
 * Range object
 ******************************************************************************/
static PyObject *
_Range_New(uint64_t start, uint64_t stop)
{
    Range *self = PyObject_New(Range, &RangeType);
    if (self == NULL) {
        return NULL;
    }
    self->start = start;
    self->stop = stop;
    return (PyObject *)PyObject_INIT(self, &RangeType);
}

static PyObject *
_Range_PyNew(PyObject *arg0, PyObject *arg1)
{
    int64_t start, stop;

    start = _get_length("start", arg0);
    if (start < 0) {
        return NULL;
    }
    stop = _get_length("stop", arg1);
    if (stop < 0) {
        return NULL;
    }
    if (start >= stop) {
        PyErr_Format(PyExc_ValueError,
            "need start < stop; got %lld >= %lld", start, stop
        );
        return NULL;
    }
    return _Range_New((uint64_t)start, (uint64_t)stop);
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "OO:Range", keys,
            &arg0, &arg1)) {
        return -1;
    }
    start = _get_length("start", arg0);
    if (start < 0) {
        return -1;
    }
    stop = _get_length("stop", arg1);
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
_Range_compare_with_same(Range *self, Range *other, int op)
{
    bool r = (self->start == other->start && self->stop == other->stop);
    if (op == Py_NE) {
        r = !r;
    }
    if (r) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
_Range_compare_with_str(Range *self, PyObject *other, int op)
{
    PyObject *this = NULL;
    PyObject *ret = NULL;
    _SET(this, Range_str(self))
    _SET(ret, PyObject_RichCompare(this, other, op))
error:
    Py_CLEAR(this);
    return ret;
}

static PyObject *
Range_richcompare(Range *self, PyObject *other, int op)
{
    if (op != Py_EQ && op != Py_NE) {
        PyErr_SetString(PyExc_TypeError, "unorderable type: Range()");
        return NULL;
    }
    if (Py_TYPE(other) == &RangeType) {
        return _Range_compare_with_same(self, (Range *)other, op);
    }
    if (PyUnicode_CheckExact(other)) {
        return _Range_compare_with_str(self, other, op);
    }
    PyErr_Format(PyExc_TypeError,
        "cannot compare Range() with %R", Py_TYPE(other)
    );
    return NULL;
}


/******************************************************************************
 * ContentRange object.
 ******************************************************************************/
static PyObject *
_ContentRange_New(uint64_t start, uint64_t stop, uint64_t total)
{
    ContentRange *self = PyObject_New(ContentRange, &ContentRangeType);
    if (self == NULL) {
        return NULL;
    }
    self->start = start;
    self->stop = stop;
    self->total = total;
    return (PyObject *)PyObject_INIT(self, &ContentRangeType);
}

static void
ContentRange_dealloc(ContentRange *self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ContentRange_init(ContentRange *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"start", "stop", "total", NULL};
    PyObject *arg0 = NULL;
    PyObject *arg1 = NULL;
    PyObject *arg2 = NULL;
    int64_t start, stop, total;

    if (! PyArg_ParseTupleAndKeywords(args, kw, "OOO:ContentRange", keys,
            &arg0, &arg1, &arg2)) {
        return -1;
    }
    start = _get_length("start", arg0);
    if (start < 0) {
        return -1;
    }
    stop = _get_length("stop", arg1);
    if (stop < 0) {
        return -1;
    }
    total = _get_length("total", arg2);
    if (total < 0) {
        return -1;
    }
    if (start >= stop || stop > total) {
        PyErr_Format(PyExc_ValueError,
            "need start < stop <= total; got (%lld, %lld, %lld)",
            start, stop, total
        );
        return -1;
    }
    self->start = (uint64_t)start;
    self->stop = (uint64_t)stop;
    self->total = (uint64_t)total;
    return 0;
}

static PyObject *
ContentRange_repr(ContentRange *self)
{
    return PyUnicode_FromFormat("ContentRange(%llu, %llu, %llu)",
        self->start, self->stop, self->total
    );
}

static PyObject *
ContentRange_str(ContentRange *self)
{
    return PyUnicode_FromFormat("bytes %llu-%llu/%llu",
        self->start, self->stop - 1, self->total
    );
}

static PyObject *
_ContentRange_compare_with_same(ContentRange *s, ContentRange *o, int op)
{
    bool r;
    r = (s->start == o->start && s->stop == o->stop && s->total == o->total);
    if (op == Py_NE) {
        r = !r;
    }
    if (r) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *
_ContentRange_compare_with_str(ContentRange *self, PyObject *other, int op)
{
    PyObject *this = NULL;
    PyObject *ret = NULL;
    _SET(this, ContentRange_str(self))
    _SET(ret, PyObject_RichCompare(this, other, op))
error:
    Py_CLEAR(this);
    return ret;
}

static PyObject *
ContentRange_richcompare(ContentRange *self, PyObject *other, int op)
{
    if (op != Py_EQ && op != Py_NE) {
        PyErr_SetString(PyExc_TypeError, "unorderable type: ContentRange()");
        return NULL;
    }
    if (Py_TYPE(other) == &ContentRangeType) {
        return _ContentRange_compare_with_same(self, (ContentRange *)other, op);
    }
    if (PyUnicode_CheckExact(other)) {
        return _ContentRange_compare_with_str(self, other, op);
    }
    PyErr_Format(PyExc_TypeError,
        "cannot compare ContentRange() with %R", Py_TYPE(other)
    );
    return NULL;
}


/******************************************************************************
 * Helper for clearing DeguHeaders, DeguRequest, DeguResponse, DeguChunk
 ******************************************************************************/
static void
_clear_degu_headers(DeguHeaders *dh)
{
    Py_CLEAR(dh->headers);
    Py_CLEAR(dh->body);
    dh->content_length = 0;
    dh->flags = 0;
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
    dr->s = 0;
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
 * Header parsing - internal C API
 ******************************************************************************/
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
_parse_range(DeguSrc src)
{
    ssize_t index;
    size_t offset;
    int64_t decimal;
    uint64_t start, stop;

    if (src.len > 39) {
        _value_error("range too long: %R...", _slice(src, 0, 39));
        return NULL;
    }
    if (src.len < 9 || !_equal(_slice(src, 0, 6), BYTES_EQ)) {
        goto bad_range;
    }
    DeguSrc inner = _slice(src, 6, src.len);

    /* Find the '-' separator */
    index = _find_in_slice(inner, 1, inner.len - 1, MINUS);
    if (index < 0) {
        goto bad_range;
    }
    offset = (size_t)index;

    /* start */
    decimal = _parse_decimal(_slice(inner, 0, offset));
    if (decimal < 0) {
        goto bad_range;
    }
    start = (uint64_t)decimal;

    /* stop */
    decimal = _parse_decimal(_slice(inner, offset + 1, inner.len));
    if (decimal < 0) {
        goto bad_range;
    }
    stop = (uint64_t)decimal + 1;

    /* Ensure (start < stop <= MAX_LENGTH) */
    if (start >= stop || stop > MAX_LENGTH) {
        goto bad_range;
    }
    return _Range_New(start, stop);

bad_range:
    _value_error("bad range: %R", src);
    return NULL;
}

static PyObject *
_parse_content_range(DeguSrc src)
{
    ssize_t index;
    size_t offset1, offset2;
    int64_t decimal;
    uint64_t start, stop, total;

    if (src.len > 56) {
        _value_error("content-range too long: %R...", _slice(src, 0, 56));
        return NULL;
    }
    if (src.len < 11 || !_equal(_slice(src, 0, 6), BYTES_SP)) {
        goto bad_content_range;
    }
    DeguSrc inner = _slice(src, 6, src.len);

    /* Find the '-' and '/' separators */
    index = _find_in_slice(inner, 1, inner.len - 3, MINUS);
    if (index < 0) {
        goto bad_content_range;
    }
    offset1 = (size_t)index;
    index = _find_in_slice(inner, offset1 + 2, inner.len - 1, SLASH);
    if (index < 0) {
        goto bad_content_range;
    }
    offset2 = (size_t)index;

    /* start */
    decimal = _parse_decimal(_slice(inner, 0, offset1));
    if (decimal < 0) {
        goto bad_content_range;
    }
    start = (uint64_t)decimal;

    /* stop */
    decimal = _parse_decimal(_slice(inner, offset1 + 1, offset2));
    if (decimal < 0) {
        goto bad_content_range;
    }
    stop = (uint64_t)decimal + 1;

    /* total */
    decimal = _parse_decimal(_slice(inner, offset2 + 1, inner.len));
    if (decimal < 0) {
        goto bad_content_range;
    }
    total = (uint64_t)decimal;

    /* Ensure (start < stop <= total <= MAX_LENGTH) */
    if (start >= stop || stop > total || total > MAX_LENGTH) {
        goto bad_content_range;
    }
    return _ContentRange_New(start, stop, total);

bad_content_range:
    _value_error("bad content-range: %R", src);
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
        dh->flags |= BIT_CONTENT_LENGTH;
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
        dh->flags |= BIT_TRANSFER_ENCODING;
    }
    else if (_equal(keysrc, RANGE)) {
        _SET_AND_INC(key, key_range)
        _SET(val, _parse_range(valsrc))
        dh->flags |= BIT_RANGE;
    }
    else if (_equal(keysrc, CONTENT_RANGE)) {
        _SET_AND_INC(key, key_content_range)
        _SET(val, _parse_content_range(valsrc))
        dh->flags |= BIT_CONTENT_RANGE;
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
_parse_headers(DeguSrc src, DeguDst scratch, DeguHeaders *dh,
               const bool isresponse)
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
    const uint8_t framing = dh->flags & FRAMING_MASK;
    if (framing == FRAMING_MASK) {
        PyErr_SetString(PyExc_ValueError, 
            "cannot have both content-length and transfer-encoding headers"
        );
        goto error; 
    }
    if (dh->flags & BIT_RANGE) {
        if (framing) {
            PyErr_SetString(PyExc_ValueError, 
                "cannot include range header and content-length/transfer-encoding"
            );
            goto error; 
        }
        if (isresponse) {
            PyErr_SetString(PyExc_ValueError, 
                "response cannot include a 'range' header"
            );
            goto error; 
        }
    }
    if ((dh->flags & BIT_CONTENT_RANGE) && !isresponse) {
        PyErr_SetString(PyExc_ValueError, 
            "request cannot include a 'content-range' header"
        );
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
        _SET(dh->body, _Body_New(rfile, dh->content_length))
    }
    else if (bodyflags == 2) {
        _SET(dh->body, _ChunkedBody_New(rfile))
    }
    return true;

error:
    return false;
}


/******************************************************************************
 * Header parsing - exported Python API
 ******************************************************************************/
static PyObject *
parse_header_name(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "y#:parse_header_name", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    if (src.len < 1) {
        PyErr_SetString(PyExc_ValueError, "header name is empty");
        return NULL;
    }
    if (src.len > SCRATCH_LEN) {
        _value_error("header name too long: %R...",  _slice(src, 0, SCRATCH_LEN));
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
parse_content_length(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (! PyArg_ParseTuple(args, "y#:parse_content_length", &buf, &len)) {
        return NULL;
    }
    const int64_t value = _parse_content_length((DeguSrc){buf, len});
    if (value < 0) {
        return NULL;
    }
    return PyLong_FromLongLong(value);
}

static PyObject *
parse_range(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (! PyArg_ParseTuple(args, "y#:parse_range", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    return _parse_range(src);
}

static PyObject *
parse_content_range(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;

    if (! PyArg_ParseTuple(args, "y#:parse_content_range", &buf, &len)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    return _parse_content_range(src);
}

static PyObject *
parse_headers(PyObject *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"src", "isresponse", NULL};
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *isresponse = Py_False;
    bool _isresponse;
    DeguHeaders dh = NEW_DEGU_HEADERS;

    if (! PyArg_ParseTupleAndKeywords(args, kw, "y#|O:parse_headers", keys,
            &buf, &len, &isresponse)) {
        return NULL;
    }
    if (isresponse == Py_False) {
        _isresponse = false;
    }
    else if (isresponse == Py_True) {
        _isresponse = true;
    }
    else {
        _type_error("isresponse", &PyBool_Type, isresponse);
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguDst scratch = _calloc_dst(SCRATCH_LEN);
    if (scratch.buf == NULL) {
        return NULL;
    }
    if (!_parse_headers(src, scratch, &dh, _isresponse)) {
        goto error;
    }
    goto cleanup;

error:
    Py_CLEAR(dh.headers);

cleanup:
    free(scratch.buf);
    return dh.headers;
}


/******************************************************************************
 * Request parsing - internal C API
 ******************************************************************************/
static PyObject *
_parse_method(DeguSrc src)
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
_parse_request(DeguSrc src, PyObject *rfile, DeguDst scratch, DeguRequest *dr)
{
    /* Check for empty premable */
    if (src.len == 0) {
        PyErr_SetString(EmptyPreambleError, "request preamble is empty");
        return false;
    }

    /* Parse request preamble */
    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguSrc line_src = _slice(src, 0, stop);
    DeguSrc headers_src = _slice(src, start, src.len);
    if (! _parse_request_line(line_src, dr)) {
        return false;
    }
    if (! _parse_headers(headers_src, scratch, (DeguHeaders *)dr, false)) {
        return false;
    }

    /* Create request body */
    return _create_body(rfile, (DeguHeaders *)dr);
}


/******************************************************************************
 * Request parsing - exported Python API
 ******************************************************************************/
static PyObject *
parse_method(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    if (! PyArg_ParseTuple(args, "s#:parse_method", &buf, &len)) {
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
    if (! PyArg_ParseTuple(args, "y#:parse_uri", &buf, &len)) {
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

static PyObject *
parse_request_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "y#:parse_request_line", &buf, &len)) {
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

    if (! PyArg_ParseTuple(args, "y#O:parse_request", &buf, &len, &rfile)) {
        return NULL;
    }
    DeguSrc src = {buf, len};
    DeguDst scratch = _calloc_dst(SCRATCH_LEN);
    if (scratch.buf == NULL) {
        return NULL;
    }

    DeguRequest dr = NEW_DEGU_REQUEST;
    if (_parse_request(src, rfile, scratch, &dr)) {
        ret = _Request(&dr);
    }
    free(scratch.buf);
    _clear_degu_request(&dr);
    return ret;
}


/******************************************************************************
 * Response parsing - internal C API
 ******************************************************************************/
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

static bool
_parse_response(PyObject *method, DeguSrc src, PyObject *rfile, DeguDst scratch,
                DeguResponse *dr)
{
    if (src.len == 0) {
        PyErr_SetString(EmptyPreambleError, "response preamble is empty");
        goto error;
    }
    const size_t stop = _search(src, CRLF);
    const size_t start = (stop < src.len) ? (stop + CRLF.len) : src.len;
    DeguSrc line_src = _slice(src, 0, stop);
    DeguSrc headers_src = _slice(src, start, src.len);
    if (! _parse_response_line(line_src, dr)) {
        goto error;
    }
    if (! _parse_headers(headers_src, scratch, (DeguHeaders *)dr, true)) {
        goto error;
    }
    /* Create request body */
    if (method == str_HEAD) {
        _SET_AND_INC(dr->body, Py_None);
    }
    else if (! _create_body(rfile, (DeguHeaders *)dr)) {
        goto error;
    }
    return true;

error:
    return false;
}


/******************************************************************************
 * Response parsing - exported Python API
 ******************************************************************************/
static PyObject *
parse_response_line(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;
    if (! PyArg_ParseTuple(args, "y#:parse_response_line", &buf, &len)) {
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
    PyObject *method = NULL;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;

    if (! PyArg_ParseTuple(args, "s#y#O:parse_response",
            &method_buf, &method_len, &buf, &len, &rfile)) {
        return NULL;
    }
    DeguDst scratch = _calloc_dst(SCRATCH_LEN);
    if (scratch.buf == NULL) {
        return NULL;
    }
    _SET(method, _parse_method((DeguSrc){method_buf, method_len}))
    DeguSrc src = {buf, len};
    if (_parse_response(method, src, rfile, scratch, &dr)) {
        _SET(ret, _Response(&dr))
    }

error:
    free(scratch.buf);
    Py_CLEAR(method);
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

    if (! PyArg_ParseTuple(args, "y#:parse_chunk_size", &buf, &len)) {
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

    if (! PyArg_ParseTuple(args, "y#:parse_chunk_extension", &buf, &len)) {
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

    if (! PyArg_ParseTuple(args, "y#:parse_chunk", &buf, &len)) {
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
    if (IS_BODY(body)) {
        return _set_content_length(headers, BODY(body)->content_length);
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

    if (! PyArg_ParseTuple(args, "OO:set_output_headers", &headers, &body)) {
        return NULL;
    }
    if (! _set_output_headers(headers, body)) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static bool
_validate_key(PyObject *key)
{
    size_t i;
    uint8_t bits;

    if (!PyUnicode_CheckExact(key)) {
        _type_error("key", &PyUnicode_Type, key);
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
_format_request(DeguRequest *dr)
{
    PyObject *h = NULL;  /* str containing header lines */
    PyObject *str = NULL;  /* str version of request preamble */
    PyObject *ret = NULL;  /* bytes version of request preamble */

    _SET(h, _format_headers(dr->headers))
    _SET(str,
        PyUnicode_FromFormat("%S %S HTTP/1.1\r\n%S\r\n", dr->method, dr->uri, h)
    )
    _SET(ret, PyUnicode_AsASCIIString(str))
    goto cleanup;

error:
    Py_CLEAR(ret);

cleanup:
    Py_CLEAR(h);
    Py_CLEAR(str);
    return  ret;
}

static inline ssize_t
_get_status(PyObject *obj)
{
    return _get_size("status", obj, 100, 599);
}

static bool
_copy_into(DeguOutput *o, DeguSrc src)
{
    DeguDst dst = _dst_slice(o->dst, o->stop, o->dst.len);
    if (src.buf == NULL) {
        return false;  /* Assuming an error has already been set */
    }
    if (src.len == 0) {
        return true;
    }
    if (src.len > dst.len) {
        PyErr_Format(PyExc_ValueError,
            "output too large: %zu > %zu", src.len, o->dst.len
        );
        return false;
    }
    o->stop += _copy(dst, src);
    return true;
}

#define _COPY_INTO(o, src) \
    if (! _copy_into(o, src)) { \
        goto error; \
    }

typedef struct {
    uint8_t *buf;
    size_t len;
    PyObject *val;
} HLine;

#define HMAX 16

static bool
_render_header_line(DeguOutput *o, HLine *l)
{
    DeguSrc key = {l->buf, l->len};
    PyObject *val_str = NULL;
    bool ret = true;

    _COPY_INTO(o, key)
    _COPY_INTO(o, SEP)
    if (Py_TYPE(l->val) == &PyUnicode_Type) {
        _COPY_INTO(o, _src_from_str("val", l->val))
    }
    else {
        _SET(val_str, PyObject_Str(l->val))
        _COPY_INTO(o, _src_from_str("val", val_str))
    }
    _COPY_INTO(o, CRLF)
    goto cleanup;

error:
    ret = false;

cleanup:
    Py_CLEAR(val_str);
    return ret;
}

static int
_hline_cmp(const void *A, const void *B)
{
    HLine *a = (HLine *)A;
    HLine *b = (HLine *)B;
    return memcmp(a->buf, b->buf, _min(a->len, b->len));
} 

static bool
_render_headers_sorted(DeguOutput *o, PyObject *headers, const size_t count)
{
    ssize_t pos = 0;
    PyObject *key = NULL;
    PyObject *val = NULL;
    HLine lines[HMAX];
    size_t i;

    if (count > HMAX) {
        PyErr_Format(PyExc_ValueError,
            "need len(headers) < %zu; got %zu", HMAX, count
        );
        return false;
    }
    i = 0;
    while (PyDict_Next(headers, &pos, &key, &val)) {
        if (! _check_str("key", key)) {
            return false;
        }
        lines[i] = (HLine) {
            PyUnicode_1BYTE_DATA(key),
            (size_t)PyUnicode_GET_LENGTH(key),
            val
        }; 
        i++;
    }
    qsort(lines, count, sizeof(HLine), _hline_cmp);
    for (i = 0; i < count; i++) {
        if (! _render_header_line(o, &lines[i])) {
            return false;
        } 
    }
    return true;
}

static bool
_render_headers_fast(DeguOutput *o, PyObject *headers, const size_t count)
{
    ssize_t pos = 0;
    PyObject *key = NULL;
    PyObject *val = NULL;
    HLine line;

    while (PyDict_Next(headers, &pos, &key, &val)) {
        if (! _check_str("key", key)) {
            return false;
        }
        line = (HLine) {
            PyUnicode_1BYTE_DATA(key),
            (size_t)PyUnicode_GET_LENGTH(key),
            val
        }; 
        if (! _render_header_line(o, &line)) {
            return false;
        } 
    }
    return true;
}

static bool
_render_headers(DeguOutput *o, PyObject *headers)
{
    if (! _check_headers(headers)) {
        return false;
    }
    const size_t count = (size_t)PyDict_Size(headers);
    if (count == 0) {
        return true;
    }
    if (count > 1) {
        return _render_headers_sorted(o, headers, count);
    }
    return _render_headers_fast(o, headers, count);
}

static PyObject *
render_headers(PyObject *self, PyObject *args)
{
    Py_buffer pybuf;
    PyObject *headers = NULL;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "w*O:render_headers", &pybuf, &headers)) {
        return NULL;
    }
    DeguDst dst = _dst_frompybuf(&pybuf);
    DeguOutput o = {dst, 0};
    if (_render_headers(&o, headers)) {
        ret = PyLong_FromSize_t(o.stop);
    }
    PyBuffer_Release(&pybuf);
    return ret;
}

static bool
_render_request(DeguOutput *o, DeguRequest *r)
{ 
    _COPY_INTO(o, _src_from_str("method", r->method))
    _COPY_INTO(o, SPACE)
    _COPY_INTO(o, _src_from_str("uri", r->uri))
    _COPY_INTO(o, REQUEST_PROTOCOL)
    _COPY_INTO(o, CRLF)
    if (! _render_headers(o, r->headers)) {
        return false;
    }
    _COPY_INTO(o, CRLF)
    return true;

error:
    return false;
}

static PyObject *
render_request(PyObject *self, PyObject *args)
{
    Py_buffer pybuf;
    DeguRequest r = NEW_DEGU_REQUEST;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "w*OOO:render_request",
            &pybuf, &r.method, &r.uri, &r.headers)) {
        return NULL;
    }
    DeguDst dst = _dst_frompybuf(&pybuf);
    DeguOutput o = {dst, 0};
    if (_render_request(&o, &r)) {
        ret = PyLong_FromSize_t(o.stop);
    }
    PyBuffer_Release(&pybuf);
    return ret;
}

static bool
_render_status(DeguOutput *o, const size_t s)
{
    if (o->stop + 4 > o->dst.len) {
        PyErr_Format(PyExc_ValueError,
            "output too large: %zu > %zu", o->stop + 4, o->dst.len
        );
        return false;
    }
    DeguDst dst = _dst_slice(o->dst, o->stop, o->stop + 4);
    dst.buf[0] = 48 + (s / 100);
    dst.buf[1] = 48 + (s % 100 / 10);
    dst.buf[2] = 48 + (s % 10);
    dst.buf[3] = ' ';
    o->stop += 4;
    return true;
}

static bool
_render_response(DeguOutput *o, DeguResponse *r)
{
    _COPY_INTO(o, RESPONSE_PROTOCOL)
    if (! _render_status(o, r->s)) {
        return false;
    }
    _COPY_INTO(o, _src_from_str("reason", r->reason))
    _COPY_INTO(o, CRLF)
    if (! _render_headers(o, r->headers)) {
        return false;
    }
    _COPY_INTO(o, CRLF)
    return true;

error:
    return false;
}

static PyObject *
render_response(PyObject *self, PyObject *args)
{
    Py_buffer pybuf;
    DeguResponse r = NEW_DEGU_RESPONSE;
    ssize_t status;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "w*OOO:render_response",
            &pybuf, &r.status, &r.reason, &r.headers)) {
        return NULL;
    }
    status = _get_status(r.status);
    if (status < 0) {
        return NULL;
    }
    r.s = (size_t)status;
    DeguDst dst = _dst_frompybuf(&pybuf);
    DeguOutput o = {dst, 0};
    if (_render_response(&o, &r)) {
        ret = PyLong_FromSize_t(o.stop);
    }
    PyBuffer_Release(&pybuf);
    return ret;
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
    if (! PyArg_ParseTuple(args, "OOO:set_default_header",
            &headers, &key, &val)) {
        return NULL;
    }
    if (! _set_default_header(headers, key, val)) {
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *
format_headers(PyObject *self, PyObject *args)
{
    PyObject *headers = NULL;
    if (! PyArg_ParseTuple(args, "O:format_headers", &headers)) {
        return NULL;
    }
    return _format_headers(headers);
}

static PyObject *
format_request(PyObject *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    DeguRequest dr = NEW_DEGU_REQUEST;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "s#OO:format_request",
            &buf, &len, &dr.uri, &dr.headers)) {
        return NULL;
    }
    _SET(dr.method, _parse_method((DeguSrc){buf, len}))
    _SET(ret, _format_request(&dr))

error:
    Py_CLEAR(dr.method);
    return ret;
}

static PyObject *
format_response(PyObject *self, PyObject *args)
{
    PyObject *status = NULL;
    PyObject *reason = NULL;
    PyObject *headers = NULL;

    if (! PyArg_ParseTuple(args, "OOO:format_response",
            &status, &reason, &headers)) {
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
_unpack_chunk(PyObject *chunk, DeguChunk *dc)
{
    if (chunk == NULL || dc->key != NULL || dc->val != NULL || dc->data != NULL || dc->size != 0) {
        Py_FatalError("_unpack_chunk(): bad internal call");
    }
    PyObject *ext = NULL;
    bool ret = true;

    /* chunk itself */
    if (! _check_tuple("chunk", chunk, 2)) {
        goto error;
    }

    /* chunk[0]: extension */
    _SET(ext, PyTuple_GET_ITEM(chunk, 0))
    if (ext != Py_None) {
        if (! _check_tuple("chunk[0]", ext, 2)) {
            goto error;
        }
        _SET_AND_INC(dc->key, PyTuple_GET_ITEM(ext, 0))
        _SET_AND_INC(dc->val, PyTuple_GET_ITEM(ext, 1))
    }

    /* chunk[1]: data */
    _SET_AND_INC(dc->data, PyTuple_GET_ITEM(chunk, 1))
    const ssize_t size = _get_bytes_len("chunk[1]", dc->data, MAX_IO_SIZE);
    if (size < 0) {
        goto error;
    }
    dc->size = (size_t)size;
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

    if (! PyArg_ParseTuple(args, "O:format_chunk", &chunk)) {
        return NULL;
    }
    if (_unpack_chunk(chunk, &dc)) {
        return _format_chunk(&dc);
    }
    return NULL;
}


/******************************************************************************
 * IO helpers for calling recv_into(), send(), etc.
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
    size = _get_size("received", int_size, 0, dst.len);
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
    size = _get_size("sent", int_size, 0, src.len);
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


/******************************************************************************
 * Abstract internal Reader/Writer fast-paths vs. Python file-like API.
 ******************************************************************************/

/* DeguRObj: absracted reader object */
static void
_clear_robj(DeguRObj *r)
{
    Py_CLEAR(r->readinto);
    Py_CLEAR(r->readline);
}

static bool
_init_robj(PyObject *rfile, DeguRObj *r, const bool readline)
{
    if (rfile == NULL) {
        Py_FatalError("_init_robj(): rfile == NULL");
    }
    if (IS_READER(rfile)) {
        _SET(r->reader, READER(rfile))
    }
    else {
        _SET(r->readinto, _getcallable("rfile", rfile, attr_readinto))
        if (readline) {
            _SET(r->readline, _getcallable("rfile", rfile, attr_readline))
        }
    }
    return true;

error:
    return false;
}

static bool
_readinto_from(DeguRObj *r, DeguDst dst)
{
    if (r->reader != NULL) {
        return _Reader_readinto(r->reader, dst);
    }
    if (r->readinto != NULL) {
        return _readinto(r->readinto, dst);
    }
    Py_FatalError("_readinto_from(): r->reader == NULL && r->readinto == NULL");
    return false;
}


/* DeguWObj: absracted writer object */
static void
_clear_wobj(DeguWObj *w)
{
    Py_CLEAR(w->write);
}

static bool
_init_wobj(PyObject *wfile, DeguWObj *w)
{
    if (wfile == NULL) {
        Py_FatalError("_init_wobj(): wfile == NULL");
    }
    if (IS_WRITER(wfile)) {
        _SET(w->writer, WRITER(wfile))
    }
    else {
        _SET(w->write, _getcallable("wfile", wfile, attr_write))
    }
    return true;

error:
    return false;
}

static ssize_t
_write_to(DeguWObj *w, DeguSrc src)
{
    if (w->writer != NULL) {
        return _Writer_write(w->writer, src);
    }
    if (w->write != NULL) {
        return _write(w->write, src);
    }
    Py_FatalError("_write_to: w->writer == NULL && w->write == NULL");
    return -1;
}


/* Chunk helpers to abstract Reader.read_until() vs. wfile.readline() */
static bool
_read_chunkline(PyObject *readline, DeguChunk *dc)
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
    _SET(line, PyObject_CallFunctionObjArgs(readline, int_MAX_LINE_LEN, NULL))
    if (! PyBytes_CheckExact(line)) {
        PyErr_Format(PyExc_TypeError,
            "need a <class 'bytes'>; readline() returned a %R", Py_TYPE(line)
        );
        goto error;
    }
    DeguSrc src = _frombytes(line);
    if (src.len > MAX_LINE_LEN) {
        PyErr_Format(PyExc_ValueError,
            "readline() returned too many bytes: %zu > %zu",
            src.len, MAX_LINE_LEN
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
_read_chunkline_from(DeguRObj *r, DeguChunk *dc)
{
    if (r->reader != NULL) {
        return _Reader_read_chunkline(r->reader, dc);
    }
    if (r->readline != NULL) {
        return _read_chunkline(r->readline, dc);
    }
    Py_FatalError("_readinto_from(): r->reader == NULL && r->readinto == NULL");
    return false;
}

static bool
_read_chunk_from(DeguRObj *r, DeguChunk *dc)
{
    if (! _read_chunkline_from(r, dc)) {
        goto error;
    }
    const ssize_t size = (ssize_t)dc->size + 2;
    _SET(dc->data, PyBytes_FromStringAndSize(NULL, size))
    DeguDst dst = _dst_frombytes(dc->data);
    if (! _readinto_from(r, dst)) {
        goto error;
    }
    DeguSrc end = _slice_src_from_dst(dst, dst.len - 2, dst.len);
    if (! _equal(end, CRLF)) {
        _value_error("bad chunk data termination: %R", end);
        goto error;
    }
    return true;

error:
    return false;
}

static ssize_t
_write_chunk_to(DeguWObj *w, DeguChunk *dc)
{
    PyObject *line = NULL;
    ssize_t total = 0;
    ssize_t wrote;

    _SET(line, _format_chunk(dc))
    DeguSrc src = _frombytes(line);
    wrote = _write_to(w, src);
    if (wrote < 0) {
        goto error;
    }
    total += wrote;

    DeguSrc data = _frombytes(dc->data);
    if (data.len > 0) {
        wrote = _write_to(w, data);
        if (wrote < 0) {
            goto error;
        }
        total += wrote;
    }

    if (data.len == dc->size) {
        wrote = _write_to(w, CRLF);
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


/******************************************************************************
 * Exported read_chunk(), write_chunk() Python methods
 ******************************************************************************/
static PyObject *
readchunk(PyObject *self, PyObject *args)
{
    PyObject *rfile = NULL;
    PyObject *ret = NULL;
    DeguRObj r = NEW_DEGU_ROBJ;
    DeguChunk dc = NEW_DEGU_CHUNK;

    if (! PyArg_ParseTuple(args, "O:readchunk", &rfile)) {
        return NULL;
    }
    if (_init_robj(rfile, &r, true) && _read_chunk_from(&r, &dc)) {
        ret = _pack_chunk(&dc);
    }
    _clear_robj(&r);
    _clear_degu_chunk(&dc);
    return ret;
}

static PyObject *
write_chunk(PyObject *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *chunk = NULL;
    PyObject *ret = NULL;
    ssize_t total;
    DeguWObj w = NEW_DEGU_WOBJ;
    DeguChunk dc = NEW_DEGU_CHUNK;

    if (! PyArg_ParseTuple(args, "OO:write_chunk", &wfile, &chunk)) {
        return NULL;
    }
    if (_init_wobj(wfile, &w) && _unpack_chunk(chunk, &dc)) {
        total = _write_chunk_to(&w, &dc);
        if (total > 0) {
            ret = PyLong_FromSsize_t(total);
        }
    }
    _clear_wobj(&w);
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
    static char *keys[] = {"sock", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kw, "O:Reader", keys, &sock)) {
        return -1;
    }
    _SET(self->recv_into, _getcallable("sock", sock, attr_recv_into))
    _SET(self->buf, _calloc_buf(BUF_LEN + SCRATCH_LEN))
    self->rawtell = 0;
    self->start = 0;
    self->stop = 0;
    return 0;

error:
    return -1;
}

static DeguSrc
_Reader_preamble_src(Reader *self)
{
    return (DeguSrc){self->buf, BUF_LEN};
}

static DeguDst
_Reader_scratch_dst(Reader *self)
{
    return (DeguDst){self->buf + BUF_LEN, SCRATCH_LEN};
}

static DeguSrc
_Reader_peek(Reader *self, const size_t size)
{
    if (self->start >= self->stop && self->start != 0) {
        Py_FatalError("_Reader_peak: start >= stop && start != 0");
    }
    DeguSrc cur = _slice(_Reader_preamble_src(self), self->start, self->stop);
    if (cur.len == 0) {
        return cur;
    }
    return _slice(cur, 0, _min(cur.len, size));
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
_Reader_read_until(Reader *self, const size_t size, DeguSrc end)
{
    ssize_t index = -1;
    ssize_t added;

    if (_isempty(end)) {
        Py_FatalError("_Reader_read_until(): bad internal call");
    }
    DeguDst dst = {self->buf, BUF_LEN};
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
Reader_rawtell(Reader *self) {
    return PyLong_FromUnsignedLongLong(self->rawtell);
}

static PyObject *
Reader_tell(Reader *self) {
    DeguSrc cur = _Reader_peek(self, BUF_LEN);
    if (cur.len > self->rawtell) {
        Py_FatalError("Reader_tell(): cur.len > self->rawtell");
    }
    return PyLong_FromUnsignedLongLong(self->rawtell - cur.len);
}

static PyObject *
Reader_expose(Reader *self) {
    return _tobytes(_Reader_preamble_src(self));
}

static PyObject *
Reader_peek(Reader *self, PyObject *args) {
    size_t size = 0;
    if (! PyArg_ParseTuple(args, "n", &size)) {
        return NULL;
    }
    return _tobytes(_Reader_peek(self, size));
}

static PyObject *
Reader_read_until(Reader *self, PyObject *args)
{
    size_t size = 0;
    uint8_t *buf = NULL;
    size_t len = 0;

    if (! PyArg_ParseTuple(args, "ny#:read_until", &size, &buf, &len)) {
        return NULL;
    }
    DeguSrc end = {buf, len};
    if (end.len == 0) {
        PyErr_SetString(PyExc_ValueError, "end cannot be empty");
        return NULL;
    }
    return _tobytes(_Reader_read_until(self, size, end));
}


static bool
_Reader_read_request(Reader *self, DeguRequest *dr) {
    DeguSrc src = _Reader_read_until(self, BUF_LEN, CRLFCRLF);
    if (src.buf == NULL) {
        return false;
    }
    PyObject *rfile = (PyObject *)self;
    DeguDst scratch = _Reader_scratch_dst(self);
    return _parse_request(src, rfile, scratch, dr);
}


static PyObject *
Reader_read_request(Reader *self) {
    DeguRequest dr = NEW_DEGU_REQUEST;
    PyObject *ret = NULL;

    if (_Reader_read_request(self, &dr)) {
        ret = _Request(&dr);
    }
    _clear_degu_request(&dr);
    return ret;
}

static bool
_Reader_read_response(Reader *self, PyObject *method, DeguResponse *dr)
{
    DeguSrc src = _Reader_read_until(self, BUF_LEN, CRLFCRLF);
    if (src.buf == NULL) {
        return false;
    }
    PyObject *rfile = (PyObject *)self;
    DeguDst scratch = _Reader_scratch_dst(self);
    return _parse_response(method, src, rfile, scratch, dr);
}

static PyObject *
Reader_read_response(Reader *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *method = NULL;
    PyObject *ret = NULL;
    DeguResponse dr = NEW_DEGU_RESPONSE;

    if (! PyArg_ParseTuple(args, "s#:read_response", &buf, &len)) {
        return NULL;
    }
    _SET(method, _parse_method((DeguSrc){buf, len}))
    if (_Reader_read_response(self, method, &dr)) {
        _SET(ret, _Response(&dr))
    }

error:
    Py_CLEAR(method);
    _clear_degu_response(&dr);
    return ret;
}

static bool
_Reader_read_chunkline(Reader *self, DeguChunk *dc) {
    DeguSrc line = _Reader_read_until(self, 4096, CRLF);
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
Reader_readinto(Reader *self, PyObject *args)
{
    Py_buffer pybuf;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "w*", &pybuf)) {
        goto error;
    }
    if (pybuf.len < 1 || (size_t)pybuf.len > MAX_IO_SIZE) {
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
    if (self->buf != NULL) {
        free(self->buf);
        self->buf = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Writer_init(Writer *self, PyObject *args, PyObject *kw)
{
    int ret = 0;
    PyObject *sock = NULL;
    static char *keys[] = {"sock", NULL};
    if (! PyArg_ParseTupleAndKeywords(args, kw, "O:Writer", keys, &sock)) {
        goto error;
    }
    _SET(self->send, _getcallable("sock", sock, attr_send))
    _SET(self->buf, _calloc_buf(BUF_LEN))
    self->tell = 0;
    self->stop = 0;
    goto cleanup;

error:
    ret = -1;

cleanup:
    return ret;
}

static DeguDst
_Writer_get_dst(Writer *self)
{
    DeguDst raw = {self->buf, BUF_LEN};
    return _dst_slice(raw, self->stop, raw.len);
}

static DeguSrc
_Writer_get_src(Writer *self)
{
    DeguSrc raw = {self->buf, BUF_LEN};
    return _slice(raw, 0, self->stop);
}

static ssize_t
_Writer_raw_write(Writer *self, DeguSrc src)
{
    const ssize_t wrote = _write(self->send, src);
    if (wrote > 0) {
        self->tell += (uint64_t)wrote;
    }
    return wrote;
}

static bool
_Writer_flush(Writer *self)
{
    if (self->stop == 0) {
        return true;
    }
    DeguSrc src = _Writer_get_src(self);
    self->stop = 0;
    if (_Writer_raw_write(self, src) < 0) {
        return false;
    }
    return true;
}

static ssize_t
_Writer_write(Writer *self, DeguSrc src)
{
    if (self->stop == 0) {
        return _Writer_raw_write(self, src);
    }

    DeguDst dst = _Writer_get_dst(self);
    if (src.len <= dst.len) {
        self->stop += _copy(dst, src);
        if (! _Writer_flush(self)) {
            return -1;
        }
    }
    else {
        if (! _Writer_flush(self)) {
            return -1;
        }
        if (_Writer_raw_write(self, src) < 0) {
            return -1;
        }
    }
    return (ssize_t)src.len;
}

static int64_t
_Writer_write_body(Writer *self, PyObject *body)
{
    DeguWObj w = {self, NULL};

    if (body == Py_None) {
        return 0;
    }
    if (PyBytes_CheckExact(body)) {
        return _Writer_write(self, _frombytes(body));
    }
    if (IS_BODY(body)) {
        return _Body_write_to(BODY(body), &w);
    }
    if (IS_CHUNKED_BODY(body)) {
        return _ChunkedBody_write_to(CHUNKED_BODY(body), &w);
    }
    if (IS_BODY_ITER(body)) {
        return _BodyIter_write_to(BODY_ITER(body), &w);
    }
    if (IS_CHUNKED_BODY_ITER(body)) {
        return _ChunkedBodyIter_write_to(CHUNKED_BODY_ITER(body), &w);
    }

    PyErr_Format(PyExc_TypeError, "bad body type: %R: %R", Py_TYPE(body), body);
    return -1;
}

static int64_t
_Writer_write_output(Writer *self, DeguSrc preamble, PyObject *body)
{
    if (self->stop != 0) {
        Py_FatalError("_Writer_write_output(): self->stop != 0");
    }

    const uint64_t origtell = self->tell;
    uint64_t total = preamble.len;
    int64_t wrote;
    DeguDst dst = _Writer_get_dst(self);

    /* Buffer the preamble */
    self->stop += _copy(dst, preamble);

    /* Write the body */
    wrote = _Writer_write_body(self, body);
    if (wrote < 0) {
        return -1;
    }
    total += (uint64_t)wrote;

    if (! _Writer_flush(self)) {
        return -1;
    }

    /* Sanity check */
    if (origtell + total != self->tell) {
        PyErr_Format(PyExc_ValueError,
            "%llu + %llu != %llu", origtell, total, self->tell
        );
        return -1;
    }
    return (int64_t)total;
}


/*******************************************************************************
 * Writer: Public API:
 *     Writer.close()
 *     Writer.tell()
 *     Writer.write()
 */
static PyObject *
Writer_tell(Writer *self) {
    return PyLong_FromUnsignedLongLong(self->tell);
}

static PyObject *
Writer_write_output(Writer *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    PyObject *body = NULL;
    int64_t total;

    if (! PyArg_ParseTuple(args, "y#O", &buf, &len, &body)) {
        return NULL;
    }
    DeguSrc preamble_src = {buf, len};
    total = _Writer_write_output(self, preamble_src, body);
    if (total < 0) {
        return NULL;
    }
    return PyLong_FromLongLong(total);
}

static int64_t
_Writer_write_request(Writer *self, DeguRequest *dr)
{
    int64_t wrote;
    DeguOutput o = {_Writer_get_dst(self), 0};

    if (! _set_output_headers(dr->headers, dr->body)) {
        return -1;
    }
    if (! _render_request(&o, dr)) {
        return -1;
    }
    self->stop = o.stop;
    wrote = _Writer_write_body(self, dr->body);
    if (wrote < 0) {
        return -1;
    }
    if (! _Writer_flush(self)) {
        return -1;
    }
    return wrote + (int64_t)o.stop;
}

static int64_t
_Writer_write_response(Writer *self, DeguResponse *dr)
{
    int64_t wrote;
    DeguOutput o = {_Writer_get_dst(self), 0};

    if (! _set_output_headers(dr->headers, dr->body)) {
        return -1;
    }
    if (! _render_response(&o, dr)) {
        return -1;
    }
    self->stop = o.stop;
    wrote = _Writer_write_body(self, dr->body);
    if (wrote < 0) {
        return -1;
    }
    if (! _Writer_flush(self)) {
        return -1;
    }
    return wrote + (int64_t)o.stop;
}

static PyObject *
Writer_write_request(Writer *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    DeguRequest dr = NEW_DEGU_REQUEST;
    int64_t wrote = -2;

    if (! PyArg_ParseTuple(args, "s#UOO:",
            &buf, &len, &dr.uri, &dr.headers, &dr.body)) {
        return NULL;
    }
    _SET(dr.method, _parse_method((DeguSrc){buf, len}))
    wrote = _Writer_write_request(self, &dr);
    goto cleanup;

error:
    wrote = -1;

cleanup:
    Py_CLEAR(dr.method);
    if (wrote < 0) {
        return NULL;
    }
    return PyLong_FromLongLong(wrote);
}

static PyObject *
Writer_write_response(Writer *self, PyObject *args)
{
    DeguResponse dr = NEW_DEGU_RESPONSE;
    ssize_t s;

    if (! PyArg_ParseTuple(args, "OUOO:",
            &dr.status, &dr.reason, &dr.headers, &dr.body)) {
        return NULL;
    }
    s = _get_status(dr.status);
    if (s < 0) {
        return NULL;
    }
    dr.s = (size_t)s;
    const int64_t total = _Writer_write_response(self, &dr);
    if (total < 0) {
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

static const char *
_rfile_repr(PyObject *rfile)
{
    static const char *repr_null =   "<NULL>";
    static const char *repr_reader = "<reader>";
    static const char *repr_rfile =  "<rfile>";
    if (rfile == NULL) {
        return repr_null;
    }
    if (IS_READER(rfile)) {
        return repr_reader;
    }
    return repr_rfile;
}


/******************************************************************************
 * Body object.
 ******************************************************************************/
static void
Body_dealloc(Body *self)
{
    Py_CLEAR(self->rfile);
    _clear_robj(&(self->robj));
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static bool
_Body_fill_args(Body *self, PyObject *rfile, const uint64_t content_length)
{
    if (rfile == NULL || content_length > MAX_LENGTH) {
        Py_FatalError("_Body_fill_args(): bad internal call");
    }
    _SET_AND_INC(self->rfile, rfile)
    if (! _init_robj(rfile, &(self->robj), false)) {
        goto error;
    }
    self->remaining = self->content_length = content_length;
    self->state = BODY_READY;
    self->chunked = false;
    return true;

error:
    self->state = BODY_ERROR;
    Py_CLEAR(self->rfile);
    _clear_robj(&(self->robj));
    return false;
}

static PyObject *
_Body_New(PyObject *rfile, const uint64_t content_length)
{
    Body *self = PyObject_New(Body, &BodyType);
    if (self == NULL) {
        return NULL;
    }
    self->rfile = NULL;
    self->robj = NEW_DEGU_ROBJ;
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "OO:Body", keys,
                &rfile, &content_length)) {
        goto error;
    }
    _content_length = _get_length("content_length", content_length);
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

static PyObject *
Body_repr(Body *self) {
    return PyUnicode_FromFormat("Body(%s, %llu)",
        _rfile_repr(self->rfile), self->content_length
    );
}

static bool
_Body_readinto(Body *self, DeguDst dst)
{
    if (dst.len > self->remaining) {
        Py_FatalError("_Body_readinto(): bad internal call");
    }
    if (_readinto_from(&(self->robj), dst)) {
        self->remaining -= dst.len;
        return true;
    }
    self->state = BODY_ERROR;
    return false;
}

static int64_t
_Body_write_to(Body *self, DeguWObj *w)
{
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
    iosize = _min(IO_SIZE, self->remaining);
    dst_buf = _calloc_buf(iosize);
    if (dst_buf == NULL) {
        goto error;
    }
    DeguDst dst = {dst_buf, iosize};
    while (self->remaining > 0) {
        size = _min(dst.len, self->remaining);
        if (! _Body_readinto(self, _dst_slice(dst, 0, size))) {
            goto error;
        }
        wrote = _write_to(w, _slice_src_from_dst(dst, 0, size));
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
    DeguWObj w = NEW_DEGU_WOBJ;
    int64_t total;

    if (! PyArg_ParseTuple(args, "O", &wfile)) {
        return NULL;
    }
    if (_init_wobj(wfile, &w)) {
        total = _Body_write_to(self, &w);
        if (total >= 0) {
            ret = PyLong_FromLongLong(total);
        }
    }
    _clear_wobj(&w);
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "|O", keys, &pysize)) {
        return NULL;
    }
    const ssize_t size = _get_read_size("size", pysize, self->remaining);
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
    _clear_robj(&(self->robj));
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static bool
_ChunkedBody_fill_args(ChunkedBody *self, PyObject *rfile)
{
    _SET_AND_INC(self->rfile, rfile)
    if (! _init_robj(rfile, &(self->robj), true)) {
        goto error;
    }
    self->chunked = true;
    self->state = BODY_READY;
    return true;

error:
    Py_CLEAR(self->rfile);
    _clear_robj(&(self->robj));
    self->state = BODY_ERROR;
    return false;
}

static PyObject *
_ChunkedBody_New(PyObject *rfile)
{
    ChunkedBody *self = PyObject_New(ChunkedBody, &ChunkedBodyType);
    if (self == NULL) {
        return NULL;
    }
    self->rfile = NULL;
    self->robj = NEW_DEGU_ROBJ;
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "O:ChunkedBody", keys,
            &rfile)) {
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

static PyObject *
ChunkedBody_repr(ChunkedBody *self) {
    return PyUnicode_FromFormat("ChunkedBody(%s)", _rfile_repr(self->rfile));

}

static bool
_ChunkedBody_readchunk(ChunkedBody *self, DeguChunk *dc)
{
    if (! _check_body_state("ChunkedBody", self->state, BODY_STARTED)) {
        return false;
    }
    self->state = BODY_STARTED;
    if (! _read_chunk_from(&(self->robj), dc)) {
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
_ChunkedBody_write_to(ChunkedBody *self, DeguWObj *w)
{
    DeguChunk dc = NEW_DEGU_CHUNK;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;

    if (! _check_body_state("ChunkedBody", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;
    while (self->state < BODY_CONSUMED) {
        if (! _ChunkedBody_readchunk(self, &dc)) {
            goto error; 
        }
        wrote = _write_chunk_to(w, &dc);
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
    _clear_degu_chunk(&dc);
    return ret;
}

static PyObject *
ChunkedBody_write_to(ChunkedBody *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;
    DeguWObj w = NEW_DEGU_WOBJ;
    int64_t total;

    if (! PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    if (_init_wobj(wfile, &w)) {
        total = _ChunkedBody_write_to(self, &w);
        if (total >= 0) {
            ret = PyLong_FromLongLong(total);
        }
    }
    _clear_wobj(&w);
    return ret;
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "OO:BodyIter", keys,
            &source, &content_length)) {
        goto error;
    }
    _SET_AND_INC(self->source, source)
    _content_length = _get_length("content_length", content_length);
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
_BodyIter_write_to(BodyIter *self, DeguWObj *w)
{
    PyObject *iterator = NULL;
    PyObject *part = NULL;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2;

    if (! _check_body_state("BodyIter", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;
    _SET(iterator, PyObject_GetIter(self->source))
    while ((part = PyIter_Next(iterator))) {
        if (! _check_bytes("BodyIter source item", part)) {
            goto error;
        }
        wrote = _write_to(w, _frombytes(part));
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
    Py_CLEAR(iterator);
    Py_CLEAR(part);
    return ret;
}

static PyObject *
BodyIter_write_to(BodyIter *self, PyObject *args)
{
    PyObject *wfile = NULL;
    PyObject *ret = NULL;
    DeguWObj w = NEW_DEGU_WOBJ;
    int64_t total;

    if (! PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    if (_init_wobj(wfile, &w)) {
        total = _BodyIter_write_to(self, &w);
        if (total >= 0) {
            ret = PyLong_FromLongLong(total);
        }
    }
    _clear_wobj(&w);
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

    if (! PyArg_ParseTupleAndKeywords(args, kw, "O:ChunkedBodyIter", keys,
            &source)) {
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
_ChunkedBodyIter_write_to(ChunkedBodyIter *self, DeguWObj *w)
{
    PyObject *iterator = NULL;
    PyObject *chunk = NULL;
    DeguChunk dc = NEW_DEGU_CHUNK;
    bool empty = false;
    ssize_t wrote;
    uint64_t total = 0;
    int64_t ret = -2; 

    if (! _check_body_state("ChunkedBodyIter", self->state, BODY_READY)) {
        return -3;
    }
    self->state = BODY_STARTED;
    _SET(iterator, PyObject_GetIter(self->source))
    while ((chunk = PyIter_Next(iterator))) {
        if (empty) {
            PyErr_SetString(PyExc_ValueError,
                "additional chunk after empty chunk data"
            );
            goto error;
        }
        if (! _unpack_chunk(chunk, &dc)) {
            goto error;
        }
        if (dc.size == 0) {
            empty = true;
        }
        wrote = _write_chunk_to(w, &dc);
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
    DeguWObj w = NEW_DEGU_WOBJ;
    int64_t total;

    if (! PyArg_ParseTuple(args, "O:write_to", &wfile)) {
        return NULL;
    }
    if (_init_wobj(wfile, &w)) {
        total = _ChunkedBodyIter_write_to(self, &w);
        if (total >= 0) {
            ret = PyLong_FromLongLong(total);
        }
    }
    _clear_wobj(&w);
    return ret;
}


/******************************************************************************
 * Server-side helpers
 ******************************************************************************/
static bool
_body_is_consumed(PyObject *obj)
{
    if (obj == NULL || obj == Py_None) {
        return true;
    }
    if (IS_BODY(obj)) {
        return BODY(obj)->state == BODY_CONSUMED;
    }
    if (IS_CHUNKED_BODY(obj)) {
        return CHUNKED_BODY(obj)->state == BODY_CONSUMED;
    }
    Py_FatalError("_body_is_consumed(): bad body type");
    return false;
}

static bool
_unpack_response(PyObject *obj, DeguResponse *dr)
{
    if (Py_TYPE(obj) == &ResponseType) {
        _SET(dr->status,  PyStructSequence_GET_ITEM(obj, 0))
        _SET(dr->reason,  PyStructSequence_GET_ITEM(obj, 1))
        _SET(dr->headers, PyStructSequence_GET_ITEM(obj, 2))
        _SET(dr->body,    PyStructSequence_GET_ITEM(obj, 3))
    }
    else {
        if (! _check_tuple("response", obj, 4)) {
            goto error;
        }
        _SET(dr->status,  PyTuple_GET_ITEM(obj, 0))
        _SET(dr->reason,  PyTuple_GET_ITEM(obj, 1))
        _SET(dr->headers, PyTuple_GET_ITEM(obj, 2))
        _SET(dr->body,    PyTuple_GET_ITEM(obj, 3))
    }
    const ssize_t s = _get_status(dr->status);
    if (s < 0) {
        goto error;
    }
    dr->s = (size_t)s;
    return true;

error:
    return false;
}

static PyObject *
handle_requests(PyObject *self, PyObject *args)
{
    PyObject *app = NULL;
    PyObject *max_requests = NULL;
    PyObject *sock = NULL;
    PyObject *session = NULL;
    PyObject *ret = NULL;
    ssize_t _max_requests;
    size_t i, status;

    /* These 6 all need to be freed */
    PyObject *reader = NULL;
    PyObject *writer = NULL;
    PyObject *request = NULL;
    PyObject *response = NULL;
    PyObject *close_result = NULL;
    DeguRequest req = NEW_DEGU_REQUEST;

    /* We don't need to call _clear_degu_response(rsp) because
     * _unpack_response() just borrows references from the response tuple, so
     * we only need to call Py_CLEAR(response) to drop the references we hold
     */
    DeguResponse rsp = NEW_DEGU_RESPONSE;

    if (! PyArg_ParseTuple(args, "OOOO:handle_requests",
            &app, &max_requests, &sock, &session)) {
        return NULL;
    }
    _max_requests = _get_size("max_requests", max_requests, 1u, 75000u);
    if (_max_requests < 0) {
        return NULL;
    }
    const size_t count = (size_t)_max_requests;
    _SET(reader, PyObject_CallFunctionObjArgs(READER_CLASS, sock, NULL))
    _SET(writer, PyObject_CallFunctionObjArgs(WRITER_CLASS, sock, NULL))

    i = 0;
    while (i < count) {
        /* Read and parse request, build Request namedtuple */
        if (! _Reader_read_request(READER(reader), &req)) {
            goto error;
        }
        _SET(request, _Request(&req))

        /* Call the application, the validate and upack the response */
        _SET(response,
            PyObject_CallFunctionObjArgs(app, session, request, bodies, NULL)
        )
        Py_CLEAR(request); /* Clear as req holds refererces to items still */
        if (! _unpack_response(response, &rsp)) {
            goto error;
        }

        /* Make sure application fully consumed request body */
        if (! _body_is_consumed(req.body)) {
            PyErr_Format(PyExc_ValueError,
                "request body not consumed: %R", req.body
            );
            goto error;
        }

        /* Make sure HEAD requests are properly handled */
        if (req.method == str_HEAD && rsp.body != Py_None) {
            PyErr_Format(PyExc_TypeError,
                "request method is HEAD, but response body is not None: %R",
                Py_TYPE(rsp.body)
            );
            goto error;
        }

        /* Write the response */
        if (_Writer_write_response((Writer *)writer, &rsp) < 0) {
            goto error;
        }
        i++;

        /* Possibly close connection depending on response status */
        status = rsp.s;
        if (status >= 400 && status != 404 && status != 409 && status != 412) {
            break;
        }
        Py_CLEAR(response);
        _clear_degu_request(&req);
        rsp = NEW_DEGU_RESPONSE;
    }

    /* Ensure sock is flushed and properly closed before shutdown is called */ 
    _SET(close_result, PyObject_CallMethod(sock, "close", NULL))

    /* Return the number of requests handled */
    _SET(ret, PyLong_FromSize_t(i))

error:
    Py_CLEAR(reader);           /* 1 */
    Py_CLEAR(writer);           /* 2 */
    Py_CLEAR(request);          /* 3 */
    Py_CLEAR(response);         /* 4 */
    Py_CLEAR(close_result);     /* 5 */
    _clear_degu_request(&req);  /* 6 */
    return ret;
}


/******************************************************************************
 * Connection object.
 ******************************************************************************/
static void
Connection_dealloc(Connection *self)
{
    _Connection_shutdown(self);
    Py_CLEAR(self->sock);
    Py_CLEAR(self->base_headers);
    Py_CLEAR(self->bodies);
    Py_CLEAR(self->reader);
    Py_CLEAR(self->writer);
    Py_CLEAR(self->response_body);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
Connection_init(Connection *self, PyObject *args, PyObject *kw)
{
    static char *keys[] = {"sock", "base_headers", NULL};
    PyObject *sock = NULL;
    PyObject *base_headers = NULL;

    if (! PyArg_ParseTupleAndKeywords(args, kw, "OO:Connection", keys,
            &sock, &base_headers)) {
        goto error;
    }
    self->closed = false;
    _SET_AND_INC(self->sock, sock)
    if (base_headers != Py_None && !_check_dict("base_headers", base_headers)) {
        goto error;
    }
    _SET_AND_INC(self->base_headers, base_headers)
    _SET_AND_INC(self->bodies, bodies)
    _SET(self->reader, PyObject_CallFunctionObjArgs(READER_CLASS, sock, NULL))
    _SET(self->writer, PyObject_CallFunctionObjArgs(WRITER_CLASS, sock, NULL))
    self->response_body = NULL;
    return 0;

error:
    return -1;
}

static void
_Connection_shutdown(Connection *self)
{
    PyObject *err_type, *err_value, *err_traceback, *result;

    if (self->closed || self->sock == NULL) {
        return;
    }
    self->closed = true;
    PyErr_Fetch(&err_type, &err_value, &err_traceback);
    result = PyObject_CallMethod(self->sock, "shutdown", "i", SHUT_RDWR);
    Py_CLEAR(result);
    PyErr_Restore(err_type, err_value, err_traceback);
}

static PyObject *
Connection_close(Connection *self)
{
    _Connection_shutdown(self);
    Py_RETURN_NONE;
}

static PyObject *
_Connection_request(Connection *self, DeguRequest *dr)
{
    DeguResponse r = NEW_DEGU_RESPONSE;
    PyObject *response = NULL;

    /* Check if Connection is closed */
    if (self->closed) {
        PyErr_SetString(PyExc_ValueError, "Connection is closed");
        return NULL;
    }

    /* Check whether previous response body was consumed */
    if (! _body_is_consumed(self->response_body)) {
        PyErr_Format(PyExc_ValueError,
            "response body not consumed: %R", self->response_body
        );
        goto error;
    }
    Py_CLEAR(self->response_body);

    /* Update headers with base_headers if they were provided */
    if (self->base_headers != Py_None) {
        if (! _check_dict("headers", dr->headers)) {
            goto error;
        }
        if (PyDict_Update(dr->headers, self->base_headers) != 0) {
            goto error;
        }
    }

    /* Write request, read response */
    if (_Writer_write_request(WRITER(self->writer), dr) < 0) {
        goto error;
    }
    if (! _Reader_read_response(READER(self->reader), dr->method, &r)) {
        goto error;
    }

    /* Build Response, retain a reference to previous response body */
    _SET(response, _Response(&r))
    _SET_AND_INC(self->response_body, r.body)
    goto cleanup;

error:
    _Connection_shutdown(self);

cleanup:
    _clear_degu_response(&r);
    return response;
}

static PyObject *
Connection_request(Connection *self, PyObject *args)
{
    const uint8_t *buf = NULL;
    size_t len = 0;
    DeguRequest dr = NEW_DEGU_REQUEST;
    PyObject *response = NULL;

    if (! PyArg_ParseTuple(args, "s#OOO:request",
            &buf, &len, &dr.uri, &dr.headers, &dr.body)) {
        goto error;
    }
    _SET(dr.method, _parse_method((DeguSrc){buf, len}))
    _SET(response, _Connection_request(self, &dr))

error:
    Py_CLEAR(dr.method);
    return response;
}

static PyObject *
Connection_put(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OOO:put", &dr.uri, &dr.headers, &dr.body)) {
        return NULL;
    }
    dr.method = str_PUT;
    return _Connection_request(self, &dr);
}

static PyObject *
Connection_post(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OOO:post", &dr.uri, &dr.headers, &dr.body)) {
        return NULL;
    }
    dr.method = str_POST;
    return _Connection_request(self, &dr);
}

static PyObject *
Connection_get(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OO:get", &dr.uri, &dr.headers)) {
        return NULL;
    }
    dr.method = str_GET;
    dr.body = Py_None;
    return _Connection_request(self, &dr);
}

static PyObject *
Connection_head(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OO:head", &dr.uri, &dr.headers)) {
        return NULL;
    }
    dr.method = str_HEAD;
    dr.body = Py_None;
    return _Connection_request(self, &dr);
}

static PyObject *
Connection_delete(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    if (! PyArg_ParseTuple(args, "OO:delete", &dr.uri, &dr.headers)) {
        return NULL;
    }
    dr.method = str_DELETE;
    dr.body = Py_None;
    return _Connection_request(self, &dr);
}

static PyObject *
Connection_get_range(Connection *self, PyObject *args)
{
    DeguRequest dr = NEW_DEGU_REQUEST;
    PyObject *start = NULL;
    PyObject *stop = NULL;
    PyObject *range = NULL;
    PyObject *ret = NULL;

    if (! PyArg_ParseTuple(args, "OOOO:get_range",
            &dr.uri, &dr.headers, &start, &stop)) {
        return NULL;
    }
    dr.method = str_GET;
    dr.body = Py_None;
    _SET(range, _Range_PyNew(start, stop))
    if (! _set_default_header(dr.headers, key_range, range)) {
        goto error;
    }
    _SET(ret, _Connection_request(self, &dr))

error:
    Py_CLEAR(range);
    return ret;
}


/******************************************************************************
 * Module init.
 ******************************************************************************/
static bool
_init_all_types(PyObject *module)
{
    RangeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&RangeType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Range", (PyObject *)&RangeType)

    ContentRangeType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ContentRangeType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "ContentRange", (PyObject *)&ContentRangeType)

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

    ConnectionType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ConnectionType) != 0) {
        goto error;
    }
    _ADD_MODULE_ATTR(module, "Connection", (PyObject *)&ConnectionType)

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
    PyModule_AddIntMacro(module, BUF_LEN);
    PyModule_AddIntMacro(module, SCRATCH_LEN);
    PyModule_AddIntMacro(module, MAX_LINE_LEN);

    PyModule_AddIntMacro(module, MAX_CL_LEN);

    PyModule_AddIntMacro(module, IO_SIZE);    
    PyModule_AddIntMacro(module, MAX_IO_SIZE);

    PyModule_AddIntMacro(module, BODY_READY);
    PyModule_AddIntMacro(module, BODY_STARTED);
    PyModule_AddIntMacro(module, BODY_CONSUMED);
    PyModule_AddIntMacro(module, BODY_ERROR);
    return module;
}

