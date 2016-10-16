/*
 * degu: an embedded HTTP server and client library
 * Copyright (C) 2014-2016 Novacut Inc
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
#include <structmember.h>
#include <stdbool.h>
#include <sys/socket.h>

/* Reader/Writer buf size, also max allowed input/output preamble size */
#define BUF_LEN 32768u

/* Reader scratch buf size, also max header name size */
#define SCRATCH_LEN 32u

/* Max length of chunk size line, including CRLF */
#define MAX_LINE_LEN 4096u

/* Max length of a content-length value */
#define MAX_CL_LEN 16u

/* Max uint64_t value for a content-length, range start/stop, etc */
#define MAX_LENGTH 9999999999999999ull

#define MAX_HEADER_COUNT 20

#define IO_SIZE 1048576u
#define MAX_IO_SIZE 16777216u

#define BODY_READY 0u
#define BODY_STARTED 1u
#define BODY_CONSUMED 2u
#define BODY_ERROR 3u

#define CONTENT_LENGTH_BIT 1u
#define TRANSFER_ENCODING_BIT 2u
#define RANGE_BIT 4u
#define CONTENT_RANGE_BIT 8u
#define BODY_MASK 3u

#define GET_BIT       (1 << 0)
#define PUT_BIT       (1 << 1)
#define POST_BIT      (1 << 2)
#define HEAD_BIT      (1 << 3)
#define DELETE_BIT    (1 << 4)
#define PUT_POST_MASK (PUT_BIT | POST_BIT)

#define ROUTER_MAX_DEPTH 10

#if PY_MINOR_VERSION >= 5
    #define _TP_AS_ASYNC .tp_as_async
    #define _M_SLOTS .m_slots
#else
    #define _TP_AS_ASYNC .tp_reserved
    #define _M_SLOTS .m_reload
#endif


/******************************************************************************
 * Error handling macros (they require an "error" label in the function).
 ******************************************************************************/
#define _SET(dst, src) \
    if (dst != NULL) { \
        Py_FatalError("_SET(): dst != NULL prior to assignment"); \
    } \
    dst = (src); \
    if (dst == NULL) { \
        goto error; \
    }

#define _SET_AND_INC(dst, src) \
    _SET(dst, src) \
    Py_INCREF(dst);

#define _ADD_MODULE_ATTR(module, name, obj) \
    if (module == NULL || name == NULL || obj == NULL) { \
        Py_FatalError("_ADD_MODULE_ATTR(): bad internal call"); \
    } \
    Py_INCREF(obj); \
    if (PyModule_AddObject(module, name, obj) != 0) { \
        goto error; \
    }


/******************************************************************************
 * Structures for read-only and writable memory buffers (aka "slices").
 ******************************************************************************/

/* DeguSrc (source): a read-only buffer.
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
} DeguSrc;

/* DeguDst (destination): a writable buffer.
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
} DeguDst;

/* Helper macros for building DeguSrc, DeguDst */
#define DEGU_SRC(buf, len) ((DeguSrc){(buf), (len)})
#define DEGU_DST(buf, len) ((DeguDst){(buf), (len)})

/* A "NULL" DeguSrc */
#define NULL_DeguSrc DEGU_SRC(NULL, 0)

/* A "NULL" DeguDst */
#define NULL_DeguDst DEGU_DST(NULL, 0)

/* _DEGU_SRC_CONSTANT(): helper macro for creating DeguSrc globals */
#define _DEGU_SRC_CONSTANT(name, text) \
    static DeguSrc name = {(uint8_t *)text, sizeof(text) - 1};

typedef struct {
    DeguDst dst;
    size_t stop;
} DeguOutput;


/******************************************************************************
 * Structures for internal C parsing API.
 ******************************************************************************/
#define DEGU_HEADERS_HEAD \
    PyObject *headers; \
    PyObject *body; \
    uint64_t content_length; \
    uint8_t flags;

typedef struct {
    DEGU_HEADERS_HEAD
} DeguHeaders;

typedef struct {
    DEGU_HEADERS_HEAD
    PyObject *method;
    PyObject *uri;
    PyObject *mount;
    PyObject *path;
    PyObject *query;
    uint8_t m;
} DeguRequest;

typedef struct {
    DEGU_HEADERS_HEAD
    PyObject *status;
    PyObject *reason;
    size_t s;
} DeguResponse;

#define NEW_DEGU_HEADERS \
    ((DeguHeaders) {NULL, NULL, 0, 0})

#define NEW_DEGU_REQUEST \
    ((DeguRequest) {NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 0})

#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, 0, 0, NULL, NULL, 0})

typedef struct {
    PyObject *key;
    PyObject *val;
    PyObject *data;
    size_t size;
} DeguChunk;

#define NEW_DEGU_CHUNK \
    ((DeguChunk){NULL, NULL, NULL, 0})

/* Structured for parsing the preamble into (first line, all header lines) */
typedef const struct {
    DeguSrc line;
    DeguSrc headers;
} DeguPreamble;


/******************************************************************************
 * Internal parsing and rendering API
 ******************************************************************************/
static bool _parse_method(DeguSrc, DeguRequest *)
    __attribute__ ((warn_unused_result));

static bool _check_method(PyObject *, DeguRequest *)
    __attribute__ ((warn_unused_result));

/******************************************************************************
 * Exported Python functions
 ******************************************************************************/

/* Header parsing */
static PyObject * parse_header_name(PyObject *, PyObject *);
static PyObject * parse_content_length(PyObject *, PyObject *);
static PyObject * parse_range(PyObject *, PyObject *);
static PyObject * parse_content_range(PyObject *, PyObject *);
static PyObject * parse_headers(PyObject *, PyObject *, PyObject *);

/* Request parsing */
static PyObject * parse_method(PyObject *, PyObject *);
static PyObject * parse_uri(PyObject *, PyObject *);
static PyObject * parse_request_line(PyObject *, PyObject *);
static PyObject * parse_request(PyObject *, PyObject *);

/* Response parsing */
static PyObject * parse_response_line(PyObject *, PyObject *);
static PyObject * parse_response(PyObject *, PyObject *);

/* Chunk line parsing */
static PyObject * parse_chunk_size(PyObject *, PyObject *);
static PyObject * parse_chunk_extension(PyObject *, PyObject *);
static PyObject * parse_chunk(PyObject *, PyObject *);

/* Formatting */
static PyObject * set_default_header(PyObject *, PyObject *);
static PyObject * format_chunk(PyObject *, PyObject *);

static PyObject * render_headers(PyObject *, PyObject *);
static PyObject * render_request(PyObject *, PyObject *);
static PyObject * render_response(PyObject *, PyObject *);

/* Misc */
static PyObject * readchunk(PyObject *, PyObject *);
static PyObject * write_chunk(PyObject *, PyObject *);
static PyObject * set_output_headers(PyObject *, PyObject *);

/* namedtuples */
static PyObject * API(PyObject *, PyObject *);
static PyObject * Response(PyObject *, PyObject *);

/* Server and client entry points */
static PyObject * _handle_requests(PyObject *, PyObject *);

static struct PyMethodDef degu_functions[] = {
    /* Header parsing */
    {"parse_header_name", parse_header_name, METH_VARARGS, NULL},
    {"parse_content_length", parse_content_length, METH_VARARGS, NULL},
    {"parse_range", parse_range, METH_VARARGS, NULL},
    {"parse_content_range", parse_content_range, METH_VARARGS, NULL},
    {"parse_headers", (PyCFunction)parse_headers, METH_VARARGS|METH_KEYWORDS, NULL},

    /* Request parsing */
    {"parse_method", parse_method, METH_VARARGS, NULL},
    {"parse_uri", parse_uri, METH_VARARGS, NULL},
    {"parse_request_line", parse_request_line, METH_VARARGS, NULL},
    {"parse_request", parse_request, METH_VARARGS, NULL},

    /* Response parsing */
    {"parse_response_line", parse_response_line, METH_VARARGS, NULL},
    {"parse_response", parse_response, METH_VARARGS, NULL},

    /* Chunk line parsing */
    {"parse_chunk_size", parse_chunk_size, METH_VARARGS, NULL},
    {"parse_chunk_extension", parse_chunk_extension, METH_VARARGS, NULL},
    {"parse_chunk", parse_chunk, METH_VARARGS, NULL},

    /* Formatting */
    {"set_default_header", set_default_header, METH_VARARGS, NULL},
    {"format_chunk", format_chunk, METH_VARARGS, NULL},
    {"render_headers", render_headers, METH_VARARGS, NULL},
    {"render_request", render_request, METH_VARARGS, NULL},
    {"render_response", render_response, METH_VARARGS, NULL},

    /* Misc */
    {"readchunk", readchunk, METH_VARARGS, NULL},
    {"write_chunk", write_chunk, METH_VARARGS, NULL},
    {"set_output_headers", set_output_headers, METH_VARARGS, NULL},

    /* namedtuples */
    {"API", API, METH_VARARGS, NULL},
    {"Response", Response, METH_VARARGS, NULL},

    /* Server and client entry points */
    {"_handle_requests", _handle_requests, METH_VARARGS, NULL},

    {NULL, NULL, 0, NULL}
};


/******************************************************************************
 * Range object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    uint64_t start;
    uint64_t stop;
} Range;

static PyObject * _Range_New(uint64_t, uint64_t);

static PyMemberDef Range_members[] = {
    {"start", T_ULONGLONG, offsetof(Range, start), READONLY, NULL},
    {"stop",  T_ULONGLONG, offsetof(Range, stop),  READONLY, NULL},
    {NULL}
};

static void Range_dealloc(Range *);
static int Range_init(Range *, PyObject *, PyObject *);
static PyObject * Range_repr(Range *);
static PyObject * Range_str(Range *);
static PyObject * Range_richcompare(Range *, PyObject *, int);

static PyTypeObject RangeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Range",
    .tp_basicsize      = sizeof(Range),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Range_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)Range_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = (reprfunc)Range_str,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Range(start, stop)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = (richcmpfunc)Range_richcompare,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = NULL,
    .tp_members        = Range_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Range_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};


/******************************************************************************
 * ContentRange object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    uint64_t start;
    uint64_t stop;
    uint64_t total;
} ContentRange;

static PyObject * _ContentRange_New(uint64_t, uint64_t, uint64_t);

static PyMemberDef ContentRange_members[] = {
    {"start", T_ULONGLONG, offsetof(ContentRange, start), READONLY, NULL},
    {"stop",  T_ULONGLONG, offsetof(ContentRange, stop),  READONLY, NULL},
    {"total", T_ULONGLONG, offsetof(ContentRange, total), READONLY, NULL},
    {NULL}
};

static void ContentRange_dealloc(ContentRange *);
static int ContentRange_init(ContentRange *, PyObject *, PyObject *);
static PyObject * ContentRange_repr(ContentRange *);
static PyObject * ContentRange_str(ContentRange *);
static PyObject * ContentRange_richcompare(ContentRange *, PyObject *, int);

static PyTypeObject ContentRangeType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.ContentRange",
    .tp_basicsize      = sizeof(ContentRange),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)ContentRange_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)ContentRange_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = (reprfunc)ContentRange_str,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "ContentRange(start, stop, total)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = (richcmpfunc)ContentRange_richcompare,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = NULL,
    .tp_members        = ContentRange_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)ContentRange_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};


/******************************************************************************
 * Request object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject * method;
    PyObject * uri;
    PyObject * headers;
    PyObject * body;
    PyObject * mount;
    PyObject * path;
    PyObject * query;
    uint8_t m;
} Request;

static PyObject * Request_shift_path(Request *);
static PyObject * Request_build_proxy_uri(Request *);

static PyMethodDef Request_methods[] = {
    {"shift_path",      (PyCFunction)Request_shift_path,      METH_NOARGS, NULL},
    {"build_proxy_uri", (PyCFunction)Request_build_proxy_uri, METH_NOARGS, NULL},
    {NULL}
};

static PyMemberDef Request_members[] = {
    {"method",  T_OBJECT, offsetof(Request, method),  READONLY, NULL},
    {"uri",     T_OBJECT, offsetof(Request, uri),     READONLY, NULL},
    {"headers", T_OBJECT, offsetof(Request, headers), READONLY, NULL},
    {"body",    T_OBJECT, offsetof(Request, body),    READONLY, NULL},
    {"mount",   T_OBJECT, offsetof(Request, mount),   READONLY, NULL},
    {"path",    T_OBJECT, offsetof(Request, path),    READONLY, NULL},
    {"query",   T_OBJECT, offsetof(Request, query),   READONLY, NULL},
    {"m",       T_UBYTE,  offsetof(Request, m),       READONLY, NULL},
    {NULL}
};

static PyObject * _Request_New(DeguRequest *);
static void Request_dealloc(Request *);
static int Request_init(Request *, PyObject *, PyObject *);
static PyObject * Request_repr(Request *);

static PyTypeObject RequestType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Request",
    .tp_basicsize      = sizeof(Request),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Request_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)Request_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Request()",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = Request_methods,
    .tp_members        = Request_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Request_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define REQUEST(obj) ((Request *)(obj))


/******************************************************************************
 * DeguIOBuf API
 ******************************************************************************/
typedef struct {
    size_t start;
    size_t stop;
    uint8_t buf[BUF_LEN];
} DeguIOBuf;

static inline DeguSrc
_iobuf_raw_src(DeguIOBuf *io)
{
    return DEGU_SRC(io->buf, BUF_LEN);
}

static inline DeguDst
_iobuf_raw_dst(DeguIOBuf *io)
{
    return DEGU_DST(io->buf, BUF_LEN);
}


/******************************************************************************
 * SocketWrapper object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *sock;
    PyObject *recv_into;
    PyObject *send;
    PyObject *close;
    bool closed;
    uint8_t scratch[SCRATCH_LEN];
    DeguIOBuf r_io;
    DeguIOBuf w_io;
} SocketWrapper;

static bool _SocketWrapper_readinto(SocketWrapper *, DeguDst);
static bool _SocketWrapper_read_chunkline(SocketWrapper *, DeguChunk *);
static ssize_t _SocketWrapper_write(SocketWrapper *, DeguSrc);
static void _SocketWrapper_close_unraisable(SocketWrapper *);

static PyObject * SocketWrapper_close(SocketWrapper *);
static PyObject * SocketWrapper_read_until(SocketWrapper *, PyObject *);
static PyObject * SocketWrapper_read_request(SocketWrapper *);
static PyObject * SocketWrapper_read_response(SocketWrapper *, PyObject *);
static PyObject * SocketWrapper_write_request(SocketWrapper *, PyObject *);
static PyObject * SocketWrapper_write_response(SocketWrapper *, PyObject *);

static PyMethodDef SocketWrapper_methods[] = {
    {"close",      (PyCFunction)SocketWrapper_close,      METH_NOARGS,  NULL},
    {"read_until", (PyCFunction)SocketWrapper_read_until, METH_VARARGS, NULL},
    {"read_request", (PyCFunction)SocketWrapper_read_request, METH_NOARGS, NULL},
    {"read_response", (PyCFunction)SocketWrapper_read_response, METH_VARARGS, NULL},
    {"write_request", (PyCFunction)SocketWrapper_write_request, METH_VARARGS, NULL},
    {"write_response", (PyCFunction)SocketWrapper_write_response, METH_VARARGS, NULL},
    {NULL}
};

static PyMemberDef SocketWrapper_members[] = {
    {"sock",    T_OBJECT,   offsetof(SocketWrapper, sock),      READONLY, NULL},
    {"closed",  T_BOOL,     offsetof(SocketWrapper, closed),    READONLY, NULL},
    {NULL}
};

static void SocketWrapper_dealloc(SocketWrapper *);
static int SocketWrapper_init(SocketWrapper *, PyObject *, PyObject *);

static PyTypeObject SocketWrapperType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.SocketWrapper",
    .tp_basicsize      = sizeof(SocketWrapper),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)SocketWrapper_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = NULL,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "SocketWrapper(sock)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = SocketWrapper_methods,
    .tp_members        = SocketWrapper_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)SocketWrapper_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define WRAPPER_CLASS ((PyObject *)&SocketWrapperType)
#define IS_WRAPPER(obj) (Py_TYPE((obj)) == &SocketWrapperType)
#define WRAPPER(obj) ((SocketWrapper *)(obj))

#define FL_WRITE_BIT     (1 << 0)
#define FL_READINTO_BIT  (1 << 1)
#define FL_READLINE_BIT  (1 << 2)
#define FL_ALLOWED_MASK  (FL_WRITE_BIT | FL_READINTO_BIT | FL_READLINE_BIT)
#define FL_WRITE         (FL_WRITE_BIT)
#define FL_READ          (FL_READINTO_BIT)
#define FL_CHUNKED       (FL_READINTO_BIT | FL_READLINE_BIT)

typedef struct {
    SocketWrapper *wrapper;
    PyObject *write;
    PyObject *readinto;
    PyObject *readline;
} DeguFileLike;

#define NEW_DEGU_FILE_LIKE ((DeguFileLike){NULL, NULL, NULL, NULL})


/******************************************************************************
 * Body object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    DeguFileLike fl;
    uint64_t content_length;
    uint64_t remaining;
    uint8_t state;
    bool chunked;
} Body;

static PyObject * _Body_New(PyObject *, uint64_t);
static int64_t _Body_write_to(Body *, DeguFileLike *);

static PyMemberDef Body_members[] = {
    {"rfile",          T_OBJECT,    offsetof(Body, rfile),          READONLY, NULL},
    {"content_length", T_ULONGLONG, offsetof(Body, content_length), READONLY, NULL},
    {"state",          T_UBYTE,     offsetof(Body, state),          READONLY, NULL},
    {"chunked",        T_BOOL,      offsetof(Body, chunked),        READONLY, NULL},
    {NULL}
};

static PyObject * Body_read(Body *, PyObject *, PyObject *);
static PyObject * Body_write_to(Body *, PyObject *);

static PyMethodDef Body_methods[] = {
    {"read",     (PyCFunction)Body_read,     METH_VARARGS|METH_KEYWORDS, NULL},
    {"write_to", (PyCFunction)Body_write_to, METH_VARARGS, NULL},
    {NULL}
};

static void Body_dealloc(Body *);
static int Body_init(Body *, PyObject *, PyObject *);
static PyObject * Body_repr(Body *);
static PyObject * Body_iter(Body *);
static PyObject * Body_next(Body *);

static PyTypeObject BodyType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Body",
    .tp_basicsize      = sizeof(Body),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Body_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)Body_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Body(rfile, content_length)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = (getiterfunc)Body_iter,
    .tp_iternext       = (iternextfunc)Body_next,
    .tp_methods        = Body_methods,
    .tp_members        = Body_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Body_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define IS_BODY(obj) (Py_TYPE((obj)) == &BodyType)
#define BODY(obj) ((Body *)(obj))


/******************************************************************************
 * ChunkedBody object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    DeguFileLike fl;
    uint8_t state;
    bool chunked;
} ChunkedBody;

static PyObject * _ChunkedBody_New(PyObject *);
static int64_t _ChunkedBody_write_to(ChunkedBody *, DeguFileLike *);

static PyMemberDef ChunkedBody_members[] = {
    {"rfile",    T_OBJECT, offsetof(ChunkedBody, rfile),    READONLY, NULL},
    {"state",    T_UBYTE,  offsetof(ChunkedBody, state),    READONLY, NULL},
    {"chunked",  T_BOOL,   offsetof(ChunkedBody, chunked),  READONLY, NULL},
    {NULL}
};

static PyObject * ChunkedBody_readchunk(ChunkedBody *);
static PyObject * ChunkedBody_read(ChunkedBody *);
static PyObject * ChunkedBody_write_to(ChunkedBody *, PyObject *);

static PyMethodDef ChunkedBody_methods[] = {
    {"readchunk", (PyCFunction)ChunkedBody_readchunk, METH_NOARGS,  NULL},
    {"read",      (PyCFunction)ChunkedBody_read,      METH_NOARGS,  NULL},
    {"write_to",  (PyCFunction)ChunkedBody_write_to,  METH_VARARGS, NULL},
    {NULL}
};

static void ChunkedBody_dealloc(ChunkedBody *);
static int ChunkedBody_init(ChunkedBody *, PyObject *, PyObject *);
static PyObject * ChunkedBody_repr(ChunkedBody *);
static PyObject * ChunkedBody_iter(ChunkedBody *);
static PyObject * ChunkedBody_next(ChunkedBody *);

static PyTypeObject ChunkedBodyType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.ChunkedBody",
    .tp_basicsize      = sizeof(ChunkedBody),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)ChunkedBody_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)ChunkedBody_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "ChunkedBody(rfile)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = (getiterfunc)ChunkedBody_iter,
    .tp_iternext       = (iternextfunc)ChunkedBody_next,
    .tp_methods        = ChunkedBody_methods,
    .tp_members        = ChunkedBody_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)ChunkedBody_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define IS_CHUNKED_BODY(obj) (Py_TYPE((obj)) == &ChunkedBodyType)
#define CHUNKED_BODY(obj) ((ChunkedBody *)(obj))


/******************************************************************************
 * BodyIter object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *source;
    uint64_t content_length;
    uint8_t state;
} BodyIter;

static int64_t _BodyIter_write_to(BodyIter *, DeguFileLike *);

static PyMemberDef BodyIter_members[] = {
    {"source", T_OBJECT, offsetof(BodyIter, source), READONLY, NULL},
    {"content_length", T_ULONGLONG, offsetof(BodyIter, content_length), READONLY, NULL},
    {"state", T_UBYTE, offsetof(BodyIter, state), READONLY, NULL},
    {NULL}
};

static PyObject * BodyIter_write_to(BodyIter *, PyObject *);

static PyMethodDef BodyIter_methods[] = {
    {"write_to",  (PyCFunction)BodyIter_write_to, METH_VARARGS, NULL},
    {NULL}
};

static void BodyIter_dealloc(BodyIter *);
static int BodyIter_init(BodyIter *, PyObject *, PyObject *);
static PyObject * BodyIter_repr(BodyIter *);

static PyTypeObject BodyIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.BodyIter",
    .tp_basicsize      = sizeof(BodyIter),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)BodyIter_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)BodyIter_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "BodyIter(source)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = BodyIter_methods,
    .tp_members        = BodyIter_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)BodyIter_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define IS_BODY_ITER(obj) (Py_TYPE((obj)) == &BodyIterType)
#define BODY_ITER(obj) ((BodyIter *)(obj))


/******************************************************************************
 * ChunkedBodyIter object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *source;
    uint8_t state;
} ChunkedBodyIter;

static int64_t _ChunkedBodyIter_write_to(ChunkedBodyIter *, DeguFileLike *);

static PyMemberDef ChunkedBodyIter_members[] = {
    {"source", T_OBJECT, offsetof(ChunkedBodyIter, source), READONLY, NULL},
    {"state",  T_UBYTE,  offsetof(ChunkedBodyIter, state),  READONLY, NULL},
    {NULL}
};

static PyObject * ChunkedBodyIter_write_to(ChunkedBodyIter *, PyObject *);

static PyMethodDef ChunkedBodyIter_methods[] = {
    {"write_to",  (PyCFunction)ChunkedBodyIter_write_to, METH_VARARGS, NULL},
    {NULL}
};

static void ChunkedBodyIter_dealloc(ChunkedBodyIter *);
static int ChunkedBodyIter_init(ChunkedBodyIter *, PyObject *, PyObject *);
static PyObject * ChunkedBodyIter_repr(ChunkedBodyIter *);

static PyTypeObject ChunkedBodyIterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.ChunkedBodyIter",
    .tp_basicsize      = sizeof(ChunkedBodyIter),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)ChunkedBodyIter_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)ChunkedBodyIter_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "ChunkedBodyIter(source)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = ChunkedBodyIter_methods,
    .tp_members        = ChunkedBodyIter_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)ChunkedBodyIter_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define IS_CHUNKED_BODY_ITER(obj) (Py_TYPE((obj)) == &ChunkedBodyIterType)
#define CHUNKED_BODY_ITER(obj) ((ChunkedBodyIter *)(obj))


/******************************************************************************
 * Connection object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *sock;
    PyObject *base_headers;
    PyObject *api;
    PyObject *wrapper;
    PyObject *response_body;
} Connection;

static PyObject * _Connection_request(Connection *, DeguRequest *);

static PyMemberDef Connection_members[] = {
    {"sock",         T_OBJECT, offsetof(Connection, sock),         READONLY, NULL},
    {"base_headers", T_OBJECT, offsetof(Connection, base_headers), READONLY, NULL},
    {"api",          T_OBJECT, offsetof(Connection, api),          READONLY, NULL},
    {"bodies",       T_OBJECT, offsetof(Connection, api),          READONLY, NULL},
    {NULL}
};

static PyObject * Connection_close(Connection *);
static PyObject * Connection_request(Connection *, PyObject *);
static PyObject * Connection_put(Connection *, PyObject *);
static PyObject * Connection_post(Connection *, PyObject *);
static PyObject * Connection_get(Connection *, PyObject *);
static PyObject * Connection_head(Connection *, PyObject *);
static PyObject * Connection_delete(Connection *, PyObject *);
static PyObject * Connection_get_range(Connection *, PyObject *);

static PyMethodDef Connection_methods[] = {
    {"close",     (PyCFunction)Connection_close,     METH_NOARGS,  NULL},
    {"request",   (PyCFunction)Connection_request,   METH_VARARGS, NULL},
    {"put",       (PyCFunction)Connection_put,       METH_VARARGS, NULL},
    {"post",      (PyCFunction)Connection_post,      METH_VARARGS, NULL},
    {"get",       (PyCFunction)Connection_get,       METH_VARARGS, NULL},
    {"head",      (PyCFunction)Connection_head,      METH_VARARGS, NULL},
    {"delete",    (PyCFunction)Connection_delete,    METH_VARARGS, NULL},
    {"get_range", (PyCFunction)Connection_get_range, METH_VARARGS, NULL},
    {NULL}
};

static PyObject * Connection_get_closed(Connection *, void *);

static PyGetSetDef Connection_getset[] = {
    {"closed", (getter)Connection_get_closed, NULL, NULL, NULL},
    {NULL}
};

static void Connection_dealloc(Connection *);
static int Connection_init(Connection *, PyObject *, PyObject *);

static PyTypeObject ConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Connection",
    .tp_basicsize      = sizeof(Connection),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Connection_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = NULL,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Connection(sock, base_headers)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = Connection_methods,
    .tp_members        = Connection_members,
    .tp_getset         = Connection_getset,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Connection_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define CONNECTION(obj) ((Connection *)(obj))


/******************************************************************************
 * Session object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *address;
    PyObject *credentials;
    PyObject *store;
    PyObject *message;
    size_t max_requests;
    size_t requests;
    bool closed;
} Session;

static PyMemberDef Session_members[] = {
    {"address",      T_OBJECT,   offsetof(Session, address),      READONLY, NULL},
    {"credentials",  T_OBJECT,   offsetof(Session, credentials),  READONLY, NULL},
    {"store",        T_OBJECT,   offsetof(Session, store),        READONLY, NULL},
    {"message",      T_OBJECT,   offsetof(Session, message),      READONLY, NULL},
    {"max_requests", T_PYSSIZET, offsetof(Session, max_requests), READONLY, NULL},
    {"requests",     T_PYSSIZET, offsetof(Session, requests),     READONLY, NULL},
    {"closed",       T_BOOL,     offsetof(Session, closed),       READONLY, NULL},
    {NULL}
};

static void Session_dealloc(Session *);
static int Session_init(Session *, PyObject *, PyObject *);
static PyObject * Session_repr(Session *);
static PyObject * Session_str(Session *);

static PyTypeObject SessionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Session",
    .tp_basicsize      = sizeof(Session),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Session_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = (reprfunc)Session_repr,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = NULL,
    .tp_str            = (reprfunc)Session_str,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Session(address, credentials=None, max_requests=None)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = NULL,
    .tp_members        = Session_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Session_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};

#define SESSION(obj) ((Session *)(obj))


/******************************************************************************
 * Router object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *appmap;
} Router;

static PyMemberDef Router_members[] = {
    {"appmap", T_OBJECT, offsetof(Router, appmap), READONLY, NULL},
    {NULL}
};

static void Router_dealloc(Router *);
static int Router_init(Router *, PyObject *, PyObject *);
static PyObject * Router_call(Router *, PyObject *, PyObject *);

static PyTypeObject RouterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.Router",
    .tp_basicsize      = sizeof(Router),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)Router_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = NULL,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = (ternaryfunc)Router_call,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "Router(appmap)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = NULL,
    .tp_members        = Router_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)Router_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};


/******************************************************************************
 * ProxyApp object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *client;
    PyObject *key;
} ProxyApp;

static PyMemberDef ProxyApp_members[] = {
    {"client",  T_OBJECT, offsetof(ProxyApp, client),  READONLY, NULL},
    {"key",     T_OBJECT, offsetof(ProxyApp, key),     READONLY, NULL},
    {NULL}
};

static void ProxyApp_dealloc(ProxyApp *);
static int ProxyApp_init(ProxyApp *, PyObject *, PyObject *);
static PyObject * ProxyApp_call(ProxyApp *, PyObject *, PyObject *);

static PyTypeObject ProxyAppType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name           = "degu._base.ProxyApp",
    .tp_basicsize      = sizeof(ProxyApp),
    .tp_itemsize       = 0,
    .tp_dealloc        = (destructor)ProxyApp_dealloc,
    .tp_print          = NULL,
    .tp_getattr        = NULL,
    .tp_setattr        = NULL,
    _TP_AS_ASYNC       = NULL,
    .tp_repr           = NULL,
    .tp_as_number      = NULL,
    .tp_as_sequence    = NULL,
    .tp_as_mapping     = NULL,
    .tp_hash           = NULL,
    .tp_call           = (ternaryfunc)ProxyApp_call,
    .tp_str            = NULL,
    .tp_getattro       = NULL,
    .tp_setattro       = NULL,
    .tp_as_buffer      = NULL,
    .tp_flags          = Py_TPFLAGS_DEFAULT,
    .tp_doc            = "ProxyApp(appmap)",
    .tp_traverse       = NULL,
    .tp_clear          = NULL,
    .tp_richcompare    = NULL,
    .tp_weaklistoffset = 0,
    .tp_iter           = NULL,
    .tp_iternext       = NULL,
    .tp_methods        = NULL,
    .tp_members        = ProxyApp_members,
    .tp_getset         = NULL,
    .tp_base           = NULL,
    .tp_dict           = NULL,
    .tp_descr_get      = NULL,
    .tp_descr_set      = NULL,
    .tp_dictoffset     = 0,
    .tp_init           = (initproc)ProxyApp_init,
    .tp_alloc          = NULL,
    .tp_new            = NULL,
    .tp_free           = NULL,
    .tp_is_gc          = NULL,
    .tp_bases          = NULL,
    .tp_mro            = NULL,
    .tp_cache          = NULL,
    .tp_subclasses     = NULL,
    .tp_weaklist       = NULL,
    .tp_del            = NULL,
    .tp_version_tag    = 0,
    .tp_finalize       = NULL,
};


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
 * VALUE 64 01000000  b'"\'()*,;<>[]'
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
      1,  1,  8, 64, 64, 16, 64,  4, //  '8'  '9'  ':'  ';'  '<'  '='  '>'  '?'
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

