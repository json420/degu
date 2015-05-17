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

#define IO_SIZE 1048576u
#define MAX_IO_SIZE 16777216u

#define BODY_READY 0u
#define BODY_STARTED 1u
#define BODY_CONSUMED 2u
#define BODY_ERROR 3u

#define BIT_CONTENT_LENGTH 1u
#define BIT_TRANSFER_ENCODING 2u
#define BIT_RANGE 4u
#define BIT_CONTENT_RANGE 8u
#define FRAMING_MASK 3u


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

/* A "NULL" DeguSrc */
#define NULL_DeguSrc ((DeguSrc){NULL, 0})

/* A "NULL" DeguDst */
#define NULL_DeguDst ((DeguDst){NULL, 0})

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
    PyObject *script;
    PyObject *path;
    PyObject *query;
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
    ((DeguRequest) {NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL})

#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, 0, 0, NULL, NULL})

typedef struct {
    PyObject *key;
    PyObject *val;
    PyObject *data;
    size_t size;
} DeguChunk;

#define NEW_DEGU_CHUNK \
    ((DeguChunk){NULL, NULL, NULL, 0})


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
static PyObject * format_headers(PyObject *, PyObject *);
static PyObject * format_request(PyObject *, PyObject *);
static PyObject * format_response(PyObject *, PyObject *);
static PyObject * format_chunk(PyObject *, PyObject *);

static PyObject * render_headers(PyObject *, PyObject *);
static PyObject * render_request(PyObject *, PyObject *);
static PyObject * render_response(PyObject *, PyObject *);

/* Misc */
static PyObject * readchunk(PyObject *, PyObject *);
static PyObject * write_chunk(PyObject *, PyObject *);
static PyObject * set_output_headers(PyObject *, PyObject *);

/* namedtuples */
static PyObject * Bodies(PyObject *, PyObject *);
static PyObject * Request(PyObject *, PyObject *);
static PyObject * Response(PyObject *, PyObject *);

/* Server and client entry points */
static PyObject * handle_requests(PyObject *, PyObject *);

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
    {"format_headers", format_headers, METH_VARARGS, NULL},
    {"format_request", format_request, METH_VARARGS, NULL},
    {"format_response", format_response, METH_VARARGS, NULL},
    {"format_chunk", format_chunk, METH_VARARGS, NULL},
    {"render_headers", render_headers, METH_VARARGS, NULL},
    {"render_request", render_request, METH_VARARGS, NULL},
    {"render_response", render_response, METH_VARARGS, NULL},

    /* Misc */
    {"readchunk", readchunk, METH_VARARGS, NULL},
    {"write_chunk", write_chunk, METH_VARARGS, NULL},
    {"set_output_headers", set_output_headers, METH_VARARGS, NULL},

    /* namedtuples */
    {"Bodies", Bodies, METH_VARARGS, NULL},
    {"Request", Request, METH_VARARGS, NULL},
    {"Response", Response, METH_VARARGS, NULL},

    /* Server and client entry points */
    {"handle_requests", handle_requests, METH_VARARGS, NULL},

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
    "degu._base.Range",                 /* tp_name */
    sizeof(Range),                      /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)Range_dealloc,          /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    (reprfunc)Range_repr,               /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    (reprfunc)Range_str,                /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "Range(start, stop)",               /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    (richcmpfunc)Range_richcompare,     /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    0,                                  /* tp_methods */
    Range_members,                      /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)Range_init,               /* tp_init */
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
    "degu._base.ContentRange",                 /* tp_name */
    sizeof(ContentRange),                      /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)ContentRange_dealloc,          /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    (reprfunc)ContentRange_repr,               /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    (reprfunc)ContentRange_str,                /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "ContentRange(start, stop, total)",               /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    (richcmpfunc)ContentRange_richcompare,     /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    0,                                  /* tp_methods */
    ContentRange_members,                      /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)ContentRange_init,               /* tp_init */
};


/******************************************************************************
 * Reader object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *recv_into;
    uint8_t *buf;
    uint64_t rawtell;
    size_t start;
    size_t stop;
} Reader;

static bool _Reader_readinto(Reader *, DeguDst);
static bool _Reader_read_chunkline(Reader *, DeguChunk *);

static PyObject * Reader_rawtell(Reader *);
static PyObject * Reader_tell(Reader *);
static PyObject * Reader_read_request(Reader *);
static PyObject * Reader_read_response(Reader *, PyObject *);
static PyObject * Reader_expose(Reader *);
static PyObject * Reader_peek(Reader *, PyObject *);
static PyObject * Reader_read_until(Reader *, PyObject *);
static PyObject * Reader_readinto(Reader *, PyObject *);

static PyMethodDef Reader_methods[] = {
    {"rawtell", (PyCFunction)Reader_rawtell, METH_NOARGS, NULL},
    {"tell", (PyCFunction)Reader_tell, METH_NOARGS, NULL},
    {"read_request", (PyCFunction)Reader_read_request, METH_NOARGS, NULL},
    {"read_response", (PyCFunction)Reader_read_response, METH_VARARGS, NULL},
    {"expose", (PyCFunction)Reader_expose, METH_NOARGS, NULL},
    {"peek", (PyCFunction)Reader_peek, METH_VARARGS, NULL},
    {"read_until", (PyCFunction)Reader_read_until, METH_VARARGS, NULL},
    {"readinto", (PyCFunction)Reader_readinto, METH_VARARGS, NULL},
    {NULL}
};

static void Reader_dealloc(Reader *);
static int Reader_init(Reader *, PyObject *, PyObject *);

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
};

#define READER_CLASS ((PyObject *)&ReaderType)
#define IS_READER(obj) (Py_TYPE((obj)) == &ReaderType)
#define READER(obj) ((Reader *)(obj))

typedef struct {
    Reader *reader;
    PyObject *readinto;
    PyObject *readline;
} DeguRObj;

#define NEW_DEGU_ROBJ ((DeguRObj){NULL, NULL, NULL}) 


/******************************************************************************
 * Writer object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *send;
    uint8_t *buf;
    uint64_t tell;
    size_t stop;
} Writer;

static ssize_t _Writer_write(Writer *, DeguSrc);

static PyObject * Writer_tell(Writer *);
static PyObject * Writer_write_output(Writer *, PyObject *);
static PyObject * Writer_write_request(Writer *, PyObject *);
static PyObject * Writer_write_response(Writer *, PyObject *);

static PyMethodDef Writer_methods[] = {
    {"tell", (PyCFunction)Writer_tell, METH_NOARGS, NULL},
    {"write_output", (PyCFunction)Writer_write_output, METH_VARARGS, NULL},
    {"write_request", (PyCFunction)Writer_write_request, METH_VARARGS, NULL},
    {"write_response", (PyCFunction)Writer_write_response, METH_VARARGS, NULL},
    {NULL}
};

static void Writer_dealloc(Writer *);
static int Writer_init(Writer *, PyObject *, PyObject *);

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
};

#define WRITER_CLASS ((PyObject *)&WriterType)
#define IS_WRITER(obj) (Py_TYPE((obj)) == &WriterType)
#define WRITER(obj) ((Writer *)(obj))

typedef struct {
    Writer *writer;
    PyObject *write;
} DeguWObj;

#define NEW_DEGU_WOBJ ((DeguWObj){NULL, NULL})


/******************************************************************************
 * Body object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    DeguRObj robj;
    uint64_t content_length;
    uint64_t remaining;
    uint8_t state;
    bool chunked;
} Body;

static PyObject * _Body_New(PyObject *, uint64_t);
static int64_t _Body_write_to(Body *, DeguWObj *);

static PyMemberDef Body_members[] = {
    {"rfile",          T_OBJECT_EX, offsetof(Body, rfile),          READONLY, NULL},
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
    "degu._base.Body",                  /* tp_name */
    sizeof(Body),                       /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)Body_dealloc,           /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    (reprfunc)Body_repr,                /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "Body(rfile, content_length)",      /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    (getiterfunc)Body_iter,             /* tp_iter */
    (iternextfunc)Body_next,            /* tp_iternext */
    Body_methods,                       /* tp_methods */
    Body_members,                       /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)Body_init,                /* tp_init */
};

#define IS_BODY(obj) (Py_TYPE((obj)) == &BodyType)
#define BODY(obj) ((Body *)(obj))


/******************************************************************************
 * ChunkedBody object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    DeguRObj robj;
    uint8_t state;
    bool chunked;
} ChunkedBody;

static PyObject * _ChunkedBody_New(PyObject *);
static int64_t _ChunkedBody_write_to(ChunkedBody *, DeguWObj *);

static PyMemberDef ChunkedBody_members[] = {
    {"rfile",    T_OBJECT_EX, offsetof(ChunkedBody, rfile),    READONLY, NULL},
    {"state",    T_UBYTE,     offsetof(ChunkedBody, state),    READONLY, NULL},
    {"chunked",  T_BOOL,      offsetof(ChunkedBody, chunked),  READONLY, NULL},
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
    "degu._base.ChunkedBody",           /* tp_name */
    sizeof(ChunkedBody),                /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)ChunkedBody_dealloc,    /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    (reprfunc)ChunkedBody_repr,         /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                 /* tp_flags */
    "ChunkedBody(rfile)",               /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    (getiterfunc)ChunkedBody_iter,      /* tp_iter */
    (iternextfunc)ChunkedBody_next,     /* tp_iternext */
    ChunkedBody_methods,                /* tp_methods */
    ChunkedBody_members,                /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)ChunkedBody_init,         /* tp_init */
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

static int64_t _BodyIter_write_to(BodyIter *, DeguWObj *);

static PyMemberDef BodyIter_members[] = {
    {"source", T_OBJECT_EX, offsetof(BodyIter, source), READONLY, NULL},
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
    "degu._base.BodyIter",                  /* tp_name */
    sizeof(BodyIter),                       /* tp_basicsize */
    0,                                      /* tp_itemsize */
    (destructor)BodyIter_dealloc,           /* tp_dealloc */
    0,                                      /* tp_print */
    0,                                      /* tp_getattr */
    0,                                      /* tp_setattr */
    0,                                      /* tp_reserved */
    (reprfunc)BodyIter_repr,                /* tp_repr */
    0,                                      /* tp_as_number */
    0,                                      /* tp_as_sequence */
    0,                                      /* tp_as_mapping */
    0,                                      /* tp_hash  */
    0,                                      /* tp_call */
    0,                                      /* tp_str */
    0,                                      /* tp_getattro */
    0,                                      /* tp_setattro */
    0,                                      /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                     /* tp_flags */
    "BodyIter(source)",                     /* tp_doc */
    0,                                      /* tp_traverse */
    0,                                      /* tp_clear */
    0,                                      /* tp_richcompare */
    0,                                      /* tp_weaklistoffset */
    0,                                      /* tp_iter */
    0,                                      /* tp_iternext */
    BodyIter_methods,                       /* tp_methods */
    BodyIter_members,                       /* tp_members */
    0,                                      /* tp_getset */
    0,                                      /* tp_base */
    0,                                      /* tp_dict */
    0,                                      /* tp_descr_get */
    0,                                      /* tp_descr_set */
    0,                                      /* tp_dictoffset */
    (initproc)BodyIter_init,                /* tp_init */
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

static int64_t _ChunkedBodyIter_write_to(ChunkedBodyIter *, DeguWObj *);

static PyMemberDef ChunkedBodyIter_members[] = {
    {"source", T_OBJECT_EX, offsetof(ChunkedBodyIter, source), READONLY, NULL},
    {"state",  T_UBYTE,     offsetof(ChunkedBodyIter, state),  READONLY, NULL},
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
    "degu._base.ChunkedBodyIter",           /* tp_name */
    sizeof(ChunkedBodyIter),                /* tp_basicsize */
    0,                                      /* tp_itemsize */
    (destructor)ChunkedBodyIter_dealloc,    /* tp_dealloc */
    0,                                      /* tp_print */
    0,                                      /* tp_getattr */
    0,                                      /* tp_setattr */
    0,                                      /* tp_reserved */
    (reprfunc)ChunkedBodyIter_repr,         /* tp_repr */
    0,                                      /* tp_as_number */
    0,                                      /* tp_as_sequence */
    0,                                      /* tp_as_mapping */
    0,                                      /* tp_hash  */
    0,                                      /* tp_call */
    0,                                      /* tp_str */
    0,                                      /* tp_getattro */
    0,                                      /* tp_setattro */
    0,                                      /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,                     /* tp_flags */
    "ChunkedBodyIter(source)",              /* tp_doc */
    0,                                      /* tp_traverse */
    0,                                      /* tp_clear */
    0,                                      /* tp_richcompare */
    0,                                      /* tp_weaklistoffset */
    0,                                      /* tp_iter */
    0,                                      /* tp_iternext */
    ChunkedBodyIter_methods,                /* tp_methods */
    ChunkedBodyIter_members,                /* tp_members */
    0,                                      /* tp_getset */
    0,                                      /* tp_base */
    0,                                      /* tp_dict */
    0,                                      /* tp_descr_get */
    0,                                      /* tp_descr_set */
    0,                                      /* tp_dictoffset */
    (initproc)ChunkedBodyIter_init,         /* tp_init */
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
    PyObject *bodies;
    PyObject *reader;
    PyObject *writer;
    PyObject *response_body;
    bool closed;
} Connection;

static PyMemberDef Connection_members[] = {
    {"sock",         T_OBJECT_EX, offsetof(Connection, sock),         READONLY, NULL},
    {"base_headers", T_OBJECT_EX, offsetof(Connection, base_headers), READONLY, NULL},
    {"bodies",       T_OBJECT_EX, offsetof(Connection, bodies),       READONLY, NULL},
    {"closed",       T_BOOL,      offsetof(Connection, closed),       READONLY, NULL},
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

static void _Connection_shutdown(Connection *);
static void Connection_dealloc(Connection *);
static int Connection_init(Connection *, PyObject *, PyObject *);

static PyTypeObject ConnectionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "degu._base.Connection",            /* tp_name */
    sizeof(Connection),                 /* tp_basicsize */
    0,                                  /* tp_itemsize */
    (destructor)Connection_dealloc,     /* tp_dealloc */
    0,                                  /* tp_print */
    0,                                  /* tp_getattr */
    0,                                  /* tp_setattr */
    0,                                  /* tp_reserved */
    0,                                  /* tp_repr */
    0,                                  /* tp_as_number */
    0,                                  /* tp_as_sequence */
    0,                                  /* tp_as_mapping */
    0,                                  /* tp_hash  */
    0,                                  /* tp_call */
    0,                                  /* tp_str */
    0,                                  /* tp_getattro */
    0,                                  /* tp_setattro */
    0,                                  /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_FINALIZE,                 /* tp_flags */
    "Connection(sock, base_headers)",   /* tp_doc */
    0,                                  /* tp_traverse */
    0,                                  /* tp_clear */
    0,                                  /* tp_richcompare */
    0,                                  /* tp_weaklistoffset */
    0,                                  /* tp_iter */
    0,                                  /* tp_iternext */
    Connection_methods,                 /* tp_methods */
    Connection_members,                 /* tp_members */
    0,                                  /* tp_getset */
    0,                                  /* tp_base */
    0,                                  /* tp_dict */
    0,                                  /* tp_descr_get */
    0,                                  /* tp_descr_set */
    0,                                  /* tp_dictoffset */
    (initproc)Connection_init,          /* tp_init */
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

