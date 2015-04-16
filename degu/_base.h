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

#define _MAX_LINE_SIZE 4096
#define MIN_PREAMBLE 4096
#define MAX_PREAMBLE 65536
#define DEFAULT_PREAMBLE 32768
#define MAX_KEY 32
#define MAX_CL_LEN 16
#define MAX_IO_SIZE 16777216
#define MAX_LENGTH 9999999999999999ull
#define IO_SIZE 1048576


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
} DeguResponse;

#define NEW_DEGU_HEADERS \
    ((DeguHeaders) {NULL, NULL, 0, 0})

#define NEW_DEGU_REQUEST \
    ((DeguRequest) {NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL})

#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, 0, 0, NULL, NULL})

typedef const struct {
    DeguDst scratch;
    PyObject *rfile;
    PyObject *Body;
    PyObject *ChunkedBody;
} DeguParse;


/******************************************************************************
 * Range object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    uint64_t start;
    uint64_t stop;
} Range;

static PyObject * Range_New(uint64_t, uint64_t);

static void Range_dealloc(Range *);
static int Range_init(Range *, PyObject *, PyObject *);
static PyObject * Range_repr(Range *);
static PyObject * Range_str(Range *);
static PyObject * Range_richcompare(Range *, PyObject *, int);

static PyMemberDef Range_members[] = {
    {"start", T_ULONGLONG, offsetof(Range, start), READONLY, NULL},
    {"stop",  T_ULONGLONG, offsetof(Range, stop),  READONLY, NULL},
    {NULL}
};

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
 * Reader object.
 ******************************************************************************/
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

static PyObject * Reader_close(Reader *);
static PyObject * Reader_rawtell(Reader *);
static PyObject * Reader_tell(Reader *);
static PyObject * Reader_read_request(Reader *);
static PyObject * Reader_read_response(Reader *, PyObject *);
static PyObject * Reader_expose(Reader *);
static PyObject * Reader_peek(Reader *, PyObject *);
static PyObject * Reader_read_until(Reader *, PyObject *, PyObject *);
static PyObject * Reader_readline(Reader *, PyObject *);
static PyObject * Reader_read(Reader *, PyObject *);
static PyObject * Reader_readinto(Reader *, PyObject *);

static PyMethodDef Reader_methods[] = {
    {"close", (PyCFunction)Reader_close, METH_NOARGS, NULL},
    {"rawtell", (PyCFunction)Reader_rawtell, METH_NOARGS, NULL},
    {"tell", (PyCFunction)Reader_tell, METH_NOARGS, NULL},
    {"read_request", (PyCFunction)Reader_read_request, METH_NOARGS, NULL},
    {"read_response", (PyCFunction)Reader_read_response, METH_VARARGS, NULL},
    {"expose", (PyCFunction)Reader_expose, METH_NOARGS, NULL},
    {"peek", (PyCFunction)Reader_peek, METH_VARARGS, NULL},
    {"read_until", (PyCFunction)Reader_read_until, METH_VARARGS|METH_KEYWORDS, NULL},
    {"readline", (PyCFunction)Reader_readline, METH_VARARGS, NULL},
    {"read", (PyCFunction)Reader_read, METH_VARARGS, NULL},
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


/******************************************************************************
 * Body object.
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    PyObject *rfile_read;
    uint64_t content_length;
    uint64_t remaining;
    bool closed;
    bool error;
    bool chunked;
} Body;

static PyObject * Body_New(PyObject *, uint64_t);

static PyMemberDef Body_members[] = {
    {"rfile",          T_OBJECT_EX, offsetof(Body, rfile),          READONLY, NULL},
    {"content_length", T_ULONGLONG, offsetof(Body, content_length), READONLY, NULL},
    {"closed",         T_BOOL,      offsetof(Body, closed),         READONLY, NULL},
    {"error",          T_BOOL,      offsetof(Body, error),          READONLY, NULL},
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

