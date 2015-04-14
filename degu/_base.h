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
        Py_FatalError("_ADD_MODULE_ATTR(): bad internal calls"); \
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
    PyObject *content_length; \
    PyObject *body; \
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
    ((DeguHeaders) {NULL, NULL, NULL, 0})


#define NEW_DEGU_REQUEST \
    ((DeguRequest) {NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL})


#define NEW_DEGU_RESPONSE \
    ((DeguResponse){NULL, NULL, NULL, 0, NULL, NULL})


typedef const struct {
    DeguDst scratch;
    PyObject *rfile;
    PyObject *Body;
    PyObject *ChunkedBody;
} DeguParse;


/******************************************************************************
 * Body object
 ******************************************************************************/
typedef struct {
    PyObject_HEAD
    PyObject *rfile;
    PyObject *rfile_read;
    uint64_t content_length;
    size_t io_size;
    uint64_t remaining;
    bool closed;
    bool chunked;
} Body;

static PyObject * Body_read(Body *, PyObject *, PyObject *);

static PyObject * Body_write_to(Body *, PyObject *);

static PyMethodDef Body_methods[] = {
    {"read",     (PyCFunction)Body_read,     METH_VARARGS|METH_KEYWORDS, "read(size)"},
    {"write_to", (PyCFunction)Body_write_to, METH_VARARGS, "write_to(wfile)"},
    {NULL}
};

static PyMemberDef Body_members[] = {
    {"rfile",          T_OBJECT_EX, offsetof(Body, rfile),          0, NULL},
    {"content_length", T_ULONGLONG, offsetof(Body, content_length), 0, NULL},
    {"_remaining",     T_ULONGLONG, offsetof(Body, remaining),      0, NULL},
    {"io_size",        T_PYSSIZET,  offsetof(Body, io_size),        0, NULL},
    {"closed",         T_BOOL,      offsetof(Body, closed),         0, NULL},
    {"chunked",        T_BOOL,      offsetof(Body, chunked),        0, NULL},
    {NULL}
};

static void Body_dealloc(Body *);

static PyObject * Body_repr(Body *);

static PyObject * Body_iter(Body *);

static PyObject * Body_next(Body *);

static int Body_init(Body *, PyObject *, PyObject *);

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
    "Body(rfile, content_length, io_size=1048576)",  /* tp_doc */
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

