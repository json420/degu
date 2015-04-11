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


/******************************************************************************
 * Error handling macros (they require an "error" label in the function).
 ******************************************************************************/

#define _SET(pyobj, source) \
    if (pyobj != NULL) { \
        Py_FatalError("_SET(): pyobj != NULL prior to assignment"); \
    } \
    pyobj = (source); \
    if (pyobj == NULL) { \
        goto error; \
    }

#define _SET_AND_INC(pyobj, source) \
    _SET(pyobj, source) \
    Py_INCREF(pyobj);



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


/* _DEGU_SRC_CONSTANT(): helper macro for creating DeguSrc global constants */
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

