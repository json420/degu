# degu: an embedded HTTP server and client library
# Copyright (C) 2014 Novacut Inc
#
# This file is part of `degu`.
#
# `degu` is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# `degu` is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with `degu`.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   Jason Gerard DeRose <jderose@novacut.com>

"""
High-level, domain-specific client for a JSON lovin' REST API like CouchDB.

This is a proof of concept domain-specific API built atop `degu.client.Client`.
"""

from json import dumps, loads
from urllib.parse import quote_plus
from collections import namedtuple


Attachment = namedtuple('Attachment', 'content_type body')


class HTTPError(Exception):
    def __init__(self, response, method, uri):
        self.response = response
        self.method = method
        self.uri = uri
        super().__init__(
            '{} {}: {} {}'.format(response.status, response.reason, method, uri)
        )


class BulkConflict(Exception):
    def __init__(self, conflicts, rows):
        self.conflicts = conflicts
        self.rows = rows
        count = len(conflicts)
        msg = ('conflict on {} doc' if count == 1 else 'conflict on {} docs')
        super().__init__(msg.format(count))


def _build_query(query):
    pairs = []
    for (key, value) in query.items():
        if key in ('key', 'startkey', 'endkey') or not isinstance(value, str):
            value = dumps(value, sort_keys=True, separators=(',', ':'))
        pairs.append('{}={}'.format(key, quote_plus(value)))
    pairs.sort()
    return '&'.join(pairs)


class JSONClient:
    def __init__(self, client, *script):
        self.client = client
        self.script = script

    def connect(self, bodies=None):
        conn = self.client.connect(bodies=bodies)
        return JSONConnection(conn, *self.script)


class JSONConnection:
    """
    A generic JSON REST adapter implemented the "Degu way".

    This doodle implements most of the `microfiber.CouchBase` functionality.
    """

    def __init__(self, conn, *script):
        self.conn = conn
        self.script = script

    @property
    def closed(self):
        return self.conn.closed

    def close(self):
        return self.conn.close()

    def request(self, method, headers, body, *path, **query):
        uri = '/' + '/'.join(self.script + path)
        if query:
            uri = '?'.join([uri, _build_query(query)])
        response = self.conn.request(method, uri, headers, body)
        if 200 <= response.status <= 299:
            return response
        raise HTTPError(response, method, uri)

    def json_request(self, method, headers, body, *path, **query):
        if body is not None:
            if isinstance(body, (dict, list)):
                body = dumps(body, sort_keys=True, separators=(',', ':')).encode()
            headers['content-type'] = 'application/json'
        response = self.request(method, headers, body, *path, **query)
        if response.body is not None:
            return loads(response.body.read().decode())

    def post(self, obj, *path, **query):
        return self.json_request('POST', {}, obj, *path, **query)

    def put(self, obj, *path, **query):
        return self.json_request('PUT', {}, obj, *path, **query)

    def get(self, *path, **query):
        return self.json_request('GET', {}, None, *path, **query)

    def delete(self, *path, **query):
        return self.json_request('DELETE', {}, None, *path, **query)

    def head(self, *path, **query):
        response = self.request('HEAD', {}, None, *path, **query)
        return response.headers

    def put_att(self, attachment, *path, **query):
        (content_type, body) = attachment
        headers = {'content-type': content_type}
        response = self.request('PUT', headers, body, *path, **query)
        if response.body is not None:
            return loads(response.body.read().decode())

    def get_att(self, *path, **query):
        response = self.request('GET', {}, None, *path, **query)
        return Attachment(response.headers.get('content-type'), response.body)

    def save(self, doc, *path, **query):
        r = self.post(doc)
        doc['_rev'] = r['rev']
        return r

    def save_many(self, docs, *path, **query):
        path += ('_bulk_docs',)
        rows = self.post({'docs': docs}, *path, **query)
        conflicts = []
        for (doc, row) in zip(docs, rows):
            assert doc['_id'] == row['id']
            if 'rev' in row:
                doc['_rev'] = row['rev']
            else:
                conflicts.append(doc)
        if conflicts:
            raise BulkConflict(conflicts, rows)
        return rows

