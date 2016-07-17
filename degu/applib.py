# degu: an embedded HTTP server and client library
# Copyright (C) 2014-2016 Novacut Inc
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
A collection of RGI server applications for common scenarios.
"""

#try:
#    from ._base import (
#        AllowedMethods,
#        MethodFilter,
#        Router,
#        Proxy,
#    )
#except ImportError:
#    from ._basepy import (
#        AllowedMethods,
#        MethodFilter,
#        Router,
#        Proxy,
#    )

from ._basepy import AllowedMethods, MethodFilter, Proxy
try:
    from ._base import (
        Router,
    )
except ImportError:
    from ._basepy import (
        Router,
    )



__all__ = (
    'AllowedMethods',
    'MethodFilter',
    'Router',
    'Proxy',
)
