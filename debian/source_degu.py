"""
Apport package hook for degu (requires Apport 2.5 or newer).

(c) 2014 Novacut Inc
Author: Jason Gerard DeRose <jderose@novacut.com>
"""

def add_info(report):
    report['CrashDB'] = "{'impl': 'launchpad', 'project': 'degu'}"

