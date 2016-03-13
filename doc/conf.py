import sys
from os import path

tree = path.dirname(path.dirname(path.abspath(__file__)))
sys.path.insert(0, tree)

import degu


# Project info
project = 'Degu'
copyright = '2014-2016, Novacut Inc'
version = degu.__version__
release = version


# General config
needs_sphinx = '1.1'
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'
exclude_patterns = ['_build']
pygments_style = 'sphinx'


# HTML config
html_theme = 'default'
html_static_path = ['_static']
htmlhelp_basename = 'Degudoc'

