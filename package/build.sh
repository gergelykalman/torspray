#!/bin/bash

set -e

cd $(dirname "${BASH_SOURCE[0]}")/../

python -m pip install build

rm -rf dist/

python setup.py clean --all

python -m build
