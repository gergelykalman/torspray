#!/bin/bash

set -e

cd $(dirname "${BASH_SOURCE[0]}")/../

twine check dist/*

twine upload --verbose -u gergelykalman dist/*
