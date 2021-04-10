#!/bin/bash
set -e

HERE=$(dirname $(realpath $0))
pushd $HERE > /dev/null
    find .. -type f -name '*.pyc'       -delete
    find .. -type d -name '__pycache__' -delete
    find .. -type d -empty              -delete
popd > /dev/null
