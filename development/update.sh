#!/bin/bash
HERE="$(dirname $(realpath $0))/../"
pushd $HERE > /dev/null
    pip install -r development/requirements.txt --upgrade pip
popd > /dev/null
