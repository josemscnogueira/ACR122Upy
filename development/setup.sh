#!/bin/bash
set -e

################################################################################
# Helper function to install pyenv
################################################################################
help_pyenv()
{
    echo "  [1] Install PyEnv https://github.com/pyenv/pyenv"
    echo "      [1.1] Make sure to add PYENV_ROOT and PATH with updated pyenv paths"
    echo "      [1.2] Make sure add eval pyenv init - to your bashrc or similar"
    echo "      [1.3] All install instructions are available on the github webpage"
}
################################################################################

################################################################################
# Helper function to install pyenv virtualenv
################################################################################
help_virtualenv()
{
    echo "  [2] Install PyEnv VirtualEnv https://github.com/pyenv/pyenv-virtualenv"
    echo "      [2.1] Make sure add eval pyenv virtual-init - to your bashrc or similar"
    echo "      [2.2] All install instructions are available on the github webpage"
}
################################################################################


################################################################################
# Check if PyEnv is installed
################################################################################
if ! command -v pyenv 1>/dev/null 2>&1
then
    echo "PyEnv is not installed."
    echo ""
    echo "Please use:"
    help_pyenv

    help_virtualenv
    exit 1
fi

################################################################################
# Check if PyEnv VirtualEnv is installed
################################################################################
if ! echo $(pyenv commands) | grep -q "virtualenv"
then
    echo "PyEnv VirtualEnv is not installed."
    echo ""
    echo "Please use:"
    help_virtualenv
    exit 1
fi


################################################################################
# Setup development environment
################################################################################
HERE="$(dirname $(realpath $0))/../"
pushd $HERE > /dev/null
    rm -rf .python-version

    LINUX_DISTRO=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
    if echo $LINUX_DISTRO | grep -iq "ubuntu"
    then
        sudo apt install -y pcscd \
                            libacsccid1 \
                            pcsc-tools \
                            libpcsclite1 \
                            libnfc-bin \
                            swig libpcsclite-dev
    fi

    PYTHON_VERSION="$(cat development/.python-version-reference | grep -v env)"
    PYTHON_VENV="$(cat development/.python-version-reference | grep env)"

    # Install necessary python version
    # This needs pyenv https://github.com/pyenv/pyenv
    if ! echo $(pyenv versions) | grep -q ${PYTHON_VERSION}
    then
        pyenv install ${PYTHON_VERSION}
    fi
    eval "$(pyenv init -)"

    # Install pyenv virtualenv plugin https://github.com/pyenv/pyenv-virtualenv
    if echo $(pyenv virtualenvs) | grep -q ${PYTHON_VENV}
    then
        pyenv virtualenv-delete -f ${PYTHON_VENV}
    fi
    pyenv virtualenv ${PYTHON_VERSION} ${PYTHON_VENV}
    eval "$(pyenv virtualenv-init -)"

    # Create .python-version
    echo ${PYTHON_VERSION}/envs/${PYTHON_VENV} > .python-version

    # Install required packages
    pip install  -U pip
    pip install -Ur development/requirements.txt

    # Print versions
    echo ""
    echo "---------------------------------------------------------------------"
    echo " Python and dependencies were installed succesfully"
    echo "---------------------------------------------------------------------"
    echo ""
    python --version
    pyenv version
popd > /dev/null
