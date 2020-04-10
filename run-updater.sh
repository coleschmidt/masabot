#!/bin/bash

# starts up updater
#
# options:
#
# $1 - venv-dir - path to the directory to use for the virtual environment, default to '.venv' or 'venv' in that order
# if none is given.

if [ "$#" -ge 1 ]
then
  if [ -d "$1" ]
  then
    virtual_dir="$1"
  else
    echo "Virtual environemnt directory '$1' not found." >&2
    echo "Abort." >&2
    exit 1
  fi
else
  echo "No virtual environment directory given; scanning for '.venv' or 'venv'..." >&2
  if [ -d .venv ]
  then
      virtual_dir=.venv
  elif [ -d venv ]
  then
      virtual_dir=venv
  else
      echo "Could not auto-detect virtual environment directory '.venv' or 'venv'." >&2
      echo "Please create one for masabot before executing, or point to existing one with CLI arguments." >&2
      exit 1
  fi
fi

running=1

echo "Using virtual environment directory '$virtual_dir'"

if [ -d "$virtual_dir/bin" ]
then
    virtualenv_path="$virtual_dir/bin"
elif [ -d "$virtual_dir/Scripts" ]
then
    virtualenv_path="$virtual_dir/Scripts"
else
    echo "Virtual environment not found in '$virtual_dir/bin' or '$virtual_dir/Scripts'." >&2
    echo "Please ensure setup is correct." >&2
    exit 1
fi

. "$virtualenv_path/activate"

python updater.py