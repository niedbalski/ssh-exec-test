#!/usr/bin/env python

from setuptools import setup

setup(
    author="Jorge Niedbalski R. <jnr@metaklass.org>",
    name="ssh-exec-test",
    version="0.1.3",
    setup_requires=['pbr'],
    install_requires=['paramiko'],
    pbr=True,
)
