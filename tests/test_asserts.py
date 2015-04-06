#!/usr/bin/env python

import unittest
import paramiko

from ssh_exec_test import (assert_ssh_exec,
                        input)


def run_client(command):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("127.0.0.1", 2022, "ubuntu", "ubuntu")
    stdin, stdout, _ = ssh.exec_command(command)
    ssh.close()
    return stdout.read().decode("unicode_escape")


class TestAssertSSHExec(unittest.TestCase):

    def test_assert_ssh_exec(self):

        with assert_ssh_exec(rules=[
                input("sudo ls -lh", output="foo"),
                input("sudo ls -lth", output="bar"),
        ]) as server:

            self.assertEqual(run_client("sudo ls -lh"), "foo")
            self.assertEqual(run_client("sudo ls -lth"), "bar")

            run_client("sudo ls -lhTr")
            run_client("not defined command")

            self.assertEqual(len(server.exceptions), 2)
