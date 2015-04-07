
SSH Exec test
=============

This is a library for testing software that makes use of paramiko, fabric
or any other component, that relies on SSH shell_exec method for executing
remote commands.

Usage
======

For more examples, please checkout the tests directory.

```bash
$ pip install ssh-exec-test
```

```python
from ssh_exec_test import (assert_ssh_exec, input)

with assert_ssh_exec(rules=[
   input("sudo ls -lhR", output="foobar"),
   input("sudo ls -lhRT", output="foobar1"),
]) as server:

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("127.0.0.1", 2022, "ubuntu", "ubuntu")
    stdin, stdout, _ = ssh.exec_command("sudo ls -lhR")
    ssh.close()


    assert stdout.read() == "foobar"
```


