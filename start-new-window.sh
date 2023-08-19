#!/bin/bash

tilix --geometry=230x50+50+50 -e "/bin/bash -l -c \"/usr/bin/gdb -q $@ ; echo exited ; read\""
