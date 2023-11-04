#!/bin/bash
PARAMS="$@"
tilix --geometry=230x50+50+50 -e "/bin/bash -l -c \"/usr/bin/gdb $PARAMS ; echo exited ; read\""
