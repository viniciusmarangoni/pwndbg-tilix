#!/bin/bash

tilix --geometry=230x50+50+50 -e "/bin/bash -c \"gdb -q $@ ; echo exited ; read\""
