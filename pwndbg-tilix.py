import os
import gdb
import sys
import stat
import atexit
import time
from pwndbg.commands.context import contextoutput, contextwatch, output, clear_screen

class TilixIntegration(gdb.Command):
    already_running = False

    def move_cursor_to(self, direction):
        time.sleep(0.3)
        direction = direction.lower()

        if direction not in ['up', 'down', 'left', 'right']:
            return

        os.popen('xdotool key Alt+{0}'.format(direction.capitalize()))

    def add_new_panel_down(self):
        fifo = '/tmp/mytmpfifo'

        try:
            if stat.S_ISFIFO(os.stat(fifo).st_mode):
                os.remove(fifo)

        except:
            pass

        os.mkfifo(fifo)
        command = 'tilix -a session-add-down -e "/bin/bash -c \\"(echo \\$\\$ && tty) > {0} && cat -\\""'.format(fifo)
        os.popen(command)
        
        f = open(fifo, 'r')
        panel_info = f.read()
        f.close()

        try:
            if stat.S_ISFIFO(os.stat(fifo).st_mode):
                os.remove(fifo)

        except:
            pass

        panel_info = panel_info.split()
        pid = None
        tty = None
        if len(panel_info) == 2:
            pid, tty = panel_info
            pid = pid.strip()
            tty = tty.strip()

        return pid, tty

    def add_new_panel_right(self):
        fifo = '/tmp/mytmpfifo'

        try:
            if stat.S_ISFIFO(os.stat(fifo).st_mode):
                os.remove(fifo)

        except:
            pass

        os.mkfifo(fifo)
        command = 'tilix -a session-add-right -e "/bin/bash -c \\"(echo \\$\\$ && tty) > {0} && cat -\\""'.format(fifo)
        os.popen(command)
        
        f = open(fifo, 'r')
        panel_info = f.read()
        f.close()

        try:
            if stat.S_ISFIFO(os.stat(fifo).st_mode):
                os.remove(fifo)

        except:
            pass

        panel_info = panel_info.split()
        pid = None
        tty = None
        if len(panel_info) == 2:
            pid, tty = panel_info
            pid = pid.strip()
            tty = tty.strip()

        return pid, tty

    def show_help(self):
        print('Use the command "tilix-integration" or "tilix-integration enable" to enable it. Use "tilix-integration disable" to disable it\n')

    def complete(self, arguments_string, last):
        all_commands = ['enable', 'disable', 'help']
        if arguments_string.strip() == '':
            return all_commands

        ret_list = []

        if len(arguments_string.split()) == 1:
            for possible_command in all_commands:
                if possible_command.startswith(arguments_string.strip()) and possible_command != arguments_string.strip():
                    ret_list.append(possible_command)
        
        return ret_list

    def on_process_attach(self, event):
        gdb.events.stop.disconnect(self.on_process_attach)
        pointer_size = gdb.parse_and_eval("sizeof(void *)")

        if pointer_size and str(pointer_size).isdigit():
            if int(str(pointer_size)) == 8:
                self.examine_stack_command = 'x/40gx $sp'

            elif int(str(pointer_size)) == 4:
                self.examine_stack_command = 'x/80wx $sp'

            contextwatch(self.examine_stack_command, "execute")


    def invoke(self, arg, from_tty):
        if arg.strip().lower() in ['help', '?', '/?', '-h', '--help']:
            self.show_help()
            return

        if arg.strip().lower() in ['disable', 'kill', 'quit', 'exit']:
            if self.already_running:
                if getattr(self, 'panes'):
                    [os.popen('kill {0} 2>/dev/null'.format(p[0])).read() for p in self.panes.values()]
                    for sec, p in self.panes.items():
                        contextoutput(sec, 'stdout', True)

                    contextoutput('legend', 'stdout', True)

                self.already_running = False

            return

        if arg.strip().lower() not in ['', 'enable', 'start']:
            self.show_help()
            return

        if self.already_running:
            return

        gdb.events.stop.connect(self.on_process_attach)

        self.already_running = True
        top_right_pid, top_right_tty = self.add_new_panel_right()
        down_right_pid, down_right_tty = self.add_new_panel_down()
        down_right_right_pid, down_right_right_tty = self.add_new_panel_right()
        self.move_cursor_to('left')
        self.move_cursor_to('left')
        left_down_pid, left_down_tty = self.add_new_panel_down()
        self.move_cursor_to('up')  # restore focus to pwndbg


        # Customize as you want here
        disas = [top_right_pid, top_right_tty]
        backtrace = [down_right_pid, down_right_tty]
        regs = [down_right_right_pid, down_right_right_tty]
        expressions = [left_down_pid, left_down_tty]
        

        self.panes = dict(disasm=disas, regs=regs, backtrace=backtrace, expressions=expressions)
        for sec, p in self.panes.items():
            contextoutput(sec, p[1], True)
            
            try:
                with open(p[1], 'w') as f:
                    f.write('---[{0}]---\n'.format(sec))

            except:
                pass
        
        contextoutput("legend", disas[1], True)
        contextoutput("stack", "/dev/null", True)
        contextwatch(self.examine_stack_command, "execute")
        atexit.register(lambda: [os.popen('kill {0} 2>/dev/null'.format(p[0])).read() for p in self.panes.values() if self.already_running])

    def __init__(self):
        self.examine_stack_command = 'x/80wx $sp'
        super(TilixIntegration, self).__init__("tilix-integration", gdb.COMMAND_USER)

TilixIntegration()
