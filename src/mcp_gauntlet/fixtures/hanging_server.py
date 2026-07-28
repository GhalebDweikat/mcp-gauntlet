"""A fixture that connects and then never answers, to prove we clean it up.

A survey of unvetted packages times out constantly, and a timeout is exactly when process
cleanup is most likely to be skipped: the cancellation that ends the evaluation also
cancels the `await` that kills the child. A server that outlives the harness then holds
whatever it had — a port, a lock, a database handle — and poisons every later attempt at
it, so the harness ends up scoring its own debris.

Writes its PID to the path in GAUNTLET_PIDFILE so a test can check whether it is still
running afterwards.
"""

import os
import sys
import time

pidfile = os.environ.get("GAUNTLET_PIDFILE")
if pidfile:
    with open(pidfile, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))

# Never speak MCP at all: the client waits for an initialize response that never comes.
sys.stderr.write("hanging-fixture: started, will not respond\n")
sys.stderr.flush()
while True:
    time.sleep(3600)
