#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dedicated scheduler process for dns-panel.
Run APScheduler in a single process to avoid duplicate jobs under multi-worker web server.
"""
import os
import signal
import sys
import time

# Force scheduler enabled in this process
os.environ['DNS_PANEL_DISABLE_SCHEDULER'] = '0'

from app import app  # noqa: E402


_running = True


def _handle_stop(signum, frame):
    global _running
    _running = False


signal.signal(signal.SIGTERM, _handle_stop)
signal.signal(signal.SIGINT, _handle_stop)


if __name__ == '__main__':
    print('dns-panel scheduler worker started (single-process).')
    # app import already initialized scheduler.start() when DNS_PANEL_DISABLE_SCHEDULER=0
    while _running:
        time.sleep(1)
    print('dns-panel scheduler worker stopped.')
    sys.exit(0)
