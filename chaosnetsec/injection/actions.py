# -*- coding: utf-8 -*-
import os
import re
import threading
import time
from typing import Any, Dict, List, Union

import frida
from logzero import logger
import hexdump

from chaosnetsec.injection import attach_to_process

__all__ = ["replace_http_url_path", "connect_to_different_host",
           "process_session"]


def replace_http_url_path(proc_identifier: Union[int, str, Dict[str, Any]],
                          new_path: str, new_method: str = "GET",
                          source_path: str = "/", source_method: str = "GET",
                          script_path: str = "./scripts/ReplaceURLPath.js",
                          duration: int = 0):
    """
    Inject a script into the given process to replace HTTP calls made so that
    they aim a different path (and potentially with a different method).

    The script does this by hooking onto the ̀`socket.send` function used by the
    attached process.

    For instance, say you have a program that calls 
    """
    single_call = duration == 0
    seen_matched = False

    event = threading.Event()
    def on_message(message: Dict[str, Any], data: str, script):
        nonlocal seen_matched
        logger.debug("Received from process:\n{}".format(message))

        if message['type'] != u'send':
            return

        from_cb = message['payload']['from']
        data = message['payload']['data']

        if from_cb == "enter":
            source = "{} {}".format(source_method, source_path)
            rg = re.compile("{} HTTP/.*\r\n".format(source))
            m = rg.match(data)
            if m:
                seen_matched = True
                target = "{} {}".format(new_method, new_path)
                data = data.replace(source, target)
            script.post(
                message={'type': 'input', 'size': len(data)}, data=data)
        elif from_cb == "leave":
            h = hexdump.hexdump(data.encode('utf-8'), 'return')
            logger.debug("Data actually sent:\n{}".format(h))

            if single_call and seen_matched:
                event.set()

    p = proc_identifier
    s = script_path
    with process_session(p, s, on_message) as session:
        if single_call:
            event.wait()
            return
        else:
            start = time.time()
            while True:
                time.sleep(1)
                if time.time() - start >= duration:
                    return


def connect_to_different_host(proc_identifier: Union[int, str, Dict[str, Any]],
                              new_host: str, new_port: int,
                              old_host: str, old_port: int,
                              script_path: str = "./scripts/ConnectToDifferentHost.js",
                              duration: int = 0, blocking: bool = True):
    """
    Inject a script into the given process to replace HTTP calls made so that
    they aim a different path (and potentially with a different method).

    The script does this by hooking onto the ̀`socket.send` function used by the
    attached process.

    For instance, say you have a program that calls 
    """
    single_call = duration == 0
    seen_matched = False
    session = None

    event = threading.Event()
    def on_message(message: Dict[str, Any], data: str, script):
        nonlocal seen_matched
        logger.debug("Received from process:\n{}".format(message))

        if message['type'] != u'send':
            return

        if message['payload'] == 'ready':
            return

        from_cb = message['payload']['from']
        data = message['payload']['data']

        if from_cb == "connect":
            script.post(
                message={'type': 'input', 'errno': 111})
            if single_call:
                if not blocking:
                    session.detach()
                event.set()

    p = proc_identifier
    s = script_path

    if blocking:
        with process_session(p, s, on_message) as session:
            if single_call:
                event.wait()
                return
            else:
                start = time.time()
                while True:
                    time.sleep(1)
                    if time.time() - start >= duration:
                        return
    else:
        session = attach_to_process(p, s, on_message)

if __name__ == '__main__':
    connect_to_different_host({
        'name': 'python',
        'args': ['apps/public.py']
    }, 'www.python.org', 80, 'www.google.com', 80)