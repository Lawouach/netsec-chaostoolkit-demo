# -*- coding: utf-8 -*-
from contextlib import contextmanager
from functools import partial, singledispatch
import os
import re
import time
from typing import Any, Callable, Dict, Union

from chaoslib.exceptions import FailedActivity
import frida
from logzero import logger
import psutil

__all__ = ["attach_to_process", "find_proc_by_name", "load_script"]

FridaOnMessage = Callable[[Dict[str, Any], bytes], None]


@contextmanager
def process_session(proc_identifier: Union[int, str, Dict[str, Any]],
                    script_path: str = None,
                    on_message: FridaOnMessage = None):
    """
    Attach to a given process, either by name of PID, and load the given
    script to perform injections (when provided).

    If `proc_identifier` is a string, the name of the process, the first
    process that matches that name is used so this may create false positives.

    If `proc_identifier` is a mapping, it can contain any the following keys:

    - name
    - cwd
    - args
    - uid
    - gid
    - username
    - created_in_the_last

    In that case, the function does its best to find the process that matches
    the best that combination. The `created_in_the_last` key is an integer
    of the number of second within which the process was created. The `args`
    key is a list of strings of arguments the process was created with, only
    pass the command line arguments you want to match with, not all of them.
    """
    session = None
    try:
        session = attach_to_process(
            proc_identifier, script_path, on_message)
        yield session
    except Exception as x:
        m = "Failed to attach to process '{}'".format(proc_identifier)
        logger.error(m, exc_info=x)
        raise FailedActivity(m)
    finally:
        if session:
            logger.debug("Detaching from process '{}'".format(proc_identifier))
            session.detach()


def attach_to_process(proc_identifier: Union[int, str, Dict[str, Any]],
                      script_path: str = None,
                      on_message: FridaOnMessage = None):
    pid = get_proc_pid(proc_identifier)
            
    logger.debug("Attaching to process '{}'".format(proc_identifier))
    session = frida.attach(pid)
    if script_path:
        load_script(session, script_path, on_message)
    
    return session


def load_script(session, script_path: str, on_message: FridaOnMessage = None):
    """
    Load a script into the process session.
    """
    path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), script_path))
        
    with open(path) as f:
        logger.debug("Loading script '{}'".format(path))
        script = session.create_script(f.read())
        if on_message:
            script.on("message", partial(on_message, script=script))
        script.load()


@singledispatch
def get_proc_pid(identifier: Any) -> int:
    pass


@get_proc_pid.register(int)
def _(identifier: int) -> int:
    logger.debug("Using process with PID: {}".format(identifier))
    return identifier


@get_proc_pid.register(str)
def _(identifier: str) -> int:
    """
    Lookup a process by its name and return the first one matching the given
    pattern.
    """
    rg = re.compile(identifier)

    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if rg.search(proc.info['name']):
            logger.debug("Using process with PID: {}".format(proc.pid))
            return proc.pid
    
    raise FailedActivity(
        "Could not find a process matching pattern '{}'".format(identifier))


@get_proc_pid.register(dict)
def _(identifier: Dict[str, Any]) -> int:
    match_name = identifier.get("name")
    match_username = identifier.get("username")
    match_uid = identifier.get("uid")
    match_gid = identifier.get("gid")
    match_cmd_args = identifier.get("args", [])
    match_cwd = identifier.get("cwd")
    created_in_the_last = identifier.get('created_in_the_last')

    now = time.time()
    attrs = ['pid', 'cwd', 'cmdline', 'username', 'uids', 'gids']
    for proc in psutil.process_iter(attrs):
        matches = []

        if match_name:
            matches.append(match_name == proc.name())

        if match_username:
            matches.append(match_username == proc.info['username'])

        if match_uid:
            matches.append(match_uid in proc.uids())

        if match_gid:
            matches.append(match_gid in proc.gids())
    
        if match_name and created_in_the_last is not None:
            if match_name in proc.name():
                alive_for = now - proc.create_time()
                matches.append(0 <= alive_for <= created_in_the_last)

        if match_cmd_args:
            cmdline = proc.cmdline()
            for match_arg in match_cmd_args:
                if match_arg not in cmdline:
                    matches.append(False)
                    break

        if all(matches):
            logger.debug("Using process with PID: {}".format(proc.pid))
            return proc.pid

    raise FailedActivity(
        "Could not find a process matching '{}'".format(identifier))
