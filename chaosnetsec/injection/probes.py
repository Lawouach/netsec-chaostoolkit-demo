# -*- coding: utf-8 -*-
from typing import List, Union

import frida
from logzero import logger

from chaosnetsec.injection import attach_to_process

__all__ = ["get_func_address"]


def get_func_address(proc_identifier: Union[str, int, Dict[str, Any]],
                     func_name: str, module_name: str) -> str:
    """
    Lookup the address of the provided function name from the given module.

    The name must be an exact match to reduce false positives.
    """
    with attach_to_process(proc_identifier) as session:
        modules = session.enumerate_modules()
        for module in modules:
            if module_name not in module.name:
                continue
            exported_funcs = module.enumerate_exports()
        
            for exported_func in exported_funcs:
                if exported_func.name == func_name:
                    return hex(exported_func.absolute_address)
