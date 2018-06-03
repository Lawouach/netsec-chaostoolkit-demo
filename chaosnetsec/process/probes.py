# -*- coding: utf-8 -*-
import re
from typing import List

import psutil

__all__ = ["list_pids_by_process_name"]


def list_pids_by_process_name(process_name: str, status: str = None,
                              uid: int = None, gid: int = None) -> List[int]:
    procs = []
    rg = re.compile(process_name)
    piter = psutil.process_iter(attrs=[
        'pid', 'name', 'status', 'username', 'cmdline', 'exe', 'create_time',
        'uids', 'gids', 'cwd'])

    for proc in piter:
        if rg.match(proc.info['name']):
            if uid and uid not in proc.uids():
                continue
            if gid and gid not in proc.gids():
                continue
            if status and proc.info['status'] != status:
                continue
            procs.append(dict(proc.info))

    return procs


if __name__ == '__main__':
    print(list_pids_by_process_name('c[a-z]t', uid=1000))