"""重启本地后端（uvicorn）—— 专门对付「套接字继承」导致的端口占着不放。

背景：这个环境下 uvicorn 的监听套接字会被另一个进程继承。
表现出来就是——杀掉 TCP 表里记录的那个 PID 之后：
  · HTTP 依然在响应
  · bind 8000 依然报 WSAEADDRINUSE
  · 但 Get-Process 里已经找不到那个 PID 了
因为 TCP 表记的是【创建套接字】的进程，而句柄还活在继承它的进程手里。

所以这里的策略是：先杀端口记录的所有者，再按内存从大到小逐个杀 python 进程，
每杀一个就重新探一次端口，直到端口真的空出来。

用法：
    python _restart_backend.py          # 停掉当前后端（不起新的）
"""
import ctypes
import socket
import time
from ctypes import wintypes

import requests

AF_INET = 2
TCP_TABLE_OWNER_PID_LISTENER = 3
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


class ROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    ]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


def port_owners(port):
    iphlpapi = ctypes.windll.iphlpapi
    size = wintypes.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET,
                                 TCP_TABLE_OWNER_PID_LISTENER, 0)
    buf = ctypes.create_string_buffer(size.value)
    iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                                 TCP_TABLE_OWNER_PID_LISTENER, 0)
    n = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    rows = ctypes.cast(ctypes.byref(buf, 4), ctypes.POINTER(ROW))
    out = []
    for i in range(n):
        r = rows[i]
        p = ((r.dwLocalPort & 0xFF) << 8) | ((r.dwLocalPort >> 8) & 0xFF)
        if p == port:
            out.append(r.dwOwningPid)
    return sorted(set(out))


def port_is_free(port):
    """判断端口是否真的空闲。

    【不要】用 bind() 试 —— Windows 在没设 SO_EXCLUSIVEADDRUSE 时允许重叠绑定，
    实测过：后端明明在正常响应 HTTP，bind(("127.0.0.1", port)) 却能成功。
    所以这里看两个更硬的证据：TCP 监听表里还有没有记录，以及 HTTP 还有没有回应。
    """
    if port_owners(port):
        return False
    try:
        requests.get(f"http://127.0.0.1:{port}/api/health", timeout=2)
        return False          # 表里没记录但还能应答 —— 更说明有问题，绝不能当空闲
    except Exception:
        return True


def python_processes_by_memory():
    """按内存从大到小列出 python 进程。

    只用 32 位 API 会被截断，这里用 GetProcessMemoryInfo 拿工作集。
    内存是个很有效的区分器：裸 python 十几 MB，
    而跑着 uvicorn + fastapi + requests 的那个是 45–80 MB。
    """
    k32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    found = []
    if k32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("ascii", "replace").lower()
            if name in ("python.exe", "pythonw.exe", "uvicorn.exe"):
                pid = entry.th32ProcessID
                h = k32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                mem = 0
                if h:
                    counters = PROCESS_MEMORY_COUNTERS()
                    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                    if psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
                        mem = counters.WorkingSetSize
                    k32.CloseHandle(h)
                found.append((mem, pid, name))
            if not k32.Process32Next(snap, ctypes.byref(entry)):
                break
    k32.CloseHandle(snap)
    return sorted(found, reverse=True)


def kill(pid):
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h:
        return False
    ok = k32.TerminateProcess(h, 0)
    k32.CloseHandle(h)
    return bool(ok)


def main(port=8000):
    if port_is_free(port):
        print(f"端口 {port} 已经是空的，无需处理")
        return

    owners = port_owners(port)
    print(f"端口 {port} 的 TCP 表记录者: {owners}")
    for pid in owners:
        print(f"  杀 {pid} -> {kill(pid)}")
    time.sleep(1.5)

    if port_is_free(port):
        print(f"端口 {port} 已释放")
        return

    print("仍被占用 —— 说明套接字被继承了，按内存从大到小排查 python 进程：")
    for mem, pid, name in python_processes_by_memory():
        if port_is_free(port):
            break
        if mem < 15 * 1024 * 1024:
            continue
        print(f"  试杀 {name} PID={pid} 内存={mem // 1024 // 1024}MB -> {kill(pid)}")
        time.sleep(1.2)

    print(f"最终：端口 {port} {'已释放' if port_is_free(port) else '仍被占用'}")


if __name__ == "__main__":
    main()
