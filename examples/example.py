import threading


def Parse(cls, raw, ts, shared_var=None):
    print("ThreadId:",
          threading.get_ident(), "Received:", len(raw), "bytes at Time:", ts)


def ParseConcurrent(cls, raw, ts, workerId, shared_var=None):
    print("WorkerId:", workerId, "ThreadId:",
          threading.get_ident(), "Received:", len(raw), "bytes at Time:", ts)
