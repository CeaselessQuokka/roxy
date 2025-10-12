import diagnostics
import time
from config import *
from threading import Thread

throttled_ips = dict(
    {
        # [IP]: {Requests: int, Throttled: bool, ThrottleResetTime: float, LastRequestTime: float},
    }
)


def is_throttled(ip: str) -> bool:
    global throttled_ips
    throttled_ip = throttled_ips.get(ip, None)
    return throttled_ip and throttled_ip["Throttled"]


def get_requests_left(ip: str) -> int:
    global throttled_ips
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        return max(0, ALLOWED_REQUESTS_PER_MINUTE - throttled_ip["Requests"])
    return ALLOWED_REQUESTS_PER_MINUTE


def get_throttle_reset_time_left(ip: str) -> int:
    global throttled_ips
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        return int(max(0, throttled_ip["ThrottleResetTime"] - time.time()))
    return 0


def reset_throttle(ip: str):
    global throttled_ips
    if ip in throttled_ips:
        throttled_ips[ip]["Throttled"] = False
        throttled_ips[ip]["Requests"] = 0
        throttled_ips[ip]["ThrottleResetTime"] = time.time() + THROTTLE_RESET_DURATION


def update_throttling(ip, made_request: bool = False):
    global throttled_ips
    now = time.time()
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        if throttled_ip["Throttled"]:
            return
        if now > throttled_ip["LastRequestTime"] + STALE_IP_DURATION:
            throttled_ips.pop(ip, None)
            return

        if now > throttled_ip["ThrottleResetTime"]:
            throttled_ip["Throttled"] = False
            throttled_ip["Requests"] = 0
            throttled_ip["ThrottleResetTime"] = now + THROTTLE_RESET_DURATION
        if made_request:
            throttled_ip["Requests"] += 1
            throttled_ip["ThrottleResetTime"] += 0.5
            throttled_ip["LastRequestTime"] = now
        if throttled_ip["Requests"] > ALLOWED_REQUESTS_PER_MINUTE:
            throttled_ip["Throttled"] = True
            diagnostics.log_throttle(ip)
    else:
        throttled_ips[ip] = dict(
            Requests=1 if made_request else 0,
            Throttled=False,
            LastRequestTime=now,
            ThrottleResetTime=now + THROTTLE_RESET_DURATION,
        )


def run_throttle_loop():
    global throttled_ips
    while True:
        ips = list(throttled_ips.keys())
        for ip in ips:
            update_throttling(ip)
        time.sleep(1)


Thread(target=run_throttle_loop).start()
