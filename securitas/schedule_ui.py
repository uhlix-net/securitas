"""A friendlier schedule picker on top of cron.

Schedules are still stored and run as five-field cron expressions (jobs.valid_cron / jobs.next_run). This module
turns the picker's fields (repeat, time, weekdays, day of month) into cron, reads a stored cron back into the picker
when it fits one of the simple shapes, and describes a schedule in plain words. Anything else is 'advanced': the
raw cron field.
"""
import datetime
import re
import zoneinfo

from croniter import croniter

FREQS = [("hourly", "Every hour"), ("daily", "Every day"), ("weekly", "Every week"), ("monthly", "Every month"),
         ("advanced", "Advanced (cron)")]
# cron weekday numbers, Monday first as people read a week
WEEKDAYS = [(1, "Mon", "Monday"), (2, "Tue", "Tuesday"), (3, "Wed", "Wednesday"), (4, "Thu", "Thursday"),
            (5, "Fri", "Friday"), (6, "Sat", "Saturday"), (0, "Sun", "Sunday")]
DAY_NAME = {n: full for n, _, full in WEEKDAYS}
MAX_MONTHDAY = 28        # every month has it, so a monthly schedule never skips a month


class ScheduleError(ValueError):
    pass


def _int(v, lo, hi, what):
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise ScheduleError("Pick the %s." % what) from None
    if not lo <= n <= hi:
        raise ScheduleError("The %s must be between %d and %d." % (what, lo, hi))
    return n


def to_cron(form):
    """form: a mapping with freq, hour, minute, weekday (list), monthday, cron. Returns the cron expression."""
    freq = str(form.get("freq", "")).strip()
    if freq == "advanced":
        cron = " ".join(str(form.get("cron", "")).split())
        if not (croniter.is_valid(cron) and len(cron.split()) == 5):
            raise ScheduleError("That is not a valid cron expression (5 fields: minute hour day month weekday).")
        return cron
    if freq not in ("hourly", "daily", "weekly", "monthly"):
        raise ScheduleError("Pick how often the scan runs.")
    minute = _int(form.get("minute"), 0, 59, "minute")
    if freq == "hourly":
        return "%d * * * *" % minute
    hour = _int(form.get("hour"), 0, 23, "hour")
    if freq == "daily":
        return "%d %d * * *" % (minute, hour)
    if freq == "weekly":
        days = sorted({_int(d, 0, 6, "weekday") for d in form.get("weekday") or []}, key=lambda d: (d == 0, d))
        if not days:
            raise ScheduleError("Tick at least one weekday.")
        return "%d %d * * %s" % (minute, hour, ",".join(str(d) for d in days))
    day = _int(form.get("monthday"), 1, MAX_MONTHDAY, "day of the month")
    return "%d %d %d * *" % (minute, hour, day)


_N = r"(\d{1,2})"


def from_cron(cron):
    """The picker's fields for a stored cron: {freq, hour, minute, weekdays, monthday, cron}. Shapes the picker
    cannot show come back as freq 'advanced' with the cron unchanged."""
    cron = " ".join((cron or "").split())
    out = {"freq": "advanced", "hour": 5, "minute": 0, "weekdays": [], "monthday": 1, "cron": cron}
    f = cron.split(" ")
    if len(f) != 5 or not re.fullmatch(_N, f[0]) or int(f[0]) > 59:
        return out
    m = int(f[0])
    if f[1:] == ["*", "*", "*", "*"]:
        return {**out, "freq": "hourly", "minute": m}
    if not re.fullmatch(_N, f[1]) or int(f[1]) > 23 or f[3] != "*":
        return out
    h = int(f[1])
    if f[2] == "*" and f[4] == "*":
        return {**out, "freq": "daily", "hour": h, "minute": m}
    if f[2] == "*" and re.fullmatch(r"[0-7](,[0-7])*", f[4]):
        days = sorted({int(d) % 7 for d in f[4].split(",")}, key=lambda d: (d == 0, d))
        return {**out, "freq": "weekly", "hour": h, "minute": m, "weekdays": days}
    if f[4] == "*" and re.fullmatch(_N, f[2]) and 1 <= int(f[2]) <= MAX_MONTHDAY:
        return {**out, "freq": "monthly", "hour": h, "minute": m, "monthday": int(f[2])}
    return out


def _ordinal(n):
    return "%d%s" % (n, "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th"))


def _join(words):
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def describe(cron, tz):
    """Plain words for a schedule: 'Every Monday and Thursday at 05:00 EST'."""
    p = from_cron(cron)
    try:
        abbr = datetime.datetime.now(zoneinfo.ZoneInfo(tz)).tzname() or tz
    except Exception:
        abbr = tz
    at = "%02d:%02d %s" % (p["hour"], p["minute"], abbr)
    if p["freq"] == "hourly":
        return "Every hour at :%02d" % p["minute"]
    if p["freq"] == "daily":
        return "Every day at " + at
    if p["freq"] == "weekly":
        days = p["weekdays"]
        if days == [1, 2, 3, 4, 5]:
            return "Every weekday (Monday to Friday) at " + at
        return "Every %s at %s" % (_join([DAY_NAME[d] for d in days]), at)
    if p["freq"] == "monthly":
        return "On the %s of every month at %s" % (_ordinal(p["monthday"]), at)
    return "Custom cron schedule (%s)" % tz


def next_runs(cron, tz, count=3, after=None):
    """The next `count` run times (timezone-aware, in tz)."""
    try:
        zone = zoneinfo.ZoneInfo(tz)
        it = croniter(cron, (after or datetime.datetime.now(datetime.timezone.utc)).astimezone(zone))
        return [it.get_next(datetime.datetime) for _ in range(count)]
    except Exception:
        return []
