from functools import wraps
from typing import AnyStr, Callable, Optional, Sequence, Union

from django.http.request import HttpRequest
from ratelimit import ALL
from ratelimit.core import get_usage
from ratelimit.exceptions import Ratelimited

Group = str
KeyCallable = Callable[[Group, HttpRequest], AnyStr]
Key = Union[str, KeyCallable]
RateCallable = Callable[[Group, HttpRequest], tuple[int, int]]
Rate = Union[str, RateCallable]
Method = Union[tuple[None], Sequence[str]]


def custom_ratelimit(
        group: Optional[Group] = None,
        key: Optional[Key] = None,
        rate: Optional[Rate] = None,
        method: Method = ALL,
        block: bool = True
    ):
    def decorator(fn):
        @wraps(fn)
        def _wrapped(request, *args, **kw):
            old_limited = getattr(request, 'limited', False)
            ratelimit_info = get_usage(request=request, group=group, fn=fn,
                                       key=key, rate=rate, method=method,
                                       increment=True)
            ratelimited = ratelimit_info is not None and ratelimit_info['should_limit']
            request.limited = ratelimited or old_limited
            if ratelimited and block:
                raise Ratelimited(ratelimit_info) # Pass ratelimit_info (might PR this)
            return fn(request, *args, **kw)
        return _wrapped
    return decorator
