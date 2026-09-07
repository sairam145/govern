"""Interception.

The point of this module: the agent should not be able to reach the
resource *except* through govern. Voluntary self-reporting (an agent
choosing to call audit()) is a logging convention, not a control. So
govern wraps the client, the function, or the subprocess call instead.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from typing import Any, Callable, Optional, Sequence

from .decision import Decision, PolicyViolation
from .engine import Governor

# kwarg names that usually identify the thing being acted on
RESOURCE_KEYS = (
    "Bucket", "BucketName", "Key", "TableName", "FunctionName", "InstanceId",
    "InstanceIds", "ClusterName", "DBInstanceIdentifier", "QueueUrl", "TopicArn",
    "RoleName", "PolicyArn", "GroupName", "UserName", "StackName", "Arn",
    "name", "Name", "namespace", "path", "resource", "url", "id",
)

_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def to_operation(method_name: str) -> str:
    """delete_bucket -> DeleteBucket ; deleteBucket -> DeleteBucket"""
    if "_" in method_name:
        return "".join(part.capitalize() for part in method_name.split("_") if part)
    return method_name[:1].upper() + method_name[1:]


def default_resolver(args: Sequence[Any], kwargs: dict) -> str:
    for key in RESOURCE_KEYS:
        if key in kwargs and kwargs[key] is not None:
            value = kwargs[key]
            if isinstance(value, (list, tuple)):
                return ",".join(str(v) for v in value)
            return str(value)
    for arg in args:
        if isinstance(arg, str):
            return arg
    return "*"


class GuardedClient:
    """A transparent proxy that policy-checks every method call.

    >>> s3 = govern.guard(boto3.client("s3"), service="s3")
    >>> s3.delete_bucket(Bucket="prod-billing")   # raises PolicyViolation
    """

    def __init__(
        self,
        target: Any,
        governor: Governor,
        service: str,
        resolver: Optional[Callable[[Sequence[Any], dict], str]] = None,
        raise_on_deny: bool = True,
    ):
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_governor", governor)
        object.__setattr__(self, "_service", service)
        object.__setattr__(self, "_resolver", resolver or default_resolver)
        object.__setattr__(self, "_raise_on_deny", raise_on_deny)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(object.__getattribute__(self, "_target"), name)
        if not callable(attr) or name.startswith("_"):
            return attr

        governor = object.__getattribute__(self, "_governor")
        service = object.__getattribute__(self, "_service")
        resolver = object.__getattribute__(self, "_resolver")
        raise_on_deny = object.__getattribute__(self, "_raise_on_deny")

        def wrapper(*args, **kwargs):
            action = f"{service}:{to_operation(name)}"
            resource = resolver(args, kwargs)
            decision = governor.evaluate(action, resource, metadata={"call": name})
            if not decision.allowed:
                if raise_on_deny:
                    raise PolicyViolation(decision)
                return decision
            return attr(*args, **kwargs)

        wrapper.__name__ = name
        return wrapper

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_target"), name, value)

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        service = object.__getattribute__(self, "_service")
        return f"<GuardedClient service={service!r} wrapping {target!r}>"


def guard(
    target: Any,
    service: str,
    governor: Optional[Governor] = None,
    resolver: Optional[Callable[[Sequence[Any], dict], str]] = None,
    raise_on_deny: bool = True,
) -> GuardedClient:
    from . import _active_governor

    return GuardedClient(
        target=target,
        governor=governor or _active_governor(),
        service=service,
        resolver=resolver,
        raise_on_deny=raise_on_deny,
    )


def guarded(
    action: str,
    resource: Any = "*",
    governor: Optional[Governor] = None,
) -> Callable:
    """Decorator for tools an agent can call.

    `resource` may be a literal or a callable taking (args, kwargs).

    >>> @govern.guarded("db:DropTable")
    ... def drop_table(name): ...
    """

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            from . import _active_governor

            gov = governor or _active_governor()
            target = resource(args, kwargs) if callable(resource) else resource
            gov.enforce(action, str(target), metadata={"function": fn.__name__})
            return fn(*args, **kwargs)

        wrapper.__name__ = getattr(fn, "__name__", "guarded")
        wrapper.__doc__ = fn.__doc__
        return wrapper

    return decorator


def run(
    command: str | Sequence[str],
    governor: Optional[Governor] = None,
    **subprocess_kwargs: Any,
) -> subprocess.CompletedProcess:
    """A policy-checked replacement for subprocess.run."""
    from . import _active_governor

    gov = governor or _active_governor()
    rendered = command if isinstance(command, str) else shlex.join(command)
    gov.enforce("shell:exec", rendered, metadata={"kind": "subprocess"})
    if isinstance(command, str):
        subprocess_kwargs.setdefault("shell", True)
    return subprocess.run(command, **subprocess_kwargs)
