"""Permission mapping — declarative, (method, path pattern) → required permission.

The path pattern is a Python regex matched against the request path. Named groups
are allowed but ignored by the matcher (service-level fine-grained logic can
extract them separately).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionRule:
    """One mapping entry: method + path pattern → required permission string."""

    method: str
    path_pattern: re.Pattern[str]
    permission: str

    @classmethod
    def make(cls, method: str, pattern: str, permission: str) -> PermissionRule:
        return cls(method.upper(), re.compile(pattern), permission)


class PermissionMap:
    """Ordered list of PermissionRules. First match wins.

    Accepts either PermissionRule objects or 3-tuples (method, pattern, permission)
    for ergonomic construction from a service's main.py.
    """

    def __init__(
        self,
        rules: Iterable[PermissionRule | tuple[str, str, str]] | None = None,
    ):
        self._rules: list[PermissionRule] = []
        if rules:
            for rule in rules:
                self.add(rule)

    def add(self, rule: PermissionRule | tuple[str, str, str]) -> None:
        if isinstance(rule, PermissionRule):
            self._rules.append(rule)
        elif isinstance(rule, tuple) and len(rule) == 3:
            self._rules.append(PermissionRule.make(*rule))
        else:
            raise TypeError(
                f"expected PermissionRule or (method, pattern, permission); got {rule!r}"
            )

    def resolve(self, method: str, path: str) -> str | None:
        """Return the permission required for (method, path), or None if the
        route is unmapped (the middleware will deny by default)."""
        method_u = method.upper()
        for rule in self._rules:
            if rule.method == method_u and rule.path_pattern.match(path):
                return rule.permission
        return None

    def __len__(self) -> int:
        return len(self._rules)
