"""PermissionMap behaviour tests."""
from ds_auth.permissions import PermissionMap, PermissionRule


def test_tuple_shorthand_constructs_rules():
    pm = PermissionMap([
        ("GET", r"^/items/?$", "catalog:read"),
        ("POST", r"^/items/?$", "catalog:create"),
    ])
    assert len(pm) == 2


def test_resolve_matches_method_and_pattern():
    pm = PermissionMap([
        ("GET", r"^/items/?$", "catalog:read"),
        ("POST", r"^/items/?$", "catalog:create"),
        ("DELETE", r"^/items/[^/]+$", "catalog:delete"),
    ])
    assert pm.resolve("GET", "/items") == "catalog:read"
    assert pm.resolve("GET", "/items/") == "catalog:read"
    assert pm.resolve("POST", "/items") == "catalog:create"
    assert pm.resolve("DELETE", "/items/abc-123") == "catalog:delete"


def test_resolve_returns_none_for_unmapped():
    pm = PermissionMap([
        ("GET", r"^/items/?$", "catalog:read"),
    ])
    assert pm.resolve("POST", "/items") is None
    assert pm.resolve("GET", "/other") is None


def test_method_case_insensitive():
    pm = PermissionMap([("get", r"^/items$", "catalog:read")])
    assert pm.resolve("GET", "/items") == "catalog:read"
    assert pm.resolve("get", "/items") == "catalog:read"


def test_first_match_wins():
    pm = PermissionMap([
        ("GET", r"^/items/.*$", "catalog:read-wide"),
        ("GET", r"^/items/special$", "catalog:read-special"),
    ])
    # The wide rule is listed first, so it matches first
    assert pm.resolve("GET", "/items/special") == "catalog:read-wide"


def test_add_accepts_rule_object():
    pm = PermissionMap()
    pm.add(PermissionRule.make("GET", r"^/x$", "x:read"))
    assert pm.resolve("GET", "/x") == "x:read"


def test_add_rejects_unknown_shape():
    pm = PermissionMap()
    try:
        pm.add("not a rule")  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
