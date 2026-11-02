import mobiusguard


def test_package_imports_and_has_a_version() -> None:
    assert mobiusguard.__version__


def test_the_three_packages_are_released_together() -> None:
    """One version for all three, and each depends on the others' same minor version."""
    import importlib.metadata as md

    import mobiusguard_eval
    import mobiusguard_redact

    versions = {
        mobiusguard.__version__,
        mobiusguard_redact.__version__,
        mobiusguard_eval.__version__,
    }
    assert len(versions) == 1
    (v,) = versions
    major, minor, *_ = v.split(".")
    pin = f">={v},<{major}.{int(minor) + 1}"
    for dist, deps in (("mobiusguard", ["mobiusguard-redact"]),
                       ("mobiusguard-eval", ["mobiusguard", "mobiusguard-redact"])):  # fmt: skip
        reqs = {r.split(";")[0].replace(" ", "") for r in md.requires(dist) or []}
        for dep in deps:
            want = {f"{dep}{pin}", f"{dep}<{major}.{int(minor) + 1},>={v}"}
            assert reqs & want, (dist, dep, sorted(reqs))
