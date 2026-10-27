import os

from hypothesis import HealthCheck, settings

# `HYPOTHESIS_PROFILE=stress make test` runs the property tests much harder.
settings.register_profile(
    "default", max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.register_profile(
    "stress", max_examples=5000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
