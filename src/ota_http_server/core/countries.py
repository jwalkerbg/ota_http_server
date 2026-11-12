"""ISO 3166-1 country code validation."""

import pycountry


def normalize_country(value: str) -> str:
    """Return an alpha-2 code, accepting either alpha-2 or alpha-3 input."""
    code = value.strip().upper()
    if not code:
        return ""
    country = None
    if len(code) == 2 and code.isascii() and code.isalpha():
        country = pycountry.countries.get(alpha_2=code)
    elif len(code) == 3 and code.isascii() and code.isalpha():
        country = pycountry.countries.get(alpha_3=code)
    if country is None:
        raise ValueError("Country must be a valid ISO 3166-1 alpha-2 or alpha-3 code")
    return str(country.alpha_2)
