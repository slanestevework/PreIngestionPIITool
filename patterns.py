import re

# --- Column name hints ---
PII_NAME_HINTS = [
    "name",
    "email",
    "phone",
    "ssn",
    "dob",
    "birth",
    "address",
    "zip",
    "postal",
    "account",
    "card",
    "customer",
    "employee",
    "user",
    "ip",

    # New
    "passport",
    "license",
    "driver",
    "tax",
    "tin",
    "ein",
    "routing",
    "bank",
    "iban"
]

HIGH_RISK_PATTERNS = [
    "ssn",
    "credit_card",
    "bank_account",
    "passport"
]



COLUMN_PATTERN_MAP = {

    "email": ["email"],

    "phone": ["phone",
              "mobile"],

    "ssn": ["ssn",
            "social"],

    "zip": ["zip",
            "postal"],

    "credit_card": [
        "card",
        "credit"
    ],

    "ip": ["ip"],

    "dob": [
        "dob",
        "birth"
    ],

    "driver_license": [
        "driver",
        "license",
        "dl"
    ],

    "passport": [
        "passport"
    ],

    "routing_number": [
        "routing"
    ],

    "bank_account": [
        "account",
        "bank"
    ],

    "ein": [
        "ein",
        "tax"
    ]
}
# --- Regex patterns ---
PII_REGEXES = {
    "email": re.compile(
        r"(?i)^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"
    ),
    "ip": re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
    ),
    "phone": re.compile(
    r"^(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}$"
    ),
    "ssn": re.compile(
        r"^\d{3}-?\d{2}-?\d{4}$"
    ),
    "credit_card": re.compile(
        r"^(?:\d[ -]*?){13,19}$"
    ),
    "zip": re.compile(
        r"^\d{5}(-\d{4})?$"
    ),
    "dob": re.compile(
        r"^(0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])[/-]\d{4}$"
    ),
    "driver_license": re.compile(
        r"^[A-Z0-9]{6,12}$"
    ),
    "passport": re.compile(
        r"^[A-Z0-9]{8,9}$"
    ),
    "routing_number": re.compile(
        r"^\d{9}$"
    ),
    "bank_account": re.compile(
        r"^\d{8,17}$"
    ),
    "ein": re.compile(
        r"^\d{2}-\d{7}$"
    ),

}