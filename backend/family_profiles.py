"""Plain-language profiles for malware families, shown next to an attribution.

The profile says what a family is in general. It is not evidence about the sample.
Evidence about the sample comes from the attribution's own reasoning, and the report
shows the two separately. Families without a profile here get an explicit
"no profile" note, never an invented description.
"""

from typing import Any, Dict, List, Optional

FAMILY_PROFILES: Dict[str, Dict[str, Any]] = {
    "SpyNote": {
        "what": (
            "A commercial Android remote-access trojan (RAT) sold as a service. Once installed "
            "it can give an operator live control of the phone."
        ),
        "typical_behaviour": [
            "Camera and microphone capture",
            "Reading contacts, call logs and SMS",
            "Drawing overlays over other apps",
            "Keeping itself alive with a foreground service",
        ],
    },
    "Opfake": {
        "what": (
            "Fake versions of popular apps used to push fraud and trojan payloads. Victims "
            "usually get them from outside the official store."
        ),
        "typical_behaviour": [
            "Repackaged legitimate apps with an added payload",
            "Premium SMS or subscription fraud",
            "Downloading further code from a remote server",
        ],
    },
    "FakeInst": {
        "what": (
            "A family that repackages popular apps and adds a fake installer routine. Its main "
            "goal is to send premium-rate SMS without the user noticing."
        ),
        "typical_behaviour": [
            "Sending premium-rate SMS",
            "Hiding SMS and notifications from the user",
            "Repackaging legitimate apps",
        ],
    },
    "BankBot": {
        "what": (
            "A banking trojan. It shows fake login screens over real banking apps to steal "
            "credentials and take control of the device."
        ),
        "typical_behaviour": [
            "Overlay attacks on banking apps",
            "Intercepting SMS, including two-factor codes",
            "Abusing accessibility services",
        ],
    },
    "Geinimi": {
        "what": (
            "An early Android trojan first seen in 2010. It was built to steal data and receive "
            "remote commands from a server."
        ),
        "typical_behaviour": [
            "Collecting device and contact data",
            "Receiving commands from a remote server",
        ],
    },
    "KungFu": {
        "what": (
            "A family of SMS-fraud malware. It hides in other apps and sends or intercepts "
            "text messages to make money or steal codes."
        ),
        "typical_behaviour": [
            "Sending SMS to premium numbers",
            "Intercepting incoming SMS",
        ],
    },
    "Dowgin": {
        "what": (
            "Adware built around an advertising SDK. It pushes ads and can add shortcuts and "
            "background activity that the user did not ask for."
        ),
        "typical_behaviour": [
            "Showing unwanted ads",
            "Creating home-screen shortcuts",
            "Background network requests to ad servers",
        ],
    },
}


def describe_family(name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the curated profile for a family name, or None when none is written."""
    if not name:
        return None
    return FAMILY_PROFILES.get(name)


def evidence_lines(reasoning: Optional[str]) -> List[str]:
    """Split an attribution's reasoning into one evidence item per line.

    Knowledge-base reasoning is ';'-separated tokens. Other methods write a sentence,
    which comes back as a single item.
    """
    if not reasoning:
        return []
    text = str(reasoning)
    if text.startswith("KB score") and ":" in text:
        # Drop the "KB score N from M discriminating tokens:" preamble.
        text = text.split(":", 1)[1]
    parts = [p.strip() for p in text.split(";")]
    return [p for p in parts if p]
