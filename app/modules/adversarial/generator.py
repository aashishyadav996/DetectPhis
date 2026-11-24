"""
Adversarial URL Mutation Generator.
Generates realistic deceptive variations of a given target URL
using known phishing attack vectors: homoglyphs, typosquatting,
subdomain nesting, destination masking, and keyword stuffing.
"""
from urllib.parse import urlparse, urlunparse
import tldextract

from app.modules.adversarial.models import MutationTechnique

_extractor = tldextract.TLDExtract(suffix_list_urls=())

# Common homoglyph visual substitutions
CHAR_HOMOGLYPHS: dict[str, list[str]] = {
    "l": ["1", "i", "|"],
    "o": ["0", "q"],
    "e": ["3", "€"],
    "a": ["4", "@"],
    "s": ["5", "$"],
    "i": ["1", "l"],
    "m": ["rn"],
    "w": ["vv"],
    "t": ["7", "+"],
}

ABUSED_TLDS = ["xyz", "top", "click", "site", "online", "live"]
KEYWORD_CHAINS = [
    "secure-account-verification",
    "login-auth-update",
    "portal-security-check",
    "billing-confirm-notice",
]


def generate_mutations(url: str) -> list[dict[str, str]]:
    """
    Generates a suite of mutated URL candidates representing distinct evasion techniques.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    parsed = urlparse(url)
    ext = _extractor.extract_str(url)

    sld = ext.domain or "target"
    suffix = ext.suffix or "com"
    path = parsed.path if parsed.path and parsed.path != "/" else "/auth/login"
    query = f"?{parsed.query}" if parsed.query else ""

    mutations: list[dict[str, str]] = []

    # 1. Homoglyph Substitution
    homoglyph_sld = None
    technique_desc = ""
    for ch, replacements in CHAR_HOMOGLYPHS.items():
        if ch in sld:
            rep = replacements[0]
            homoglyph_sld = sld.replace(ch, rep, 1)
            technique_desc = f"Substituted visual lookalike '{rep}' for character '{ch}' in domain label"
            break

    if not homoglyph_sld:
        homoglyph_sld = f"{sld}1"
        technique_desc = "Appended visual numeral '1' imitating letter 'l'"

    homoglyph_host = f"{homoglyph_sld}.{suffix}"
    mutations.append({
        "technique": MutationTechnique.HOMOGLYPH_SUBSTITUTION.value,
        "mutated_url": f"https://{homoglyph_host}{path}{query}",
        "description": technique_desc,
    })

    # 2. Typosquatting (Character Omission)
    if len(sld) > 3:
        omission_idx = len(sld) // 2
        omission_sld = sld[:omission_idx] + sld[omission_idx + 1:]
        mutations.append({
            "technique": MutationTechnique.TYPOSQUATTING_OMISSION.value,
            "mutated_url": f"https://{omission_sld}.{suffix}{path}{query}",
            "description": f"Omitted character '{sld[omission_idx]}' at position {omission_idx + 1} to exploit typo entry",
        })

    # 3. Typosquatting (Character Duplication)
    if len(sld) >= 3:
        dup_ch = sld[-2] if len(sld) > 2 else sld[0]
        dup_sld = sld.replace(dup_ch, dup_ch + dup_ch, 1)
        mutations.append({
            "technique": MutationTechnique.TYPOSQUATTING_REPETITION.value,
            "mutated_url": f"https://{dup_sld}.{suffix}{path}{query}",
            "description": f"Duplicated keystroke character '{dup_ch}' within domain label",
        })

    # 4. Typosquatting (Adjacent Character Transposition)
    if len(sld) >= 4:
        pos = len(sld) - 3
        transposed_sld = sld[:pos] + sld[pos + 1] + sld[pos] + sld[pos + 2:]
        mutations.append({
            "technique": MutationTechnique.TYPOSQUATTING_TRANSPOSITION.value,
            "mutated_url": f"https://{transposed_sld}.{suffix}{path}{query}",
            "description": f"Transposed adjacent letters '{sld[pos]}' and '{sld[pos + 1]}'",
        })

    # 5. Subdomain Nesting & Brand Masquerading
    brand_label = f"{sld}.{suffix}"
    nested_host = f"{brand_label}.account-security-alert.org"
    mutations.append({
        "technique": MutationTechnique.SUBDOMAIN_NESTING.value,
        "mutated_url": f"https://{nested_host}{path}{query}",
        "description": f"Nested target brand '{brand_label}' as a subdomain under an attacker-controlled apex domain",
    })

    # 6. Userinfo Destination Masking ('@' sign)
    attacker_destination = "verify-identity-harvest.net"
    masked_url = f"https://{sld}.{suffix}:secure@{attacker_destination}{path}{query}"
    mutations.append({
        "technique": MutationTechnique.AT_SIGN_DESTINATION_MASK.value,
        "mutated_url": masked_url,
        "description": "Used browser userinfo '@' symbol so URL appears to point to target brand while browser visits attacker host",
    })

    # 7. Authentication Keyword Hyphenation Padding
    padded_host = f"{sld}-{KEYWORD_CHAINS[0]}.{suffix}"
    mutations.append({
        "technique": MutationTechnique.AUTH_KEYWORD_PADDING.value,
        "mutated_url": f"https://{padded_host}{path}{query}",
        "description": "Appended deceptive security keywords ('secure-account-verification') using hyphenation",
    })

    # 8. Alternative TLD Substitution
    alt_tld = ABUSED_TLDS[0] if suffix != ABUSED_TLDS[0] else ABUSED_TLDS[1]
    alt_tld_host = f"{sld}.{alt_tld}"
    mutations.append({
        "technique": MutationTechnique.TLD_SWAP.value,
        "mutated_url": f"https://{alt_tld_host}{path}{query}",
        "description": f"Replaced legitimate top-level domain '.{suffix}' with disposable low-cost TLD '.{alt_tld}'",
    })

    return mutations
