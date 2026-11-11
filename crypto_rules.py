"""Detection rules.

Each rule is a regular expression applied line by line. Rules are grouped into
two categories:

* ``quantum``   - algorithms a large quantum computer is expected to break or
                  weaken (Shor's / Grover's algorithms).
* ``classical`` - cryptographic hygiene problems that are weak today, with no
                  quantum computer required.
* ``pqc``       - references to post-quantum algorithms (informational).

Patterns are heuristics. They can produce false positives and false negatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

NIST_NOTE = (
    "NIST finalized the first post-quantum standards in August 2024: "
    "FIPS 203 (ML-KEM, key establishment), FIPS 204 (ML-DSA, signatures) and "
    "FIPS 205 (SLH-DSA, hash-based signatures)."
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    category: str
    pattern: "re.Pattern[str]"
    why: str
    fix: str


def _rule(rule_id, title, severity, category, pattern, why, fix):
    return Rule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        pattern=re.compile(pattern, re.IGNORECASE),
        why=why,
        fix=fix,
    )


RULES = [
    _rule(
        "QS001",
        "RSA usage",
        "high",
        "quantum",
        r"rsa\.generate_private_key|\bRSA\.(generate|importKey|import_key)\b"
        r"|generateKeyPair(Sync)?\(\s*['\"]rsa|getInstance\(\s*['\"]RSA"
        r"|rsa\.GenerateKey|\bgenrsa\b|-newkey\s+rsa|RSA_generate_key",
        "RSA relies on integer factoring, which Shor's algorithm solves on a "
        "large quantum computer. Data encrypted today can be stored and "
        "decrypted later (harvest now, decrypt later).",
        "Plan migration to ML-KEM (FIPS 203) for key establishment and "
        "ML-DSA (FIPS 204) for signatures. Use a hybrid (classical + "
        "post-quantum) approach during transition. " + NIST_NOTE,
    ),
    _rule(
        "QS002",
        "Elliptic-curve cryptography (ECC, ECDSA, ECDH, Ed25519, X25519)",
        "high",
        "quantum",
        r"ec\.generate_private_key|ec\.SECP\d+R1|ECDSA|ECDH"
        r"|\bsecp(256|384|521)[rk]1\b|prime256v1|\bP-(256|384|521)\b"
        r"|Ed25519|X25519|Ed448|\bX448\b|elliptic\.P(256|384|521)"
        r"|generateKeyPair(Sync)?\(\s*['\"](ec|ed25519|x25519|ed448|x448)",
        "Elliptic-curve discrete logarithms are solved by Shor's algorithm. "
        "This includes Ed25519 and X25519.",
        "Migrate key exchange to ML-KEM (FIPS 203) and signatures to ML-DSA "
        "(FIPS 204) or SLH-DSA (FIPS 205). Hybrid schemes such as X25519 + "
        "ML-KEM are a common transition step.",
    ),
    _rule(
        "QS003",
        "Diffie-Hellman key exchange",
        "high",
        "quantum",
        r"dh\.generate_parameters|createDiffieHellman|DiffieHellman"
        r"|\bDHE?-|getInstance\(\s*['\"]DH['\"]|ssl_dhparam|\bdhparam\b",
        "Finite-field Diffie-Hellman depends on the discrete logarithm "
        "problem, which Shor's algorithm breaks.",
        "Replace with ML-KEM (FIPS 203), ideally in a hybrid construction.",
    ),
    _rule(
        "QS004",
        "DSA signatures",
        "high",
        "quantum",
        r"\bdsa\.generate_private_key|\bDSA\.generate\b"
        r"|getInstance\(\s*['\"]DSA['\"]",
        "DSA depends on the discrete logarithm problem (Shor's algorithm). "
        "DSA is also deprecated for new signatures in current NIST guidance.",
        "Use ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).",
    ),
    _rule(
        "QS005",
        "JWT/token signing with RSA, ECDSA or EdDSA",
        "medium",
        "quantum",
        r"['\"](RS|PS|ES)(256|384|512)['\"]|['\"]EdDSA['\"]",
        "These token-signing algorithms use RSA or elliptic curves, which are "
        "not quantum-safe. Short-lived tokens are lower risk than long-lived "
        "signatures.",
        "Track post-quantum signature support in your JWT/JOSE libraries and "
        "plan algorithm agility so the algorithm can be swapped by config.",
    ),
    _rule(
        "QS006",
        "ssh-rsa / ssh-dss key",
        "medium",
        "quantum",
        r"ssh-rsa\s+AAAA|ssh-dss\s+AAAA",
        "SSH keys based on RSA or DSA are not quantum-safe, and ssh-rsa "
        "(SHA-1) signatures are deprecated in OpenSSH.",
        "Rotate to a modern key type now and follow OpenSSH post-quantum "
        "key-exchange support for the longer term.",
    ),
    _rule(
        "QS007",
        "AES-128 (reduced margin against Grover's algorithm)",
        "low",
        "quantum",
        r"AES[-_]?128|aes128",
        "Grover's algorithm roughly halves symmetric key strength. NIST still "
        "treats AES-128 as acceptable, but AES-256 gives a larger margin for "
        "data that must stay secret for many years.",
        "Prefer AES-256 for long-lived sensitive data.",
    ),
    _rule(
        "QS008",
        "MD5 or SHA-1 hash",
        "medium",
        "classical",
        r"hashlib\.(md5|sha1)\b|createHash\(\s*['\"](md5|sha1)['\"]"
        r"|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)['\"]"
        r"|\bmd5\(|\bsha1\(|Digest::(MD5|SHA1)|crypto/(md5|sha1)",
        "MD5 and SHA-1 have practical collision attacks today. This is a "
        "classical weakness, not a quantum one.",
        "Use SHA-256 or SHA-3. For password storage use Argon2, scrypt or "
        "bcrypt.",
    ),
    _rule(
        "QS009",
        "Small key size (512, 768 or 1024 bits)",
        "high",
        "classical",
        r"(key_?size|keysize|key_?length|modulus_?length|rsa_keygen_bits)"
        r"\s*[=:(]\s*['\"]?(512|768|1024)\b|rsa:(512|768|1024)\b",
        "Keys of this size are considered breakable with classical computers.",
        "Use at least 3072-bit RSA or a modern curve today, and plan the "
        "post-quantum migration.",
    ),
    _rule(
        "QS010",
        "Legacy SSL/TLS protocol version",
        "medium",
        "classical",
        r"SSLv2|SSLv3|TLSv?1\.[01]\b|PROTOCOL_TLSv1(_1)?\b|\bTLSv1(_1)?_method|\bTLS[-_]1[-_][01]\b",
        "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 are deprecated and have known "
        "weaknesses.",
        "Require TLS 1.2 or TLS 1.3 only.",
    ),
    _rule(
        "QS011",
        "Private key embedded in source",
        "critical",
        "classical",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "A private key is stored in the repository. Anyone with read access "
        "can impersonate the key owner.",
        "Remove the key from the repository and its git history, revoke and "
        "rotate it, and load keys from a secrets manager or environment.",
    ),
    _rule(
        "QS100",
        "Post-quantum algorithm referenced",
        "info",
        "pqc",
        r"ML-?KEM|ML-?DSA|SLH-?DSA|\bkyber\d*\b|\bdilithium\d*\b"
        r"|\bsphincs\+?|liboqs|\boqs\b",
        "Informational: the code references a post-quantum algorithm or "
        "library. Review that it is used correctly and in a hybrid setup "
        "where appropriate.",
        "No action required from this finding.",
    ),
]

RULES_BY_ID = {r.rule_id: r for r in RULES}
