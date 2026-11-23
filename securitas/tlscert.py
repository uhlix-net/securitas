"""Settings > Certificates: check a new TLS certificate and key before they replace the ingress Secret.

Accepts PEM (certificate, private key, optional chain) or a PKCS#12 / PFX file with its password, as a Windows CA
hands them out. The result is normalised to what an ingress TLS Secret holds: tls.crt = the server certificate
followed by its chain (PEM), tls.key = the unencrypted private key (PKCS#8 PEM). Nothing is stored by Securitas.
"""
import datetime
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_BYTES = 256 * 1024


class CertError(ValueError):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _pem_certs(data):
    try:
        return x509.load_pem_x509_certificates(data)
    except ValueError:
        try:
            return [x509.load_der_x509_certificate(data)]
        except ValueError:
            raise CertError("The certificate is not a PEM or DER certificate.") from None


def _key(data, password):
    try:
        return serialization.load_pem_private_key(data, password or None)
    except TypeError:
        raise CertError("The private key is encrypted: enter its password.") from None
    except ValueError:
        try:
            return serialization.load_der_private_key(data, password or None)
        except (TypeError, ValueError):
            raise CertError("The private key could not be read (wrong format or password).") from None


def _pub(k):
    return k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def load(cert=b"", key=b"", chain=b"", pfx=b"", password=""):
    """Returns (leaf, [chain certificates], private key) after checking that they belong together."""
    pw = password.encode() if password else None
    if pfx:
        try:
            k, leaf, extra = pkcs12.load_key_and_certificates(pfx, pw)
        except ValueError:
            raise CertError("The PFX / PKCS#12 file could not be opened: wrong password or not a PKCS#12 file.") from None
        if leaf is None or k is None:
            raise CertError("The PFX file must contain the certificate and its private key.")
        certs = [leaf] + list(extra or [])
    else:
        if not cert or not key:
            raise CertError("Give the certificate and the private key, or a PFX file.")
        certs = _pem_certs(cert) + (_pem_certs(chain) if chain else [])
        k = _key(key, pw)
    if not isinstance(k, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        raise CertError("Unsupported private key type.")
    # the leaf is the certificate that matches the key (a PEM bundle may list the chain first)
    leaf = next((c for c in certs if _pub(c.public_key()) == _pub(k.public_key())), None)
    if leaf is None:
        raise CertError("The private key does not belong to the certificate.")
    rest, seen = [], {leaf.fingerprint(hashes.SHA256())}
    for c in certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            rest.append(c)
    return leaf, _order_chain(leaf, rest), k


def _order_chain(leaf, others):
    """Chain in issuing order (leaf's issuer first); certificates that do not fit go last."""
    out, cur, left = [], leaf, list(others)
    while left:
        nxt = next((c for c in left if c.subject == cur.issuer), None)
        if nxt is None:
            break
        out.append(nxt)
        left.remove(nxt)
        cur = nxt
    return out + left


def names(c):
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [cn[0].value] if cn else []


def _covers(pattern, host):
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern == host:
        return True
    if pattern.startswith("*.") and "." in host:
        return host.split(".", 1)[1] == pattern[2:]
    return False


def covers(c, host):
    try:
        ip = ipaddress.ip_address(host)
        return str(ip) in names(c)
    except ValueError:
        return any(_covers(n, host) for n in names(c))


def info(c):
    """What the page shows about a certificate."""
    cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    icn = c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    end = c.not_valid_after_utc
    return {"subject": cn[0].value if cn else c.subject.rfc4514_string(), "subject_dn": c.subject.rfc4514_string(),
            "issuer": icn[0].value if icn else c.issuer.rfc4514_string(), "names": names(c),
            "not_before": c.not_valid_before_utc, "not_after": end, "days_left": (end - _now()).days,
            "expired": end < _now(), "serial": format(c.serial_number, "x"),
            "sha256": c.fingerprint(hashes.SHA256()).hex(":").upper(), "self_signed": c.issuer == c.subject}


def check(leaf, chain, hosts):
    """(errors, warnings) for a new certificate."""
    errors, warnings = [], []
    now = _now()
    if leaf.not_valid_after_utc < now:
        errors.append("The certificate expired on %s." % leaf.not_valid_after_utc.strftime("%Y-%m-%d"))
    if leaf.not_valid_before_utc > now:
        errors.append("The certificate is not valid until %s." % leaf.not_valid_before_utc.strftime("%Y-%m-%d %H:%M UTC"))
    missing = [h for h in hosts if not covers(leaf, h)]
    if missing:
        errors.append("The certificate does not cover %s (it names %s)." % (", ".join(missing), ", ".join(names(leaf)) or "nothing"))
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            errors.append("The certificate is not for server authentication (no TLS Web Server Authentication usage).")
    except x509.ExtensionNotFound:
        pass
    if 0 <= (leaf.not_valid_after_utc - now).days < 30:
        warnings.append("The certificate expires in %d days." % (leaf.not_valid_after_utc - now).days)
    if leaf.issuer == leaf.subject:
        warnings.append("The certificate is self-signed: browsers will not trust it.")
    elif not any(c.subject == leaf.issuer for c in chain):
        warnings.append("No issuing CA certificate was given: clients must already have the intermediate CA.")
    for c in chain:
        if c.not_valid_after_utc < now:
            warnings.append("A chain certificate (%s) has expired." % info(c)["subject"])
    return errors, warnings


def secret_data(leaf, chain, key):
    """(tls.crt, tls.key) bytes for the Secret: server certificate + chain (root CAs left out), unencrypted key."""
    crt = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [leaf] + [c for c in chain if c.issuer != c.subject])
    k = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return crt, k
