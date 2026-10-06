import argparse
from datetime import datetime, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding


MIN_RSA_KEY_SIZE = 2048
EXPECTED_ISSUER_CN = "TLS Lab Root CA"


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="TLS Certificate Security Inspector"
    )

    parser.add_argument(
        "certificate",
        help="Path to the X.509 certificate to inspect"
    )

    parser.add_argument(
        "--hostname",
        default="localhost",
        help="Expected hostname in the certificate SAN"
    )

    parser.add_argument(
        "--ca",
        help="Path to the trusted Root CA certificate"
    )

    return parser.parse_args()


def verify_certificate_signature(certificate, ca_certificate):
    """
    Verify that the certificate was cryptographically signed
    by the supplied CA certificate.
    """

    public_key = ca_certificate.public_key()

    try:

        if isinstance(public_key, rsa.RSAPublicKey):

            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm
            )

        else:

            print(
                "Signature verification for this CA key type "
                "is not implemented."
            )

            return False

        return True

    except Exception:

        return False


def main():

    args = parse_arguments()

    cert_path = args.certificate
    expected_hostname = args.hostname
    ca_path = args.ca

    failed_checks = 0
    warnings = 0
    critical_issues = 0

    print("=" * 60)
    print("TLS CERTIFICATE SECURITY INSPECTOR")
    print("=" * 60)

    print(f"Certificate : {cert_path}")

    # ------------------------------------------------------------
    # LOAD CERTIFICATE
    # ------------------------------------------------------------

    try:

        with open(cert_path, "rb") as cert_file:

            certificate = x509.load_pem_x509_certificate(
                cert_file.read(),
                default_backend()
            )

    except FileNotFoundError:

        print("ERROR: Certificate file not found.")
        return

    except ValueError:

        print("ERROR: Invalid or unsupported certificate format.")
        return

    # ------------------------------------------------------------
    # CERTIFICATE INFORMATION
    # ------------------------------------------------------------

    print(f"Subject     : {certificate.subject}")
    print(f"Issuer      : {certificate.issuer}")
    print(f"Serial      : {certificate.serial_number}")

    valid_from = certificate.not_valid_before.replace(
        tzinfo=timezone.utc
    )

    valid_until = certificate.not_valid_after.replace(
        tzinfo=timezone.utc
    )

    print(f"Valid From  : {valid_from}")
    print(f"Valid Until : {valid_until}")

    print(
        f"Signature   : "
        f"{certificate.signature_hash_algorithm.name}"
    )

    public_key = certificate.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):

        print("Public Key  : RSA")
        print(f"Key Size    : {public_key.key_size} bits")

    else:

        print(
            f"Public Key  : "
            f"{public_key.__class__.__name__}"
        )

    # ------------------------------------------------------------
    # CERTIFICATE EXPIRY CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("CERTIFICATE EXPIRY CHECK")
    print("-" * 60)

    now = datetime.now(timezone.utc)

    days_remaining = (valid_until - now).days

    print(f"Days Remaining: {days_remaining}")

    if days_remaining < 0:

        print("Status: FAIL")
        print("Reason: Certificate has expired")

        failed_checks += 1

    elif days_remaining <= 7:

        print("Status: CRITICAL")
        print("Reason: Certificate expires within 7 days")

        critical_issues += 1

    elif days_remaining <= 30:

        print("Status: WARNING")
        print("Reason: Certificate expires within 30 days")

        warnings += 1

    else:

        print("Status: PASS")
        print("Reason: Certificate has sufficient validity")

    # ------------------------------------------------------------
    # HOSTNAME / SAN CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("HOSTNAME / SAN CHECK")
    print("-" * 60)

    try:

        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        dns_names = san.get_values_for_type(
            x509.DNSName
        )

        ip_addresses = san.get_values_for_type(
            x509.IPAddress
        )

    except x509.ExtensionNotFound:

        dns_names = []
        ip_addresses = []

    print(f"DNS Names   : {dns_names}")
    print(f"IP Addresses: {ip_addresses}")
    print(f"Expected Hostname: {expected_hostname}")

    hostname_match = False

    if expected_hostname in dns_names:

        hostname_match = True

    try:

        expected_ip = ipaddress.ip_address(
            expected_hostname
        )

        if expected_ip in ip_addresses:

            hostname_match = True

    except ValueError:

        pass

    if hostname_match:

        print("Hostname Check: PASS")
        print(
            "Reason: Expected hostname is present "
            "in the certificate SAN"
        )

    else:

        print("Hostname Check: FAIL")
        print(
            "Reason: Expected hostname is not present "
            "in the certificate SAN"
        )

        failed_checks += 1

    # ------------------------------------------------------------
    # ISSUER / CA NAME CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("ISSUER / CA CHECK")
    print("-" * 60)

    issuer_cn = None

    for attribute in certificate.issuer:

        if attribute.oid == NameOID.COMMON_NAME:

            issuer_cn = attribute.value
            break

    print(
        f"Certificate Issuer CN: {issuer_cn}"
    )

    print(
        f"Expected Issuer CN   : "
        f"{EXPECTED_ISSUER_CN}"
    )

    if issuer_cn == EXPECTED_ISSUER_CN:

        print("Issuer Check: PASS")
        print(
            "Reason: Certificate issuer matches "
            "the expected CA"
        )

    else:

        print("Issuer Check: FAIL")
        print(
            "Reason: Certificate issuer does not "
            "match the expected CA"
        )

        failed_checks += 1

    # ------------------------------------------------------------
    # CRYPTOGRAPHIC TRUST / SIGNATURE CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("CERTIFICATE SIGNATURE / TRUST CHECK")
    print("-" * 60)

    if ca_path:

        print(f"Trusted CA: {ca_path}")

        try:

            with open(ca_path, "rb") as ca_file:

                ca_certificate = x509.load_pem_x509_certificate(
                    ca_file.read(),
                    default_backend()
                )

            signature_valid = verify_certificate_signature(
                certificate,
                ca_certificate
            )

            if signature_valid:

                print("Signature Verification: PASS")
                print(
                    "Reason: Certificate signature is valid "
                    "under the trusted CA public key"
                )

            else:

                print("Signature Verification: FAIL")
                print(
                    "Reason: Certificate signature could not "
                    "be verified by the trusted CA"
                )

                failed_checks += 1

        except FileNotFoundError:

            print("Signature Verification: FAIL")
            print(
                "Reason: Trusted CA certificate "
                "was not found"
            )

            failed_checks += 1

        except ValueError:

            print("Signature Verification: FAIL")
            print(
                "Reason: Invalid trusted CA certificate"
            )

            failed_checks += 1

    else:

        print("Signature Verification: SKIPPED")
        print(
            "Reason: No trusted CA certificate "
            "was provided"
        )

    # ------------------------------------------------------------
    # BASIC CONSTRAINTS / CA CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("BASIC CONSTRAINTS / CA CHECK")
    print("-" * 60)

    try:

        basic_constraints = (
            certificate.extensions
            .get_extension_for_class(
                x509.BasicConstraints
            )
            .value
        )

        ca_flag = basic_constraints.ca

        print(f"CA Flag: {ca_flag}")

        if ca_flag is False:

            print("CA Check: PASS")
            print(
                "Reason: Certificate is correctly "
                "marked as CA:FALSE"
            )

        else:

            print("CA Check: FAIL")
            print(
                "Reason: Server certificate is incorrectly "
                "marked as CA:TRUE"
            )

            failed_checks += 1

    except x509.ExtensionNotFound:

        print("CA Check: FAIL")
        print(
            "Reason: Basic Constraints extension "
            "is missing"
        )

        failed_checks += 1

    # ------------------------------------------------------------
    # KEY USAGE CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("KEY USAGE CHECK")
    print("-" * 60)

    try:

        key_usage = (
            certificate.extensions
            .get_extension_for_class(
                x509.KeyUsage
            )
            .value
        )

        digital_signature = (
            key_usage.digital_signature
        )

        key_encipherment = (
            key_usage.key_encipherment
        )

        print(
            f"Digital Signature: "
            f"{digital_signature}"
        )

        print(
            f"Key Encipherment : "
            f"{key_encipherment}"
        )

        if digital_signature:

            print(
                "Digital Signature Check: PASS"
            )

        else:

            print(
                "Digital Signature Check: FAIL"
            )

            failed_checks += 1

        if key_encipherment:

            print(
                "Key Encipherment Check: PASS"
            )

        else:

            print(
                "Key Encipherment Check: FAIL"
            )

            failed_checks += 1

    except x509.ExtensionNotFound:

        print("Key Usage Check: FAIL")
        print(
            "Reason: Key Usage extension is missing"
        )

        failed_checks += 1

    # ------------------------------------------------------------
    # EXTENDED KEY USAGE CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("EXTENDED KEY USAGE CHECK")
    print("-" * 60)

    try:

        extended_key_usage = (
            certificate.extensions
            .get_extension_for_class(
                x509.ExtendedKeyUsage
            )
            .value
        )

        server_auth = (
            ExtendedKeyUsageOID.SERVER_AUTH
            in extended_key_usage
        )

        print(
            f"TLS Server Authentication: "
            f"{server_auth}"
        )

        if server_auth:

            print(
                "Server Authentication Check: PASS"
            )

            print(
                "Reason: Certificate permits "
                "TLS server authentication"
            )

        else:

            print(
                "Server Authentication Check: FAIL"
            )

            print(
                "Reason: Certificate does not permit "
                "TLS server authentication"
            )

            failed_checks += 1

    except x509.ExtensionNotFound:

        print(
            "Server Authentication Check: FAIL"
        )

        print(
            "Reason: Extended Key Usage "
            "extension is missing"
        )

        failed_checks += 1

    # ------------------------------------------------------------
    # PUBLIC KEY SECURITY CHECK
    # ------------------------------------------------------------

    print("-" * 60)
    print("PUBLIC KEY SECURITY CHECK")
    print("-" * 60)

    if isinstance(public_key, rsa.RSAPublicKey):

        print("Key Algorithm: RSA")

        print(
            f"Key Size: "
            f"{public_key.key_size} bits"
        )

        print(
            f"Minimum Required: "
            f"{MIN_RSA_KEY_SIZE} bits"
        )

        if public_key.key_size >= MIN_RSA_KEY_SIZE:

            print("Key Size Check: PASS")

            print(
                "Reason: RSA key meets the "
                "minimum security requirement"
            )

        else:

            print("Key Size Check: FAIL")

            print(
                "Reason: RSA key is smaller "
                "than the minimum requirement"
            )

            failed_checks += 1

    else:

        print(
            f"Key Algorithm: "
            f"{public_key.__class__.__name__}"
        )

        print(
            "Key Size Check: NOT APPLICABLE"
        )

        print(
            "Reason: Certificate does not use RSA"
        )

    # ------------------------------------------------------------
    # OVERALL SECURITY ASSESSMENT
    # ------------------------------------------------------------

    print("=" * 60)
    print("OVERALL SECURITY ASSESSMENT")
    print("=" * 60)

    print(
        f"Failed Checks : "
        f"{failed_checks}"
    )

    print(
        f"Critical Issues: "
        f"{critical_issues}"
    )

    print(
        f"Warnings      : "
        f"{warnings}"
    )

    if failed_checks > 0:

        print(
            "Certificate Status: FAIL"
        )

        print(
            "Security assessment: "
            "Certificate has security issues."
        )

    elif critical_issues > 0:

        print(
            "Certificate Status: CRITICAL"
        )

        print(
            "Security assessment: "
            "Immediate attention required."
        )

    elif warnings > 0:

        print(
            "Certificate Status: WARNING"
        )

        print(
            "Security assessment: "
            "Certificate requires attention."
        )

    else:

        print(
            "Certificate Status: PASS"
        )

        print(
            "Security assessment: "
            "Certificate passed all checks."
        )

    print("=" * 60)


if __name__ == "__main__":
    main()
