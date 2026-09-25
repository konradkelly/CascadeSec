#!/usr/bin/env python3
"""Move the GitHub App's private key into AWS KMS, where no code can read it.

github-gateway signs the App's JWT with kms:Sign on this key and never holds
the key itself (docs/ci-integration-spec.md §4.1). A key in Secrets Manager
can be read by anything granted GetSecretValue, and read once it is copied
for good; a key in KMS can only be used, and every use is a CloudTrail event.

Run once, locally, with the .pem GitHub downloaded:

  python scripts/import_github_app_key.py --pem path/to/cascadesec.private-key.pem

or, if the .pem is gone and only the Secrets Manager copy remains:

  python scripts/import_github_app_key.py --from-secret iacposture/dev/github-app-private-key

What it does, in order:
  1. creates an RSA SIGN_VERIFY key with Origin=EXTERNAL and the alias
     Terraform looks it up by (or resumes one still waiting for its material);
  2. wraps the key with KMS's one-time import public key
     (RSA_AES_KEY_WRAP_SHA_256), in this process -- the unwrapped key never
     leaves this machine;
  3. imports it, with no expiry;
  4. proves the import: KMS signs a test message, and the signature is
     verified against the public half of the local key. A key that verifies
     is the App's key; nothing else is taken on trust.

The key material is never printed or written to disk. Needs `cryptography`
(requirements-dev.txt) and credentials that can create KMS keys.
"""

import argparse
import os
import sys

import boto3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding

KEY_SPECS = {2048: "RSA_2048", 3072: "RSA_3072", 4096: "RSA_4096"}
# RS256, the only algorithm GitHub accepts for an App JWT.
SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"


def load_key(args, session):
    if args.pem:
        with open(args.pem, "rb") as f:
            pem = f.read()
    else:
        sm = session.client("secretsmanager")
        pem = sm.get_secret_value(SecretId=args.from_secret)["SecretString"].encode()
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        sys.exit("not an RSA private key -- GitHub App keys are RSA")
    if key.key_size not in KEY_SPECS:
        sys.exit(f"unsupported RSA key size {key.key_size}")
    return key


def find_or_create_key(kms, alias, key_spec):
    """The key under `alias`, created if absent. Refuses one already imported."""
    try:
        meta = kms.describe_key(KeyId=alias)["KeyMetadata"]
    except kms.exceptions.NotFoundException:
        meta = None

    if meta is not None:
        if meta["KeyState"] != "PendingImport":
            sys.exit(f"{alias} is {meta['KeyState']}, not waiting for material. KMS "
                     "cannot replace imported material with a different key; to "
                     "rotate, delete the alias and key, then run this again.")
        if meta.get("KeySpec") != key_spec or meta.get("Origin") != "EXTERNAL":
            sys.exit(f"{alias} exists as {meta.get('KeySpec')}/{meta.get('Origin')}, "
                     f"expected {key_spec}/EXTERNAL")
        print(f"resuming   {meta['Arn']} (was waiting for its material)")
        return meta["Arn"]

    meta = kms.create_key(
        KeySpec=key_spec,
        KeyUsage="SIGN_VERIFY",
        Origin="EXTERNAL",
        Description="GitHub App private key (CascadeSec); github-gateway signs its JWT with it",
    )["KeyMetadata"]
    kms.create_alias(AliasName=alias, TargetKeyId=meta["KeyId"])
    print(f"created    {meta['Arn']}")
    return meta["Arn"]


def wrap(key, wrapping_public_der):
    """RSA_AES_KEY_WRAP_SHA_256: a fresh AES key wraps the PKCS#8 DER key,
    and KMS's public key wraps the AES key. KMS wants the two concatenated,
    RSA-wrapped AES key first."""
    material = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    aes_key = os.urandom(32)
    wrapping_key = serialization.load_der_public_key(wrapping_public_der)
    encrypted_aes = wrapping_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return encrypted_aes + aes_key_wrap_with_padding(aes_key, material)


def prove(kms, key_arn, key):
    """KMS signs; the local public key verifies. Raises if they differ."""
    message = b"cascadesec key import check"
    signature = kms.sign(
        KeyId=key_arn, Message=message, MessageType="RAW",
        SigningAlgorithm=SIGNING_ALGORITHM,
    )["Signature"]
    key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pem", help="path to the .pem GitHub downloaded")
    source.add_argument("--from-secret", help="Secrets Manager id holding the PEM")
    parser.add_argument("--alias", default="alias/iacposture-dev-github-app",
                        help="must match terraform/lambda_github_gateway.tf (default: %(default)s)")
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    kms = session.client("kms")

    key = load_key(args, session)
    key_spec = KEY_SPECS[key.key_size]
    print(f"local key  RSA {key.key_size}")

    key_arn = find_or_create_key(kms, args.alias, key_spec)

    params = kms.get_parameters_for_import(
        KeyId=key_arn,
        WrappingAlgorithm="RSA_AES_KEY_WRAP_SHA_256",
        WrappingKeySpec="RSA_4096",
    )
    kms.import_key_material(
        KeyId=key_arn,
        ImportToken=params["ImportToken"],
        EncryptedKeyMaterial=wrap(key, params["PublicKey"]),
        ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
    )
    print("imported   key material, no expiry")

    prove(kms, key_arn, key)
    print("verified   KMS signature checks out against the local public key")
    print(f"\ndone. alias {args.alias} -> {key_arn}")


if __name__ == "__main__":
    main()
