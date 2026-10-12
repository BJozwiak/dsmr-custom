#!/usr/bin/env python3
"""Offline analysis of a raw STOEN / ELGAMA P1 telegram.

Capture a telegram with the component's debug dump:

    dsmr_custom:
      ...
      debug_udp_target: "<this machine>:37008"

    $ nc -ul 37008 > telegram.bin     # stop after one or two seconds

then inspect it here:

    $ python3 scripts/analyze-stoen-telegram.py telegram.bin --key-file key.txt

The script mirrors the frame arithmetic of components/dsmr_custom/bajo.cpp, so
it is a second opinion on that code: it prints the DLMS wrapper fields, the
decrypted telegram, and which additional-authenticated-data layout (if any)
reproduces the AES-GCM tag that the meter sent.

The decryption key is read from a file by default so it stays out of the shell
history; --key accepts it inline for throwaway use.
"""

from __future__ import annotations

import argparse
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ImportError:  # pragma: no cover
    sys.exit("needs the 'cryptography' package: pip install cryptography")

GCM_TAG_LENGTH = 12
SC_AND_FC_LENGTH = 5  # security control byte + 4 byte frame counter
SC_ENCRYPTED = 0x20
SC_AUTHENTICATED = 0x10


def tag_matches(key: bytes, iv: bytes, aad: bytes | None, ciphertext: bytes, frame_tag: bytes) -> bool:
    """Does the ciphertext authenticate to frame_tag under aad?

    DLMS truncates the GCM tag to 12 bytes, which the AESGCM convenience class
    refuses, so go through the Cipher API with an explicit min_tag_length.
    """
    decryptor = Cipher(
        algorithms.AES(key), modes.GCM(iv, frame_tag, min_tag_length=len(frame_tag))
    ).decryptor()
    if aad:
        decryptor.authenticate_additional_data(aad)
    decryptor.update(ciphertext)
    try:
        decryptor.finalize()
    except InvalidTag:
        return False
    return True


def parse_key(args: argparse.Namespace, which: str) -> bytes | None:
    """Read a 16 byte key from --<which> or --<which>-file."""
    inline = getattr(args, which)
    path = getattr(args, f"{which}_file")
    if inline is None and path is None:
        return None
    text = inline if inline is not None else open(path).read()
    text = "".join(text.split()).removeprefix("0x")
    if len(text) != 32:
        sys.exit(f"{which}: expected 32 hex characters, got {len(text)}")
    return bytes.fromhex(text)


def split_telegram(raw: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a raw capture into (header line, encrypted body, footer CRC)."""
    start = raw.find(b"/")
    if start < 0:
        sys.exit("no '/' in the capture, so no telegram start")
    separator = raw.find(b"\r\n\r\n", start)
    if separator < 0:
        sys.exit("no empty line after the header, so no body start")
    header = raw[start:separator]

    # Offline we have the whole frame, so the footer is simply the tail. That
    # avoids the "'!' also occurs inside the ciphertext" problem the firmware
    # has to deal with while streaming.
    end = raw.rfind(b"\r\n")
    if end < 0 or end < separator:
        sys.exit("no CRLF at the end of the telegram")
    tail = raw[separator + 4 : end]
    bang = tail.rfind(b"!")
    if bang < 0:
        sys.exit("no '!' before the final CRLF, so no footer")
    return header, tail[:bang], tail[bang + 1 :]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture", help="file holding one raw telegram")
    parser.add_argument("--key", help="decryption key as 32 hex characters")
    parser.add_argument("--key-file", help="file holding the decryption key")
    parser.add_argument("--auth-key", help="DLMS authentication key as 32 hex characters")
    parser.add_argument("--auth-key-file", help="file holding the authentication key")
    args = parser.parse_args()

    raw = open(args.capture, "rb").read()
    print(f"capture: {len(raw)} bytes")

    header, body, footer = split_telegram(raw)
    print(f"header:  {header!r}")
    print(f"body:    {len(body)} bytes")
    print(f"footer:  {footer!r}")

    if len(body) < 2:
        sys.exit("body too short for a DLMS wrapper")

    if body[0] == 0x00:
        system_title_length = 1
        system_title = b""
    elif body[0] == 0xDB:
        system_title_length = body[1] + 2
        system_title = body[2:system_title_length]
    else:
        sys.exit(f"unknown start byte 0x{body[0]:02X}")

    if len(body) < system_title_length + 8:
        sys.exit("body too short for the length field")
    if body[system_title_length] != 0x82:
        sys.exit(f"expected a 0x82 length marker, got 0x{body[system_title_length]:02X}")

    len_info = int.from_bytes(body[system_title_length + 1 : system_title_length + 3], "big")
    security_byte = body[system_title_length + 3]
    frame_counter = body[system_title_length + 4 : system_title_length + 8]
    ciphertext_offset = system_title_length + 8

    print(f"\nsystem title:  {system_title.hex(' ') or '(empty)'} ({system_title_length} bytes incl. prefix)")
    print(f"LEN_INFO:      {len_info}")
    print(f"security byte: 0x{security_byte:02X}", end="  ")
    print(
        f"(encrypted={bool(security_byte & SC_ENCRYPTED)}, "
        f"authenticated={bool(security_byte & SC_AUTHENTICATED)})"
    )
    print(f"frame counter: {frame_counter.hex(' ')}")

    tag_length = GCM_TAG_LENGTH if security_byte & SC_AUTHENTICATED else 0
    ciphertext_len = len_info - SC_AND_FC_LENGTH - tag_length
    expected = ciphertext_offset + ciphertext_len + tag_length
    print(f"ciphertext:    {ciphertext_len} bytes at offset {ciphertext_offset}")
    print(f"frame length:  LEN_INFO implies {expected}, body holds {len(body)}", end="")
    print("  <-- MISMATCH" if expected != len(body) else "  (match)")
    if ciphertext_len <= 0 or expected > len(body):
        sys.exit("frame arithmetic does not work out, nothing to decrypt")

    ciphertext = body[ciphertext_offset : ciphertext_offset + ciphertext_len]
    frame_tag = body[ciphertext_offset + ciphertext_len : ciphertext_offset + ciphertext_len + tag_length]
    iv = (system_title if len(system_title) == 8 else bytes(8)) + frame_counter
    print(f"IV:            {iv.hex(' ')}")
    print(f"tag in frame:  {frame_tag.hex(' ')}")

    key = parse_key(args, "key")
    if key is None:
        sys.exit("\nno decryption key given (--key or --key-file), stopping before decryption")
    auth_key = parse_key(args, "auth_key")

    candidates: list[tuple[str, bytes | None]] = []
    if auth_key is not None:
        candidates.append(("security byte || authentication key", bytes([security_byte]) + auth_key))
    candidates.append(("security byte", bytes([security_byte])))
    candidates.append(("none", None))

    print("\nadditional authenticated data candidates:")
    verified = None
    for name, aad in candidates:
        if tag_matches(key, iv, aad, ciphertext, frame_tag):
            print(f"  {name:38} tag MATCHES")
            if verified is None:
                verified = name
        else:
            print(f"  {name:38} tag does NOT match")
    if verified is None:
        print("\n  -> the tag cannot be reproduced: the meter authenticates over data we do not have")
        print("     (with a decryption key only this is expected; the plaintext below is still correct)")
    else:
        print(f"\n  -> authenticated telegram, additional data = {verified}")

    # Keystream only: GCM decryption without the tag check, which is what the
    # firmware falls back to when the tag cannot be reproduced.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).decryptor()
    plaintext = decryptor.update(ciphertext)

    print(f"\ndecrypted {len(plaintext)} bytes:\n")
    try:
        print(plaintext.decode("ascii"))
    except UnicodeDecodeError:
        print(plaintext)
        print("\n  -> not ASCII, so the key or the frame arithmetic is wrong")


if __name__ == "__main__":
    main()
