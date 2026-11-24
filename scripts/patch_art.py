#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 feiyehua
"""Rebind an ART body to a saved SHSH IM4M and recompute its MAC.

Two values are taken from the supplied ticket:

* the manifest hash -- SHA-1 over the complete IM4M DER
* the restore nonce -- the ``snon`` OCTET STRING inside MANP

They replace the ART body's manifest-hash and restore-nonce OCTET STRINGs.
Either field may be empty (or longer than 20 bytes) in a template ART, so the
OCTET STRING, body SEQUENCE and outer SEQUENCE lengths are re-encoded and the
patched ART may grow or shrink. The sleep hash and subcounter SET are kept
byte-for-byte.

The 32-byte ART MAC is then recomputed as HMAC-SHA256(K_ART, body_DER), where
body_DER is the complete inner SEQUENCE including its tag and length.

The ticket may be given either as an SHSH2 property list (ApImg4Ticket is
picked automatically) or as a raw IM4M DER file. Read-only except for the
optional --output file. No third-party modules are used.
"""
import argparse
import base64
import hashlib
import hmac
import plistlib
import sys
from pathlib import Path

UNIVERSAL_CLASS = 0
TAG_INTEGER = 2
TAG_OCTET_STRING = 4
TAG_SEQUENCE = 16
TAG_SET = 17
TAG_IA5_STRING = 22


class DerError(ValueError):
    """Input is not well-formed enough to be patched."""


class Node:
    """One definite-length DER TLV, with absolute offsets into the input."""

    __slots__ = ('cls', 'tag', 'constructed', 'start', 'header_end', 'end',
                 'value', 'children')

    def __init__(self, cls, tag, constructed, start, header_end, end, value):
        self.cls = cls
        self.tag = tag
        self.constructed = constructed
        self.start = start
        self.header_end = header_end
        self.end = end
        self.value = value
        self.children = []


def parse_tlv(data, offset=0, limit=None):
    """Parse one DER TLV at *offset* and return (node, end)."""
    if limit is None:
        limit = len(data)
    start = offset
    if offset >= limit:
        raise DerError(f'truncated DER at offset {offset}')

    first = data[offset]
    offset += 1
    cls = first & 0xC0
    constructed = bool(first & 0x20)
    tag = first & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if offset >= limit:
                raise DerError(f'truncated high tag at offset {start}')
            byte = data[offset]
            offset += 1
            tag = (tag << 7) | (byte & 0x7F)
            if tag > 0xFFFFFFFF:
                raise DerError(f'tag at offset {start} is too large')
            if not byte & 0x80:
                break

    if offset >= limit:
        raise DerError(f'truncated length at offset {start}')
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        raise DerError(f'indefinite length at offset {start} is not DER')
    else:
        count = length_byte & 0x7F
        if count > 8 or offset + count > limit:
            raise DerError(f'bad length at offset {start}')
        length = int.from_bytes(data[offset:offset + count], 'big')
        offset += count

    header_end = offset
    end = header_end + length
    if end > limit:
        raise DerError(f'element at offset {start} runs past its container')

    value = None if constructed else bytes(data[header_end:end])
    node = Node(cls, tag, constructed, start, header_end, end, value)
    if constructed:
        position = header_end
        while position < end:
            child, position = parse_tlv(data, position, end)
            node.children.append(child)
        if position != end:
            raise DerError(f'element at offset {start} has trailing bytes')
    return node, end


def parse_complete(data, what):
    node, end = parse_tlv(data)
    if end != len(data):
        raise DerError(f'{what}: {len(data) - end} trailing bytes after DER')
    return node


def percent_hex(data):
    """nvram-style byte string: every byte is prefixed with '%'."""
    return ''.join(f'%{byte:02x}' for byte in data)


def der_tlv(tag, value):
    size = len(value)
    if size < 0x80:
        header = bytes((tag, size))
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, 'big')
        header = bytes((tag, 0x80 | len(encoded))) + encoded
    return header + value


def raw(data, node):
    return data[node.start:node.end]


def is_universal(node, tag):
    return node.cls == UNIVERSAL_CLASS and node.tag == tag


def find_octet_string(node, name):
    """Return the OCTET STRING paired with IA5STRING *name* anywhere below."""
    if not node.constructed:
        return None
    children = node.children
    if len(children) >= 2:
        label, field = children[0], children[1]
        if is_universal(label, TAG_IA5_STRING) and label.value == name \
                and is_universal(field, TAG_OCTET_STRING):
            return field.value
    for child in children:
        found = find_octet_string(child, name)
        if found is not None:
            return found
    return None


def iter_tickets(plist, prefix=''):
    """Yield (key path, ApImg4Ticket bytes) for every ticket in the plist."""
    for key, value in plist.items():
        path = f'{prefix}{key}'
        if isinstance(value, dict):
            yield from iter_tickets(value, path + '/')
        elif 'ApImg4Ticket' in key:
            if isinstance(value, bytes):
                yield path, value
            elif isinstance(value, str):
                try:
                    yield path, base64.b64decode(value, validate=True)
                except ValueError:
                    continue


def select_ticket(plist, wanted):
    entries = list(iter_tickets(plist))
    if not entries:
        raise DerError('No ApImg4Ticket found in the property list')
    names = [name for name, _ in entries]
    if wanted is not None:
        for name, blob in entries:
            if name == wanted:
                return name, blob
        raise DerError(f'No ticket {wanted!r}; available: {names}')
    for name, blob in entries:
        if name == 'ApImg4Ticket':
            return name, blob
    main = [(name, blob) for name, blob in entries if 'updateInstall' not in name]
    if len(main) == 1:
        return main[0]
    raise DerError('Cannot choose a main ticket automatically; pass '
                   f'--ticket-key. Available: {names}')


def load_ticket(path):
    """Return (key path, IM4M DER bytes) from an SHSH2 plist or a raw DER."""
    data = path.read_bytes()
    if data[:1] == b'\x30':  # DER SEQUENCE: an extracted IM4M
        return path.name, data
    try:
        plist = plistlib.loads(data)
    except Exception as exc:
        raise DerError(f'{path}: neither a property list nor a DER ticket: {exc}')
    if not isinstance(plist, dict):
        raise DerError(f'{path}: property list root is not a dictionary')
    return select_ticket(plist, None)


def ticket_values(blob):
    """Return (SHA-1 of the whole IM4M DER, MANP snon)."""
    im4m = parse_complete(blob, 'IM4M')
    if not is_universal(im4m, TAG_SEQUENCE) or not im4m.children \
            or not is_universal(im4m.children[0], TAG_IA5_STRING) \
            or im4m.children[0].value != b'IM4M':
        raise DerError('Ticket is not an IM4M SEQUENCE starting with "IM4M"')
    nonce = find_octet_string(im4m, b'snon')
    if nonce is None:
        nonce = find_octet_string(im4m, b'SNON')
    if nonce is None:
        raise DerError('Ticket has no MANP snon field')
    if len(nonce) != 20:
        raise DerError(f'SNON is {len(nonce)} bytes, expected 20')
    return hashlib.sha1(blob).digest(), nonce


def patch_art(data, manifest, nonce, key):
    """Return (patched ART DER, body_DER length, new MAC)."""
    art = parse_complete(data, 'ART')
    if not is_universal(art, TAG_SEQUENCE):
        raise DerError('ART is not a SEQUENCE')
    if len(art.children) != 3:
        raise DerError('ART must hold version, body and MAC')
    version, body, mac = art.children
    if not is_universal(version, TAG_INTEGER) \
            or not is_universal(body, TAG_SEQUENCE) \
            or not is_universal(mac, TAG_OCTET_STRING):
        raise DerError('ART must be INTEGER, SEQUENCE (body), OCTET STRING (MAC)')
    if [(child.cls, child.tag) for child in body.children] != [
            (UNIVERSAL_CLASS, TAG_INTEGER),
            (UNIVERSAL_CLASS, TAG_OCTET_STRING),
            (UNIVERSAL_CLASS, TAG_OCTET_STRING),
            (UNIVERSAL_CLASS, TAG_OCTET_STRING),
            (UNIVERSAL_CLASS, TAG_SET)]:
        raise DerError('ART body must be INTEGER, three OCTET STRINGs, SET')
    if len(manifest) != 20 or len(nonce) != 20:
        raise DerError('Manifest hash and restore nonce must be 20 bytes')

    counter, _, sleep, _, props = body.children
    body_der = der_tlv(0x30, b''.join((
        raw(data, counter),
        der_tlv(0x04, manifest),
        raw(data, sleep),
        der_tlv(0x04, nonce),
        raw(data, props),
    )))
    new_mac = hmac.new(key, body_der, hashlib.sha256).digest()
    out = der_tlv(0x30, b''.join((
        raw(data, version),
        body_der,
        der_tlv(0x04, new_mac),
    )))

    check = parse_complete(out, 'patched ART')
    _, check_body, check_mac = check.children
    if check_body.children[1].value != manifest:
        raise DerError('Post-patch manifest hash mismatch')
    if check_body.children[3].value != nonce:
        raise DerError('Post-patch restore nonce mismatch')
    if check_mac.value != new_mac:
        raise DerError('Post-patch ART MAC mismatch')
    return out, len(body_der), new_mac


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shsh', type=Path, required=True,
                        help='SHSH2 property list, or a file holding the raw '
                             'IM4M/ApImg4Ticket DER')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--art-hex', help='Original ART DER as hexadecimal')
    source.add_argument('--art-file', type=Path,
                        help='Original ART DER binary file')
    parser.add_argument('--art-key', required=True,
                        help='K_ART as hexadecimal (32 bytes)')
    parser.add_argument('--ticket-key', default=None,
                        help='Exact plist key of the ticket '
                             '(default: main ApImg4Ticket)')
    parser.add_argument('--format', choices=('both', 'percent', 'hex', 'der'),
                        default='both',
                        help='Output format: nvram-style percent string and '
                             'plain hex (default), percent string only, plain '
                             'hex only, or raw DER')
    parser.add_argument('--output', type=Path,
                        help='Write to this file instead of stdout')
    args = parser.parse_args()

    try:
        key_hex = args.art_key.strip()
        if key_hex[:2].lower() == '0x':
            key_hex = key_hex[2:]
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            raise DerError('--art-key is not valid hexadecimal')
        if len(key) != 32:
            raise DerError(f'K_ART must be 32 bytes, got {len(key)}')

        if args.art_file:
            art_data = args.art_file.read_bytes()
        else:
            try:
                art_data = bytes.fromhex(args.art_hex)
            except ValueError:
                raise DerError('--art-hex is not valid hexadecimal')

        if args.ticket_key is None:
            name, blob = load_ticket(args.shsh)
        else:
            data = args.shsh.read_bytes()
            if data[:1] == b'\x30':
                raise DerError('--ticket-key is only meaningful for a plist; '
                               'the DER file holds a single ticket')
            name, blob = select_ticket(plistlib.loads(data), args.ticket_key)
        manifest, nonce = ticket_values(blob)
        patched, body_len, mac = patch_art(art_data, manifest, nonce, key)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f'ticket: {name}', file=sys.stderr)
    print(f'manifest SHA-1: {manifest.hex()}', file=sys.stderr)
    print(f'SNON: {nonce.hex()}', file=sys.stderr)
    print(f'body_DER: {body_len} bytes', file=sys.stderr)
    print(f'MAC32: {mac.hex()}', file=sys.stderr)

    if args.format == 'der':
        payload = patched
    else:
        lines = []
        if args.format in ('both', 'percent'):
            lines.append(percent_hex(patched))
        if args.format in ('both', 'hex'):
            lines.append(patched.hex())
        payload = ('\n'.join(lines) + '\n').encode('ascii')

    if args.output:
        args.output.write_bytes(payload)
        print(f'wrote {args.output} ({len(payload)} bytes, {args.format})',
              file=sys.stderr)
    else:
        sys.stdout.buffer.write(payload)


if __name__ == '__main__':
    main()
