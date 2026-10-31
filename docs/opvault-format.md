# `.opvault` backup format · v2

Open format so that anyone can decrypt their data without the app, for example with `opvault decrypt`. The cryptography is in [crypto-spec.md](crypto-spec.md).

v2 adds attached images. v1 is still read: it had no attachments.

## Structure

```
┌──────────────────────────────┐
│ magic         8 bytes        │  "OPVAULT" 0x02
│ header_len    u32 LE         │  ≤ 65 536
│ header        header_len     │  JSON UTF-8, plaintext but authenticated
├──────────────────────────────┤
│ body          rest           │  STREAM-BE32 over XChaCha20-Poly1305
└──────────────────────────────┘
```

The last byte of `magic` is the major version of the format. A complete file cannot exceed 64 MiB.

## Header

```json
{
  "format_version": 2,
  "created_at": 1793257200,
  "vault": {
    "vault_id": "9f2c…(16 bytes hex)",
    "kdf": { "alg": "argon2id", "m_kib": 262144, "t": 3, "p": 4 },
    "salt": "…(32 bytes hex)",
    "secret_key_id": "…(4 bytes hex)",
    "wrapped_vault_key": "…(72 bytes hex)"
  },
  "stream_nonce": "…(19 bytes hex)",
  "wrapped_file_key": "…(72 bytes hex)"
}
```

The header contains no user data: no number of items, no titles, no images. Only what is needed to derive keys. `created_at` is a Unix timestamp in seconds.

## Body

1. `FK` is obtained by opening `wrapped_file_key` with the VK and AAD `aad("op/wrap/v1", "file_key", vault_id, stream_nonce)`.
2. The plaintext is split into 65 536-byte blocks; the last one may be shorter or empty.
3. Each block is encrypted with STREAM-BE32: nonce = `stream_nonce (19) ‖ counter u32 BE ‖ marca_final (1 byte)`.
4. AAD of each block: `SHA-256(magic ‖ header_len ‖ header)`. Modifying a single byte of the header invalidates the body.
5. Each encrypted block occupies 65 552 bytes except the last one. The end marker detects truncations, even at the exact limit of one block.

The plaintext of the body is JSON:

```json
{
  "items": [
    { "id": "…", "revision": 3, "wrapped_item_key": "…", "overview": "…", "details": "…" }
  ],
  "attachments": [
    { "item_id": "…", "id": "…", "data": "base64 estándar" }
  ]
}
```

Items remain individually encrypted inside the body (section 7 of the specification). Thus the body hides the number of items and their revisions, and an item can be imported without re-encrypting it. Attachments are encrypted too: `data` is the envelope of an image sealed with the item key, and it is opened as described in `crypto-spec.md`.

`attachments` is optional. In a v1 backup it never appears; if it appears with content, a v2 reader rejects the file instead of losing the images.

## Opening procedure

1. Check that the file does not exceed 64 MiB, that it starts with `OPVAULT` and that the version is 1 or 2.
2. Check that `header.format_version` matches the `magic` byte.
3. Reject KDF parameters above the accepted maximum.
4. Compare `secret_key_id` with that of the SK entered and warn if they do not match.
5. Derive the KEK and open the VK. If it fails: wrong password or secret key.
6. Open the FK and decrypt the body. In v2, reject duplicate attachments or attachments larger than the maximum; discard those that point to a missing item.

## Compatibility

- A v1 reader MUST reject `magic` with another major version. That is why an old app warns «versión más nueva» on a v2 backup, instead of ignoring the images.
- A v2 reader MUST open v1 (without attachments) and v2.
- New fields MAY be added to the header; readers ignore them, but they remain authenticated.
- The v2 body accepts new fields, but a v2 reader ignores unknown `attachments`: data that is essential must not be added without bumping the version.
