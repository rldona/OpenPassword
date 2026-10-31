# OpenPassword cryptographic specification · v1

Status: implemented and verified by the golden vectors in `core/tests/vectors/op-v1.json`; pending external audit. This document is normative: if the code and the specification disagree, the bug is in the code or the specification has to be versioned.

The words MUST, MUST NOT and MAY are used as defined in RFC 2119.

## 1. Goals

1. Zero knowledge: only someone who knows the master password **and** holds the secret key can decrypt a vault or a backup.
2. A stolen backup file MUST withstand brute force even if the master password is weak.
3. All the content of an item, including metadata (type, title, URLs, tags, dates), MUST be encrypted.
4. No encrypted block MUST be movable to another context (another item, another revision, another vault, another field) without authentication failing.
5. Only standard primitives with audited implementations.

## 2. Primitives

| Use | Primitive | Implementation |
|---|---|---|
| Derivation from password | Argon2id v1.3 (RFC 9106) | `argon2` crate (RustCrypto) |
| Key derivation | HKDF-SHA256 (RFC 5869) | `hkdf` + `sha2` crates |
| Authenticated encryption | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) | `chacha20poly1305` crate |
| Block encryption of the backup | STREAM, BE32 variant (Hoang, Reyhanitabar, Rogaway, Vizár, 2015) over XChaCha20-Poly1305 | `chacha20poly1305::aead::stream` |
| Digest | SHA-256 | `sha2` crate |
| Randomness | Operating system CSPRNG | `getrandom` crate |

No compression is used before encrypting: it avoids length leaks (CRIME type) and a dependency in C.

## 3. Keys

All symmetric keys are 256 bits.

| Name | What it is | Where it lives |
|---|---|---|
| **MP** | Master password, Unicode NFKD normalized | Only in the user's head |
| **SK** | Secret key, 128 random bits | Device (protected by Keystore) and paper emergency kit |
| **KEK** | Key encryption key, derived from MP and SK | Only in memory, during unlock |
| **VK** | Vault key, random | Wrapped by the KEK (and optionally by a Keystore key) |
| **IK** | Item key, random, one per item | Wrapped by the VK |
| **FK** | File key, random, one per backup | Wrapped by the VK inside the backup |

## 4. Secret key (SK)

- 16 bytes from the CSPRNG.
- Human representation: version prefix `OP1` and 30 Crockford Base32 characters (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), in groups of 6:

  ```
  OP1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
  ```

  - Characters 1–26: the 128 bits of the SK in big-endian, followed by 2 zero bits.
  - Characters 27–30: 20-bit checksum = the first 20 bits of `SHA-256("op/sk-check/v1" ‖ SK)`.
- When reading it, the implementation MUST ignore hyphens and spaces, accept lowercase and map `O→0` and `I, L→1`. It MUST reject an incorrect checksum or non-zero padding bits.
- Public identifier: `sk_id = HKDF-SHA256(ikm = SK, salt = empty, info = "op/sk-id/v1")[0..4]`. It allows a «clave secreta equivocada» warning before running Argon2id. It does not reveal any bits of the SK.

## 5. KEK derivation

Inputs: MP, SK, `salt` (32 random bytes per vault) and Argon2id parameters.

```
mp_bytes = UTF-8(NFKD(MP))
pw_key   = Argon2id(password = mp_bytes, salt = salt, m, t, p, len = 32)
sk_key   = HKDF-SHA256(ikm = SK, salt = salt, info = "op/sk/v1", len = 32)
KEK      = HKDF-SHA256(ikm = pw_key ‖ sk_key, salt = salt, info = "op/kek/v1", len = 32)
```

The password is not trimmed or modified except for NFKD normalization, so that the same password typed on different keyboards produces the same bytes.

### Argon2id parameters

| Profile | m (KiB) | t | p | Use |
|---|---|---|---|---|
| Recommended | 262 144 (256 MiB) | 3 | 4 | Default when creating a vault |
| Minimum | 65 536 (64 MiB) | 2 | 1 | Low end; it MUST NOT be possible to create below this |
| Maximum accepted on read | 2 097 152 (2 GiB) | 16 | 16 | Reject costlier headers (prevents denial of service) |

Platforms MAY apply a lower ceiling than the format maximum. Android: 512 MiB / 6 / 8 (`MOBILE_MAXIMUM` in `op-ffi`), checked before deriving the key.

When reading an existing vault or backup, parameters below the minimum are accepted (they may come from an older device), but the app MUST offer to re-encrypt with current parameters.

## 6. Authenticated encryption

### 6.1 Format of a sealed block

```
sealed = nonce (24 bytes, random) ‖ ciphertext ‖ tag (16 bytes)
```

Every sealing operation MUST use a fresh nonce from the CSPRNG. With 192 bits the collision risk is negligible.

### 6.2 Associated data (AAD)

Every sealing carries AAD that fixes its context. Encoding:

```
aad(domain, parts...) = UTF-8(domain) ‖ 0x00 ‖ for each part: u32_le(len(part)) ‖ part
```

| What is sealed | Key | Domain | Parts |
|---|---|---|---|
| VK | KEK | `op/wrap/v1` | `"vault_key"`, `vault_id` |
| IK | VK | `op/wrap/v1` | `"item_key"`, `vault_id`, `item_id` |
| Item overview | IK | `op/item/v1` | `"overview"`, `vault_id`, `item_id`, `u64_le(revision)` |
| Item details | IK | `op/item/v1` | `"details"`, `vault_id`, `item_id`, `u64_le(revision)` |
| Attached image | IK | `op/attachment/v1` | `"image"`, `vault_id`, `item_id`, `attachment_id` |
| Backup FK | VK | `op/wrap/v1` | `"file_key"`, `vault_id`, `stream_nonce` |

Consequences: the overview of one item cannot be swapped with that of another, nor can the overview of revision 3 be mixed with the details of revision 2, nor can an IK wrapped in another item or vault be reused.

### 6.3 Padding

Before sealing, the JSON of an overview or of some details is padded to hide its exact length:

```
padded = u32_le(len(json)) ‖ json ‖ 0x00…  (up to a multiple of 64 bytes)
```

When opening, the padding MUST be all zeros and the total length a multiple of 64.

Images use 4096-byte blocks. Their plaintext is `u8 version = 1 ‖ u8 type = 1 (JPEG) ‖ jpeg`. The block is coarser because an image already hides its approximate size and 64-byte padding would add nothing.

## 7. Items

Each item is stored as:

| Field | Contents |
|---|---|
| `id` | 16 random bytes |
| `revision` | u64, starts at 1 and increases on each edit |
| `wrapped_item_key` | IK sealed with the VK |
| `overview` | Sealed with the IK: type, title, subtitle, URLs, tags, favorite, dates. Decrypted on unlock for the list and search |
| `details` | Sealed with the IK: fields, notes and password history. Decrypted only when opening the item |

An edit keeps the IK, increments `revision` and re-seals `overview` and `details` with fresh nonces.

### Images

An item may carry up to 10 images. Each one is an `image` field whose value is the attachment id (hex of 16 bytes) and a separate `EncryptedAttachment` record, sealed with the item's IK and the AAD from the table in 6.2. The attachment is immutable: replacing an image creates a new id, which is why its AAD does not include the revision. The list of `image` fields is the source of truth; a reference without an attachment is kept and the app shows it as unavailable.

Only JPEGs without metadata (no APP1/Exif, COM or MPF) of up to 1.5 MiB are accepted. The app rescales and re-encodes them before sealing them. Images do not go into the password history. The `.opvault` v2 backup includes them; v1 did not have them.

### Password history

In logins, Wi-Fi and secrets, when editing, the core decrypts the `details` of the previous revision and appends to `history` every hidden field whose value is no longer present under the same label: `{label, value, changed_at}`, with `changed_at` equal to the `updated_at` of the edit. The 10 most recent are kept, from newest to oldest. The history is computed by the core, not by the app, so that a UI bug cannot erase it. Cards do not keep history: an old CVV adds nothing and is one more secret. If `history` is empty it is not serialized, so items without history encrypt the same as before.

## 8. Changing the password or the secret key

A new `salt` is generated, the new KEK is derived and the VK is wrapped again. Items are not touched. Old backups still open with the old credentials: the app MUST warn about it.

## 9. Biometric unlock (Android)

1. An AES-256-GCM key is created in the Android Keystore with `setUserAuthenticationRequired(true)`, `BIOMETRIC_STRONG` authentication, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)` and StrongBox when available.
2. The VK is encrypted with that key after a password unlock and stored next to the vault.
3. When unlocking with a fingerprint, the Keystore decrypts the VK.
4. The app MUST ask for the master password every 14 days and after a device reboot. To detect the reboot, it stores `Settings.Global.BOOT_COUNT` on every password unlock.
5. File `vault-key.biometric`: `version (1) ‖ iv (12) ‖ encrypted VK (32) ‖ tag (16)`. If Android invalidates the key (`KeyPermanentlyInvalidatedException`), the app deletes the file and the key and falls back to the password.

This part lives in the Android layer, not in `op-core`.

## 10. Memory hygiene

- The key types in `op-core` wipe their contents when freed (`zeroize`) and do not print their value in `Debug`.
- Decrypted plaintexts are returned in types that are wiped when freed.
- Known limitation: the JVM and Compose handle immutable `String`s that cannot be wiped. The Android layer MUST minimize their lifetime.
- Accepted leftover: `decrypt_image` returns the bytes over UniFFI in a `RustBuffer` that is freed without wiping. The app wipes its copy; bitmaps are wiped when leaving the viewer.

## 11. Versioning

- Domains carry a version suffix (`/v1`). An incompatible change creates `/v2` and a new format version.
- The test vectors in `core/tests/vectors/op-v1.json` pin this version. If a code change breaks them, the change is incompatible.
- The `.opvault` v2 format adds attached images. A v1 reader rejects a v2 backup by its version byte; a v2 reader opens v1 and v2.

## 12. TOTP codes

- RFC 6238 over HOTP (RFC 4226), with HMAC-SHA1, SHA-256 or SHA-512, 6 to 8 digits and a period of 1 to 3600 s. By default: SHA-1, 6 digits and 30 s.
- Input: an `otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=…&digits=…&period=…` link or the secret in base32 (uppercase, spaces, hyphens and `=` padding are ignored). HOTP (`otpauth://hotp`) is not supported, because it requires storing a counter.
- The secret entered by the user MUST be at least 80 bits. This rejects words or text pasted by mistake.
- The secret is one more field of the item's details: it is encrypted like the rest and never shown. The app only shows and copies the code.
- Implementation in `core/src/totp.rs`, tested with the RFC 6238 (appendix B) and RFC 4226 (appendix D) vectors.

## 13. Out of scope for v1

Sharing items between users, synchronization and passkeys. Attached images arrive in v2 (section 7). The per-item IK design leaves sharing prepared.
