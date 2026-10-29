//! Known-answer tests from the primitives' own specifications.
//! If one fails, a dependency is broken or misconfigured: do not ship.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use hkdf::Hkdf;
use op_core::crypto::{Key, open, seal_with_nonce};
use sha2::Sha256;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

/// RFC 9106, section 5.3 (Argon2id).
#[test]
fn argon2id_rfc9106() {
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&[0x04; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let argon2 =
        Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
        .unwrap();
    assert_eq!(
        out.to_vec(),
        unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

/// RFC 5869, appendix A.1 (HKDF-SHA256, test case 1).
#[test]
fn hkdf_sha256_rfc5869() {
    let ikm = [0x0b; 22];
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(&info, &mut okm)
        .unwrap();
    assert_eq!(
        okm.to_vec(),
        unhex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
             34007208d5b887185865"
        )
    );
}

/// draft-irtf-cfrg-xchacha-03, appendix A.3.1 (AEAD_XChaCha20_Poly1305),
/// run through op-core's own `nonce ‖ ciphertext ‖ tag` framing.
#[test]
fn xchacha20poly1305_draft_irtf_cfrg_xchacha() {
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let key = Key::from_bytes(
        unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap(),
    );
    let nonce: [u8; 24] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
        .try_into()
        .unwrap();
    let ciphertext = unhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e",
    );
    let tag = unhex("c0875924c1c7987947deafd8780acf49");

    let sealed = seal_with_nonce(&key, &nonce, plaintext, &aad);
    let mut expected = nonce.to_vec();
    expected.extend_from_slice(&ciphertext);
    expected.extend_from_slice(&tag);
    assert_eq!(sealed, expected);
    assert_eq!(open(&key, &sealed, &aad).unwrap().as_slice(), plaintext);
}
