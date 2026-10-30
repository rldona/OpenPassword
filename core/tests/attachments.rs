mod common;

use common::*;
use op_core::backup;
use op_core::vault::{
    Field, FieldKind, MAX_IMAGE_BYTES, MAX_IMAGES_PER_ITEM, NewImage, new_attachment_id,
};
use op_core::Error;
use zeroize::Zeroizing;

/// Minimal structurally valid JPEG: SOI, DQT, SOF0, DHT, SOS, data, EOI.
fn jpeg(seed: u8) -> Vec<u8> {
    let segment = |marker: u8, payload: &[u8]| {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
        out.extend_from_slice(payload);
        out
    };
    let mut out = vec![0xFF, 0xD8];
    out.extend(segment(0xDB, &[seed; 65]));
    out.extend(segment(0xC0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]));
    out.extend(segment(0xC4, &[seed; 20]));
    out.extend(segment(0xDA, &[1, 1, 0, 0, 63, 0]));
    out.extend_from_slice(&[seed, seed.wrapping_add(1)]);
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

fn image_field(id: [u8; 16]) -> Field {
    Field::new("Anverso", FieldKind::Image, hex::encode(id))
}

fn new_image(seed: u8) -> (NewImage, Vec<u8>) {
    let id = new_attachment_id().unwrap();
    let bytes = jpeg(seed);
    (
        NewImage {
            id,
            jpeg: Zeroizing::new(bytes.clone()),
        },
        bytes,
    )
}

#[test]
fn image_roundtrip() {
    let vault = new_vault();
    let (image, bytes) = new_image(1);
    let id = image.id;
    let mut item = card();
    item.details.fields.push(image_field(id));

    let change = vault.encrypt_item_with_images(&item, vec![image]).unwrap();
    assert_eq!(change.added.len(), 1);
    assert!(change.removed.is_empty());
    assert_eq!(vault.image_ids(&change.item).unwrap(), vec![id]);

    let decrypted = vault
        .decrypt_image(&change.item, &change.added[0])
        .unwrap();
    assert_eq!(decrypted.jpeg.as_slice(), bytes.as_slice());
}

#[test]
fn image_aad_is_bound_to_vault_item_and_id() {
    let vault = new_vault();
    let (image, _) = new_image(2);
    let mut item = card();
    item.details.fields.push(image_field(image.id));
    let change = vault.encrypt_item_with_images(&item, vec![image]).unwrap();

    let mut other_id = change.added[0].clone();
    other_id.id = [9; 16];
    assert!(matches!(
        vault.decrypt_image(&change.item, &other_id),
        Err(Error::Decrypt)
    ));

    let mut other_item = change.added[0].clone();
    other_item.item_id = [8; 16];
    assert_eq!(
        vault.decrypt_image(&change.item, &other_item).unwrap_err(),
        Error::InvalidInput("attachment does not belong to item")
    );

    let mut tampered = change.added[0].clone();
    *tampered.data.last_mut().unwrap() ^= 1;
    assert!(matches!(
        vault.decrypt_image(&change.item, &tampered),
        Err(Error::Decrypt)
    ));

    let other_vault = new_vault();
    assert!(matches!(
        other_vault.decrypt_image(&change.item, &change.added[0]),
        Err(Error::Decrypt)
    ));
}

#[test]
fn update_reports_added_and_removed_images() {
    let vault = new_vault();
    let (first, _) = new_image(3);
    let first_id = first.id;
    let mut item = card();
    item.details.fields.push(image_field(first_id));
    let created = vault.encrypt_item_with_images(&item, vec![first]).unwrap();

    let (second, _) = new_image(4);
    let second_id = second.id;
    let mut edited = card();
    edited.details.fields.push(image_field(second_id));
    let change = vault
        .update_item_with_images(&created.item, &edited, vec![second])
        .unwrap();
    assert_eq!(change.added.len(), 1);
    assert_eq!(change.removed, vec![first_id]);
    assert_eq!(change.item.revision, 2);
    assert_eq!(vault.image_ids(&change.item).unwrap(), vec![second_id]);
    // Images never enter the password history.
    assert!(vault.decrypt_details(&change.item).unwrap().history.is_empty());
}

#[test]
fn update_without_images_keeps_the_image_set() {
    let vault = new_vault();
    let (image, _) = new_image(5);
    let mut item = card();
    item.details.fields.push(image_field(image.id));
    let created = vault.encrypt_item_with_images(&item, vec![image]).unwrap();

    let mut retitled = vault.decrypt_item(&created.item).unwrap();
    retitled.overview.title = "Visa renombrada".into();
    let updated = vault.update_item(&created.item, &retitled).unwrap();
    assert_eq!(vault.image_ids(&updated).unwrap().len(), 1);

    let mut without = vault.decrypt_item(&created.item).unwrap();
    without
        .details
        .fields
        .retain(|f| f.kind != FieldKind::Image);
    assert_eq!(
        vault.update_item(&created.item, &without).unwrap_err(),
        Error::InvalidInput("image set changed")
    );
}

#[test]
fn rejects_missing_extra_duplicate_and_oversized_images() {
    let vault = new_vault();
    let (image, _) = new_image(6);
    let mut item = card();
    item.details.fields.push(image_field(image.id));

    assert_eq!(
        vault.encrypt_item(&item).unwrap_err(),
        Error::InvalidInput("image field without data")
    );

    let mut orphan = new_image(7).0;
    orphan.id = new_attachment_id().unwrap();
    assert_eq!(
        vault
            .encrypt_item_with_images(&item, vec![orphan])
            .unwrap_err(),
        Error::InvalidInput("image data without field")
    );

    let mut duplicate = item.clone();
    duplicate.details.fields.push(image_field(image.id));
    assert_eq!(
        vault
            .encrypt_item_with_images(&duplicate, vec![])
            .unwrap_err(),
        Error::InvalidInput("duplicate image id")
    );

    let oversized = NewImage {
        id: new_attachment_id().unwrap(),
        jpeg: Zeroizing::new(vec![0xFF; MAX_IMAGE_BYTES + 1]),
    };
    let mut oversized_item = card();
    oversized_item
        .details
        .fields
        .push(image_field(oversized.id));
    assert_eq!(
        vault
            .encrypt_item_with_images(&oversized_item, vec![oversized])
            .unwrap_err(),
        Error::InvalidInput("image too large")
    );
}

#[test]
fn rejects_too_many_images() {
    let vault = new_vault();
    let mut item = card();
    let mut images = Vec::new();
    for i in 0..=MAX_IMAGES_PER_ITEM {
        let id = new_attachment_id().unwrap();
        item.details.fields.push(image_field(id));
        images.push(NewImage {
            id,
            jpeg: Zeroizing::new(jpeg(u8::try_from(i).unwrap())),
        });
    }
    assert_eq!(
        vault.encrypt_item_with_images(&item, images).unwrap_err(),
        Error::InvalidInput("too many images")
    );
}

#[test]
fn a_missing_attachment_is_kept_as_a_reference() {
    let vault = new_vault();
    let (image, _) = new_image(8);
    let mut item = card();
    item.details.fields.push(image_field(image.id));
    let created = vault.encrypt_item_with_images(&item, vec![image]).unwrap();

    let mut retitled = vault.decrypt_item(&created.item).unwrap();
    retitled.overview.title = "Sigue".into();
    let updated = vault.update_item(&created.item, &retitled).unwrap();
    assert_eq!(vault.image_ids(&updated).unwrap().len(), 1);
}

#[test]
fn adopts_an_item_with_images_into_another_vault() {
    let source = new_vault();
    let (image, bytes) = new_image(9);
    let id = image.id;
    let mut item = card();
    item.details.fields.push(image_field(id));
    let created = source.encrypt_item_with_images(&item, vec![image]).unwrap();

    let plain = source
        .open_item_with_images(&created.item, &created.added)
        .unwrap();
    let target = new_vault();
    let adopted = target.adopt_item(&plain).unwrap();

    assert_ne!(adopted.item.id, created.item.id);
    assert_eq!(target.image_ids(&adopted.item).unwrap(), vec![id]);
    let decrypted = target
        .decrypt_image(&adopted.item, &adopted.added[0])
        .unwrap();
    assert_eq!(decrypted.jpeg.as_slice(), bytes.as_slice());
}

#[test]
fn backup_carries_images_and_drops_orphans() {
    let vault = new_vault();
    let (image, bytes) = new_image(10);
    let mut item = card();
    item.details.fields.push(image_field(image.id));
    let change = vault.encrypt_item_with_images(&item, vec![image]).unwrap();

    let file = backup::write(&vault, std::slice::from_ref(&change.item), &change.added, 1).unwrap();
    let (_, items, attachments) = backup::open(&file, PASSWORD, &secret_key()).unwrap();
    assert_eq!(items, vec![change.item.clone()]);
    assert_eq!(attachments, change.added);
    let restored = vault.decrypt_image(&items[0], &attachments[0]).unwrap();
    assert_eq!(restored.jpeg.as_slice(), bytes.as_slice());

    let mut orphan = change.added[0].clone();
    orphan.item_id = [7; 16];
    let file = backup::write(&vault, std::slice::from_ref(&change.item), &[orphan], 1).unwrap();
    let (_, _, attachments) = backup::open(&file, PASSWORD, &secret_key()).unwrap();
    assert!(attachments.is_empty());

    assert_eq!(
        backup::write(&vault, &[change.item], &[change.added[0].clone(), change.added[0].clone()], 1)
            .unwrap_err(),
        Error::InvalidInput("duplicate attachment")
    );
}
