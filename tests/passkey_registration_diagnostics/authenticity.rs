use super::*;

#[test]
fn invalid_signature_masks_missing_user_verification() {
    let fixture = ceremony(93);
    let proof = stage(&fixture).expect("stage");
    let wrong = SigningKey::from_bytes((&[94_u8; 32]).into()).expect("wrong key");
    owner_json(
        &fixture.assertion,
        &assertion_with_flags(&proof, &wrong, 1, 0x01),
    );
    assert_reason(&confirm(&fixture), "signature");
}
