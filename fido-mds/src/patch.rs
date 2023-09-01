use crate::mds::{
    UserVerificationMethod as RawUserVerificationMethod, VerificationMethodAndCombinations,
};
use crate::UserVerificationMethod;
use tracing::{debug, error, warn};
use uuid::Uuid;

use crc32c::Crc32cHasher;
use std::hash::{Hash, Hasher};

const YK5LIGHTNING: Uuid = uuid::uuid!("c5ef55ff-ad9a-4b9f-b580-adebafe026d0");
const YK5LIGHTNING_HASH: u64 = 3670715709;

const RSADS100: Uuid = uuid::uuid!("7e3f3d30-3557-4442-bdae-139312178b39");
const RSADS100_HASH: u64 = 3336810553;

const FIDO_KEYPASS_S3: Uuid = uuid::uuid!("f4c63eff-d26c-4248-801c-3736c7eaa93a");
const FIDO_KEYPASS_S3_HASH: u64 = 2407033003;

const VIVOKEY_APEX: Uuid = uuid::uuid!("d7a423ad-3e19-4492-9200-78137dccc136");
const VIVOKEY_APEX_HASH: u64 = 2407033003;

const VERIMARK_GUARD_FINGERPRINT: Uuid = uuid::uuid!("d94a29d9-52dd-4247-9c2d-8b818b610389");
const VERIMARK_GUARD_FINGERPRINT_HASH: u64 = 3483018605;

const AUTHENTON1: Uuid = uuid::uuid!("b267239b-954f-4041-a01b-ee4f33c145b6");
const AUTHENTON1_HASH: u64 = 1117557365;

pub(crate) fn mds_user_verification_method_code_accuracy_descriptor(
    uvm: &mut [Vec<VerificationMethodAndCombinations>],
) -> bool {
    let mut changed = false;

    for uvm_and in uvm.iter_mut() {
        if uvm_and.len() == 2 {
            let (l, r) = uvm_and.split_at_mut(1);
            if (l[0].user_verification_method == RawUserVerificationMethod::PasscodeExternal
                && l[0].ca_desc.is_none()
                && r[0].user_verification_method == RawUserVerificationMethod::PresenceInternal
                && r[0].ca_desc.is_some())
                || (r[0].user_verification_method == RawUserVerificationMethod::PasscodeExternal
                    && r[0].ca_desc.is_none()
                    && l[0].user_verification_method == RawUserVerificationMethod::PresenceInternal
                    && l[0].ca_desc.is_some())
            {
                std::mem::swap(&mut l[0].ca_desc, &mut r[0].ca_desc);
                changed = true;
            }
        }
    }

    changed
}

pub(crate) fn mds_user_verification_method_invalid_all_present(
    uvm: &mut [Vec<VerificationMethodAndCombinations>],
) -> bool {
    let mut changed = false;

    for uvm_and in uvm.iter_mut() {
        let mut idx = None;
        for (i, uvm_item) in uvm_and.iter().enumerate() {
            if uvm_item.user_verification_method == RawUserVerificationMethod::All {
                idx = Some(i)
            }
        }
        if let Some(idx) = idx {
            uvm_and.remove(idx);
            changed = true;
        }
    }

    changed
}

pub(crate) fn user_verification_method(
    aaguid: Option<Uuid>,
    uvm: &Vec<Vec<UserVerificationMethod>>,
) -> Result<Option<Vec<Vec<UserVerificationMethod>>>, ()> {
    #[allow(deprecated)]
    let mut hasher = Crc32cHasher::default();
    uvm.hash(&mut hasher);
    let hash = hasher.finish();

    match aaguid {
        Some(aaguid) => {
            if aaguid == YK5LIGHTNING {
                if hash == YK5LIGHTNING_HASH {
                    user_verification_method_yk5lightning(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        YK5LIGHTNING, hash
                    );
                    Err(())
                }
            } else if aaguid == RSADS100 {
                if hash == RSADS100_HASH {
                    user_verification_method_rsads100(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        RSADS100, hash
                    );
                    Err(())
                }
            } else if aaguid == FIDO_KEYPASS_S3 {
                if hash == FIDO_KEYPASS_S3_HASH {
                    user_verification_method_fido_keypass_s3(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        FIDO_KEYPASS_S3, hash
                    );
                    Err(())
                }
            } else if aaguid == VIVOKEY_APEX {
                if hash == VIVOKEY_APEX_HASH {
                    user_verification_method_vivokey_apex(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        VIVOKEY_APEX, hash
                    );
                    Err(())
                }
            } else if aaguid == VERIMARK_GUARD_FINGERPRINT {
                if hash == VERIMARK_GUARD_FINGERPRINT_HASH {
                    user_verification_method_verimark_guard_fingerprint(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        VERIMARK_GUARD_FINGERPRINT, hash
                    );
                    Err(())
                }
            } else if aaguid == AUTHENTON1 {
                if hash == AUTHENTON1_HASH {
                    user_verification_method_authenton1(uvm).map(Some)
                } else {
                    warn!(
                        "Hash for {} hash changed ({}), this must be inspected manually",
                        AUTHENTON1, hash
                    );
                    Err(())
                }
            } else {
                debug!(?hash);
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

/// Incorrect UVM Method:
/// `PresenceInternal AND PasscodeInternal() AND None`
///
/// This is and incorrect documentation of the methods, but the "intent" is clear since the
/// intended UVM's are the same as other Yubikey models. The intent here was that these should
/// actually be in the OR condition structure, and that PasscodeInternal is actually
/// PresenceInternal + PasscodeExternal.
fn user_verification_method_yk5lightning(
    uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    // We know the

    let code_accuracy = match uvm_and.get(0).and_then(|inner| inner.get(1)) {
        Some(UserVerificationMethod::PasscodeInternal(cad)) => cad.clone(),
        res => {
            error!("Expected UVM::PasscodeInternal, found {:?}", res);
            return Err(());
        }
    };

    // ORs
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![
            UserVerificationMethod::PresenceInternal,
            UserVerificationMethod::PasscodeExternal(code_accuracy.clone()),
        ],
        vec![UserVerificationMethod::PasscodeExternal(code_accuracy)],
        vec![UserVerificationMethod::None],
    ])
}

/// We do NOT have access to this device, so we can only speculate that the same data error
/// that affects the yk5ci is present here. Since the product does not have a method to
/// internally accept a PIN, this is likely correct. See
/// <https://www.rsa.com/resources/datasheets/id-plus-ds100-authenticator/>
fn user_verification_method_rsads100(
    uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    let code_accuracy = match uvm_and.get(0).and_then(|inner| inner.get(1)) {
        Some(UserVerificationMethod::PasscodeExternal(cad)) => cad.clone(),
        res => {
            error!("Expected UVM::PasscodeInternal, found {:?}", res);
            return Err(());
        }
    };

    // ORs
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![
            UserVerificationMethod::PresenceInternal,
            UserVerificationMethod::PasscodeExternal(code_accuracy.clone()),
        ],
        vec![UserVerificationMethod::PasscodeExternal(code_accuracy)],
        vec![UserVerificationMethod::None],
    ])
}

/// We do NOT have access to this device, so we can only speculate that the same data error
/// that affects the yk5ci is present here where the inputs were placed into an AND rather
/// than the OR block.
fn user_verification_method_fido_keypass_s3(
    _uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    // ORs
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![UserVerificationMethod::None],
    ])
}

/// We do NOT have access to this device, so we can only speculate that the same data error
/// that affects the yk5ci is present here where the inputs were placed into an AND rather
/// than the OR block.
fn user_verification_method_vivokey_apex(
    _uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    // ORs
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![UserVerificationMethod::None],
    ])
}

/// We do NOT have access to this device, so we can only speculate that the same data error
/// that affects the yk5ci is present here. Since the product does not have a method to
/// internally accept a PIN, this is likely correct. See
/// <https://www.kensington.com/software/verimark-setup/verimark-guard-setup-guide/>
fn user_verification_method_verimark_guard_fingerprint(
    _uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![
            UserVerificationMethod::PresenceInternal,
            UserVerificationMethod::FingerprintInternal(None),
        ],
        vec![
            UserVerificationMethod::PresenceInternal,
            UserVerificationMethod::PasscodeExternal(None),
        ],
        vec![UserVerificationMethod::None],
    ])
}

/// Incorrect UVM Method:
/// `PresenceInternal AND PasscodeInternal() AND None`
///
/// This issue affects multiple other FIDO devices. FIDO have inserted incorrect
/// metadata that is not consistent.
fn user_verification_method_authenton1(
    uvm_and: &[Vec<UserVerificationMethod>],
) -> Result<Vec<Vec<UserVerificationMethod>>, ()> {
    debug!(?uvm_and);
    let code_accuracy = match uvm_and.get(0).and_then(|inner| inner.get(2)) {
        Some(UserVerificationMethod::PasscodeExternal(cad)) => cad.clone(),
        res => {
            error!("Expected UVM::PasscodeInternal, found {:?}", res);
            return Err(());
        }
    };

    // ORs
    Ok(vec![
        vec![UserVerificationMethod::PresenceInternal],
        vec![
            UserVerificationMethod::PresenceInternal,
            UserVerificationMethod::PasscodeExternal(code_accuracy.clone()),
        ],
        vec![UserVerificationMethod::PasscodeExternal(code_accuracy)],
        vec![UserVerificationMethod::None],
    ])
}
