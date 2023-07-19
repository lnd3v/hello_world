use sha2::{Sha256, Digest};
use zbase32;
use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
use secp256k1::rand;
use secp256k1::ecdsa::{RecoveryId, RecoverableSignature};

fn sign_message(message: &str, secret_key: SecretKey) -> Option<String> {
    let secp = Secp256k1::new();
    let prefixed_message = format!("Lightning Signed Message:{}", message);
    let message_hash = Sha256::digest(prefixed_message.as_bytes());
    let msg = Message::from_slice(&message_hash).ok()?;
    let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let (recovery_id, signature_data) = signature.serialize_compact();
    let mut complete_signature = vec![recovery_id.to_i32() as u8];
    complete_signature.extend_from_slice(&signature_data);
    Some(zbase32::encode_full_bytes(complete_signature.as_slice()))
}

fn verify_message(message: &str, signature: &str, public_key: PublicKey) -> Option<bool> {
    let secp = Secp256k1::new();
    let signature_bytes = zbase32::decode_full_bytes(signature.as_bytes()).ok()?;
    let recovery_id = RecoveryId::from_i32((signature_bytes[0]) as i32).ok()?;
    let signature_data = &signature_bytes[1..];
    let recoverable_signature = RecoverableSignature::from_compact(signature_data, recovery_id).ok()?;
    let prefixed_message = format!("Lightning Signed Message:{}", message);
    let message_hash = Sha256::digest(&prefixed_message.as_bytes());
    let msg = Message::from_slice(&message_hash).ok()?;
    let recovered_public_key = secp.recover_ecdsa(&msg, &recoverable_signature).ok()?;
    Some(recovered_public_key == public_key)
}

fn main() {
    let message = "Hello, World!";
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    match sign_message(message, secret_key) {
        Some(signature) => {
            println!("Signature: {:?}", signature);
            match verify_message(message, &signature, public_key) {
                Some(is_valid) => println!("Is valid: {}", is_valid),
                None => println!("Failed to verify message."),
            }
        },
        None => println!("Failed to sign message."),
    }
}
