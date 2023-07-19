use sha2::{Sha256, Digest};
use zbase32;
use secp256k1::{Secp256k1, Message};
use secp256k1::rand;

fn sign_message(message: &str) -> String {
    let message_hash = Sha256::digest(message.as_bytes());

    let secp = Secp256k1::new();
    let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());

    let msg = Message::from_slice(&message_hash).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);

    let (recovery_id, signature_data) = signature.serialize_compact();
    let mut complete_signature = vec![31 + recovery_id.to_i32() as u8];
    complete_signature.extend_from_slice(&signature_data);

    let zbase32_encoded_message = zbase32::encode_full_bytes(message.as_bytes());

    zbase32_encoded_message
}

fn main() {
    let message = "Lighting Signed Message:Hello, World!";
    let signature = sign_message(message);

    println!("Signature: {:?}", signature);
}
