use sha2::{Sha256, Digest};
use zbase32;
use secp256k1::{Secp256k1, Message, SecretKey};
use secp256k1::rand;

fn sign_message(message: &str, secret_key: SecretKey) -> String {
    let secp = Secp256k1::new();
    
    let prefixed_message = format!("Lightning Signed Message:{}", message);
    let message_hash = Sha256::digest(prefixed_message.as_bytes());
    
    let msg = Message::from_slice(&message_hash).unwrap();
    let signature = secp.sign_ecdsa_recoverable(&msg, &secret_key);

    let (recovery_id, signature_data) = signature.serialize_compact();
    let mut complete_signature = vec![recovery_id.to_i32() as u8];
    complete_signature.extend_from_slice(&signature_data);

    let zbase32_encoded_signature = zbase32::encode_full_bytes(complete_signature.as_slice());

    zbase32_encoded_signature
}

fn main() {
    let message = "Hello, World!";
    let secp = Secp256k1::new();
    let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());
    let signature = sign_message(message, secret_key);

    println!("Signature: {:?}", signature);
}
