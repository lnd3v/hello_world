#[allow(unused_variables)]
use sha2::{Sha256, Digest};
use zbase32;
use secp256k1::{Secp256k1, Message};
use secp256k1::rand;

#[allow(unused_variables)]
fn main() {
    let message = "Lighting Signed Message:Hello, World!";
    let msg_hash = Sha256::digest(&message.as_bytes());

    let full = Secp256k1::new();
    let (sk, pk) = full.generate_keypair(&mut rand::thread_rng());
    let msg = Message::from_slice(&msg_hash).unwrap();
    let sig = full.sign_ecdsa_recoverable(&msg, &sk);
    let (recovery_id, sig_data) = sig.serialize_compact();
    let mut signature = vec![31 + recovery_id.to_i32() as u8];
    signature.extend(sig_data.iter());
    let zbase32_encoded = zbase32::encode_full_bytes(message.as_bytes());
    println!("Signature: {:?}", zbase32_encoded);
}
