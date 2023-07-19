#[allow(unused_variables)]
use bs58;
use zbase32;
use secp256k1::{Secp256k1, Message, SecretKey};
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand;

fn encode_base58(message: &str) -> String {
    let bytes = message.as_bytes();
    bs58::encode(bytes).into_string()
}

pub(crate) fn random_32_bytes<R: rand::Rng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut ret = [0u8; 32];
    rng.fill(&mut ret);
    ret
}

#[allow(unused_variables)]
fn main() {
    let message = "Hello, World!";
    let encoded = encode_base58(message);
    println!("Encoded: {}", encoded);

    let full = Secp256k1::new();
    let mut rng = OsRng::default();
    let (sk, pk) = full.generate_keypair(&mut rand::thread_rng());
    let msg = crate::random_32_bytes(&mut rand::thread_rng());
    let msg = Message::from_slice(&msg).unwrap();
    let sig = full.sign_ecdsa(&msg, &sk);
    let zbase32_encoded = zbase32::encode_full_bytes(message.as_bytes());
    println!("Signature: {:?}", zbase32_encoded);
}
