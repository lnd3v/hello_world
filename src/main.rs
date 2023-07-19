#[allow(unused_imports)]
use secp256k1::hashes::hex::FromHex;
#[allow(unused_imports)]
use secp256k1::rand::Rng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zbase32;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::rand;

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
    let recoverable_signature =
        RecoverableSignature::from_compact(signature_data, recovery_id).ok()?;
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
        }
        None => println!("Failed to sign message."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::rand;
    use secp256k1::Secp256k1;

    #[test]
    fn test_message_signing_and_verification_succeeds() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        match sign_message(message, secret_key) {
            Some(signature) => match verify_message(message, &signature, public_key) {
                Some(is_valid) => assert!(is_valid, "Expected valid signature."),
                None => panic!("Failed to verify message."),
            },
            None => panic!("Failed to sign message."),
        }
    }

    #[test]
    fn test_message_signing_and_verification_fails_with_wrong_key() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, _public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let (_, wrong_public_key) = secp.generate_keypair(&mut rand::thread_rng());

        match sign_message(message, secret_key) {
            Some(signature) => match verify_message(message, &signature, wrong_public_key) {
                Some(is_valid) => assert!(!is_valid, "Expected invalid signature with wrong key."),
                None => panic!("Failed to verify message."),
            },
            None => panic!("Failed to sign message."),
        }
    }

    #[test]
    fn test_message_verification_from_external_source() {
        let message = "Hello, World!";
        let signature = "dhjauydce4y44id1u7j4a7wa7amw971e9cs56s6pyycysg41jar3shnii641xpjw4b7ttgsqmu3s89wiryawyebuircuhw3umqj7cfzm";

        // Convert the provided hex string into a public key
        let public_key_data = Vec::<u8>::from_hex(
            "037774907be58f0a9f391dfafbee159658c83948c9f06644ddc658dafcb0c44831",
        )
        .unwrap();
        let external_public_key = PublicKey::from_slice(&public_key_data).unwrap();

        match verify_message(message, signature, external_public_key) {
            Some(is_valid) => assert!(is_valid, "Expected valid signature from external source."),
            None => panic!("Failed to verify message."),
        }
    }

    #[test]
    fn test_empty_message() {
        let message = "";
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let signature = sign_message(message, secret_key).expect("Failed to sign empty message");
        let is_valid = verify_message(message, &signature, public_key)
            .expect("Failed to verify empty message");
        assert!(is_valid);
    }

    #[test]
    fn test_long_message() {
        let message = "a".repeat(1000);
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let signature = sign_message(&message, secret_key).expect("Failed to sign long message");
        let is_valid = verify_message(&message, &signature, public_key)
            .expect("Failed to verify long message");
        assert!(is_valid);
    }

    #[test]
    fn test_non_ascii_message() {
        let message = "こんにちは, 世界!";
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let signature =
            sign_message(message, secret_key).expect("Failed to sign non-ASCII message");
        let is_valid = verify_message(message, &signature, public_key)
            .expect("Failed to verify non-ASCII message");
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature_format() {
        let message = "Hello, World!";
        let invalid_signature = "invalid_signature";
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let is_valid = verify_message(message, invalid_signature, public_key);
        assert!(
            is_valid.is_none(),
            "Expected None result with invalid signature format"
        );
    }

    #[test]
    fn test_message_tampering() {
        let message = "Hello, World!";
        let tampered_message = "H3llo, World!";
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    
        let signature = sign_message(message, secret_key).expect("Failed to sign message");
    
        let verify_res = verify_message(tampered_message, &signature, public_key);
        assert!(verify_res.unwrap() == false, "Expected verification to fail with tampered message");
    }
    

    #[test]
    fn test_public_key_tampering() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, public_key_data) = secp.generate_keypair(&mut rand::thread_rng());

        // Convert public key to bytes and tamper the data
        let mut public_key_bytes = public_key_data.serialize();
        public_key_bytes[0] ^= 0x01; // Flip the first bit
        let tampered_public_key = PublicKey::from_slice(&public_key_bytes).unwrap();

        let signature = sign_message(message, secret_key).expect("Failed to sign message");
        let is_valid = verify_message(message, &signature, tampered_public_key);
        assert!(
            is_valid.unwrap() == false,
            "Expected false result with tampered public key"
        );
    }

    #[test]
    fn test_random_messages() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let rng = rand::thread_rng();

        for _ in 0..1000 {
            let message: String = rng
                .clone()
                .sample_iter(rand::distributions::Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let signature = sign_message(&message, secret_key).expect("Failed to sign message");
            let is_valid =
                verify_message(&message, &signature, public_key).expect("Failed to verify message");
            assert!(is_valid, "Failed to verify random message");
        }
    }

    #[test]
    fn test_recovery_of_public_key() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, original_public_key) = secp.generate_keypair(&mut rand::thread_rng());
    
        let signature = sign_message(message, secret_key).expect("Failed to sign message");
        let prefixed_message = format!("Lightning Signed Message:{}", message);
        let message_hash = Sha256::digest(&prefixed_message.as_bytes());
        let msg = Message::from_slice(&message_hash).unwrap();
        let signature_bytes = zbase32::decode_full_bytes(signature.as_bytes()).unwrap();
        let recovery_id = RecoveryId::from_i32((signature_bytes[0]) as i32).unwrap();
        let signature_data = &signature_bytes[1..];
        let recoverable_signature = RecoverableSignature::from_compact(signature_data, recovery_id).unwrap();
        let recovered_public_key = secp.recover_ecdsa(&msg, &recoverable_signature).unwrap();
    
        assert_eq!(original_public_key, recovered_public_key, "Failed to recover public key");
    }
    

    #[test]
    fn test_different_private_keys() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let (secret_key, public_key) = secp.generate_keypair(&mut rng);
            let signature = sign_message(&message, secret_key).expect("Failed to sign message");
            let is_valid =
                verify_message(&message, &signature, public_key).expect("Failed to verify message");
            assert!(
                is_valid,
                "Failed to verify message with different private key"
            );
        }
    }

    #[test]
    fn test_same_message_different_signatures() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key_1, _) = secp.generate_keypair(&mut rand::thread_rng());
        let (secret_key_2, _) = secp.generate_keypair(&mut rand::thread_rng());
        
        let signature_1 = sign_message(message, secret_key_1).expect("Failed to sign message");
        let signature_2 = sign_message(message, secret_key_2).expect("Failed to sign message");
    
        assert_ne!(signature_1, signature_2, "Expected different signatures for different keys");
    }
    

    #[test]
    fn test_deterministic_signatures() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
    
        let signature_1 = sign_message(message, secret_key).expect("Failed to sign message");
        let signature_2 = sign_message(message, secret_key).expect("Failed to sign message");
    
        assert_eq!(signature_1, signature_2, "Expected the same signature for the same key and message");
    }    

    #[test]
    fn test_signature_tampering() {
        let message = "Hello, World!";
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
    
        let signature = sign_message(message, secret_key).expect("Failed to sign message");
    
        let mut tampered_signature = signature.clone().into_bytes();
        if let Some(byte) = tampered_signature.get_mut(0) {
            *byte ^= 0x01; // Flip the first bit
        }
    
        let verify_res = verify_message(message, &String::from_utf8(tampered_signature).unwrap(), public_key);
        assert!(verify_res.is_none(), "Expected None result with tampered signature");
    }
    
}
