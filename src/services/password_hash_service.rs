use std::ops::Add;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

pub struct PasswordHashService;

impl PasswordHashService {
    pub fn create_new_hash(input: impl Into<String>) -> String {
        let salt: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();

        let hash_target = input.into().add(&*salt);

        let mut hasher = Sha256::new();
        hasher.update(hash_target);
        let hash_output = hasher.finalize();
        let hash_part = format!("{:x}", hash_output);

        format!("$01${}${}$", salt, hash_part)
    }

    pub fn verify(hash: impl Into<String>, password: impl Into<String>) -> bool {
        let hash = hash.into();
        let mut hash_parts = hash.split('$');
        hash_parts.next();

        let _version = hash_parts.next().unwrap();
        let salt = hash_parts.next().unwrap();
        let hash = hash_parts.next().unwrap();

        let hash_target = password.into().add(salt);
        let mut hasher = Sha256::new();
        hasher.update(hash_target);
        let hash_output = hasher.finalize();
        let hash_part = format!("{:x}", hash_output);

        hash == hash_part
    }
}
