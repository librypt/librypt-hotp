#![no_std]
#![forbid(unsafe_code)]

use librypt_hash::HashFn;
use librypt_mac::MacFn;
use librypt_mac_hmac::Hmac;

pub struct Hotp<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>> {
    hmac: Hmac<BLOCK_SIZE, HASH_SIZE, H>,
}

impl<const BLOCK_SIZE: usize, const HASH_SIZE: usize, H: HashFn<BLOCK_SIZE, HASH_SIZE>>
    Hotp<BLOCK_SIZE, HASH_SIZE, H>
{
    pub fn new(secret: &[u8]) -> Self {
        Self {
            hmac: Hmac::new(secret),
        }
    }

    pub fn generate(&mut self, counter: u64, digits: u32) -> u32 {
        self.hmac.update(&counter.to_be_bytes());

        let mac = self.hmac.finalize_reset();

        let offset = (mac[mac.len() - 1] & 0xf) as usize;
        let bin_code: u32 = ((mac[offset] & 0x7f) as u32) << 24
            | ((mac[offset + 1] & 0xff) as u32) << 16
            | ((mac[offset + 2] & 0xff) as u32) << 8
            | ((mac[offset + 3] & 0xff) as u32);

        bin_code % 10u32.pow(digits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use librypt_hash_sha1::Sha1;

    #[test]
    fn test_hotp() {
        let mut otp = Hotp::<64, 20, Sha1>::new(b"12345678901234567890");

        assert_eq!(otp.generate(0, 6), 755224);
    }
}
