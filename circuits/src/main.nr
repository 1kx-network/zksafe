use dep::std;

type Address = [u8; 20];
type Signature = [u8; 64];
type Hash = [u8; 32];
struct  PubKey {
    x: [u8; 32],
    y: [u8; 32],
}

/// Compare two arrays of bytes, return true if a > b.
fn cmp_gt<N>(a: [u8; N], b: [u8; N]) -> bool {
    let mut result = false;
    let mut done = false;
    for i in 0..N {
        if !done {
            if a[i] > b[i] {
                result = true;
                done = true;
            } else if a[i] < b[i] {
                result = false;
                done = true;
            }
        }
    }
    result
}

/// Verify if the signatures are valid and the signers are in the owners list.
fn verify_signers<T, N>(signers: [PubKey; T], signatures: [Signature; T], hash: Hash, owners: [Address; N]) {
    let mut curr_owner = [0; 20];
    for i in 0..T {
        if (signers[i].x != [0; 32]) & (signers[i].y != [0; 32]) {
            assert(std::ecdsa_secp256k1::verify_signature(signers[i].x, signers[i].y, signatures[i], hash));
            let mut uncompressed_pubkey = [0; 64];
            for j in 0..32 {
                uncompressed_pubkey[j] = signers[i].x[j];
                uncompressed_pubkey[j + 32] = signers[i].y[j];
            }
            let pubkey_hash = std::hash::keccak256(uncompressed_pubkey, 64);
            let mut address: Address = [0; 20];
            for j in 0..20 {
                address[j] = pubkey_hash[j + 12];
            }
            assert(cmp_gt(address, curr_owner));
            let mut found = false;
            for j in 0..N {
                if address == owners[j] {
                   found = true;
               }
           }
           assert(found);
           curr_owner = address;
        }
    }
}

fn main(signers: [PubKey; 3], signatures: [Signature; 3], hash: pub Hash, owners: pub [Address; 6]) {
    verify_signers(signers, signatures, hash, owners);
}
