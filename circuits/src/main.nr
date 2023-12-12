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
fn verify_signers<T, N>(threshold: u8, signers: [PubKey; T], signatures: [Signature; T], txn_hash: Hash, owners: [Address; N]) {
    let mut curr_owner = [0; 20];
    let mut num_verified_signatures = 0;
    // We use the generator point of the secp256k1 curve as the NIL value.
    let g_x = [121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152];
    let g_y = [72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184];
    for i in 0..T {
        // check only if the signature is not NIL
        if (signers[i].x != g_x) & (signers[i].y != g_y) {
            // First, check that it verifies
            assert(std::ecdsa_secp256k1::verify_signature(signers[i].x, signers[i].y, signatures[i], txn_hash));
            // Then, find the address to which the verifying key corresponds.
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
            // Check the uniquiness of each signature by requiring and asserting they are sorted in strictly increasing order.
            // We need this to avoid the same signature being used mulitple times.
            // (Check Safe verification code for more details - it does the same checking).
            assert(cmp_gt(address, curr_owner));
            // Check that the address is in the list of owners.
            let mut found = false;
            for j in 0..N {
                if address == owners[j] {
                   found = true;
               }
           }
           assert(found);
           curr_owner = address;
           num_verified_signatures += 1;
        }
    }
    assert(num_verified_signatures >= threshold);
}

fn main(threshold: pub u8, signers: [PubKey; 3], signatures: [Signature; 3], txn_hash: pub Hash, owners: pub [Address; 6]) {
    verify_signers(threshold, signers, signatures, txn_hash, owners);
}
