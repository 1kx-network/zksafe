use dep::std;
use std::hash::poseidon;

global TREE_SIZE: u32 = 3;

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

fn hash_values(leaves: [Field; 2]) -> Field {
    let hash = poseidon::bn254::hash_2(leaves);
    hash
}

fn merkle_tree_root<N>(leaf: Field, path_indices: Field, siblings: ([Field; N])) -> Field {
    let index_bits = path_indices.to_be_bits(N);
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hash_values([hash_left, hash_right]);
    }
    current
}

/// Verify if the signatures are valid and the signers are in the owners list.
fn verify_signers<T>(threshold: u8, signers: [PubKey; T], signatures: [Signature; T], txn_hash: Hash, owners_root: Field, indices: [Field; T], siblings: [[Field; TREE_SIZE]; T]) {
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

            // Check that the address is in the merkle tree of owners.   
            let mut result : Field = 0;
            let mut v : Field = 1;
            for k in 0..20 {
                result += address[19 - k] as Field * v;
                v *= 256 as Field;
            }

            let address_hash = poseidon::bn254::hash_1([result]);
            assert(owners_root == merkle_tree_root(address_hash, indices[i], siblings[i]));

            curr_owner = address;
            num_verified_signatures += 1;
        }
    }
    assert(num_verified_signatures >= threshold);
}

fn main(threshold: pub u8, signers: [PubKey; 4], signatures: [Signature; 4], txn_hash: pub Hash, owners_root: pub Field, indices: [Field; 4], siblings: [[Field; TREE_SIZE]; 4]) {
    verify_signers(threshold, signers, signatures, txn_hash, owners_root, indices, siblings);
}


#[test]
fn test_main() {
//nargo test --show-output

    let threshold = 2;
    let signers = [
        PubKey{
            x: [
                53,  71, 134,  16, 177,   4,  15, 133,
                25, 199,  71,  21, 168, 105, 126,  45,
                174, 177,   8, 191, 134,  56,  60, 104,
                78,  23,   8, 132,  62,  37, 207,  80
            ],
            y: [
                200, 250, 119, 110, 103, 174, 120,   3,
                66, 244,  62,  45,  94,  33, 234, 108,
                143, 249,   3, 190, 152, 154, 161,  60,
                191,  83, 145, 205,  71,  52, 134,  30
            ]
        },
        PubKey{
            x: [
                232, 234, 134, 123,  19, 106, 252,
                246, 161, 209, 222, 169, 195,  50,
                143,  95, 254, 160, 200, 129,  37,
                12,   1, 208, 160, 130, 216, 129,
                3, 138, 179,  85
            ],
            y: [
                195,   9, 201, 206, 200,  33, 160, 243,
                48,  88, 110,  63, 183,  75,  81,  49,
                162,  18,  41, 167, 219, 128,  52, 234,
                20, 183, 113, 117, 223, 238,  74,  92
            ]
        },
        PubKey{
            x: [
                121, 190, 102, 126, 249, 220, 187, 172,
                85, 160,  98, 149, 206, 135,  11,   7,
                2, 155, 252, 219,  45, 206,  40, 217,
                89, 242, 129,  91,  22, 248,  23, 152
            ],
            y: [
                72,  58, 218, 119,  38, 163, 196, 101,
                93, 164, 251, 252,  14,  17,   8, 168,
                253,  23, 180,  72, 166, 133,  84,  25,
                156,  71, 208, 143, 251,  16, 212, 184
            ]
        },
        PubKey{
            x: [
                121, 190, 102, 126, 249, 220, 187, 172,
                85, 160,  98, 149, 206, 135,  11,   7,
                2, 155, 252, 219,  45, 206,  40, 217,
                89, 242, 129,  91,  22, 248,  23, 152
            ],
            y: [
                72,  58, 218, 119,  38, 163, 196, 101,
                93, 164, 251, 252,  14,  17,   8, 168,
                253,  23, 180,  72, 166, 133,  84,  25,
                156,  71, 208, 143, 251,  16, 212, 184
            ]
        }
    ];
    let signatures = [
        [
            32, 162, 72, 137,  45,  72,  57,  17, 233,  39, 26,
            157, 193, 46, 218,  17, 247, 154, 225, 125, 177, 24,
            169, 178, 82,  53, 217,  48, 223, 176, 222,  92, 73,
            110, 121, 27,  50, 197,  18,  12, 206, 225,  78,  9,
            91,  87, 41,  43, 242,  87,  72,  32, 168,  86, 10,
            13,  35, 15, 188,  30, 188,  98, 188,  99
        ],
        [
            243,  74, 103, 247,  32, 179, 192, 114, 155, 138, 221,
            197, 148, 242, 153,  95,  22,  16, 195, 184, 204,  10,
            170,  21, 140,  36, 111,  57, 164, 162,  56,  50,  47,
            123,  58,   9,  57, 197, 201, 102, 246, 249, 184,  84,
            69, 116, 146, 117, 152, 227, 149,  66, 201,  60, 214,
            40,  84, 230, 230, 197, 224, 192, 210, 170
        ],

        [
            121, 190, 102, 126, 249, 220, 187, 172,  85, 160,  98,
            149, 206, 135,  11,   7,   2, 155, 252, 219,  45, 206,
            40, 217,  89, 242, 129,  91,  22, 248,  23, 152,  72,
            58, 218, 119,  38, 163, 196, 101,  93, 164, 251, 252,
            14,  17,   8, 168, 253,  23, 180,  72, 166, 133,  84,
            25, 156,  71, 208, 143, 251,  16, 212, 184
        ],
        [
            121, 190, 102, 126, 249, 220, 187, 172,  85, 160,  98,
            149, 206, 135,  11,   7,   2, 155, 252, 219,  45, 206,
            40, 217,  89, 242, 129,  91,  22, 248,  23, 152,  72,
            58, 218, 119,  38, 163, 196, 101,  93, 164, 251, 252,
            14,  17,   8, 168, 253,  23, 180,  72, 166, 133,  84,
            25, 156,  71, 208, 143, 251,  16, 212, 184
        ]
    ];
    let txn_hash = [
        178, 111, 145, 229, 128, 135, 100,
        239, 206, 128, 108, 143, 251, 138,
        50, 167, 200, 245, 167, 208, 233,
        229,  82,  89, 192, 177,  67, 118,
        253, 234,  21,  13

    ];
    let owners_root = 17897203097150046839921532379502770926277654824102125397176958523092682054867;
    let indices = [ 0, 4, 0, 0 ];
    let siblings =  [
       
        [
        17977818632254850994499563799926012671831968850897273284027183264605336003045,
        1497638773132338639532317295234201546636355065065018781026914885146950983393,
        12386614053368250862402026605703981421752319129480328092916744368761112006403,
        ],
         [
        703436641212405272137913002671072418472058081051457094174645100911872532801,
        1497638773132338639532317295234201546636355065065018781026914885146950983393,
        12386614053368250862402026605703981421752319129480328092916744368761112006403,
        ],
        [ 0, 0, 0],
        [ 0, 0, 0]
    ];

    main(threshold, signers, signatures, txn_hash, owners_root, indices, siblings)
}