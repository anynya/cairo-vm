use core::hash::HashStateTrait;
use core::pedersen::PedersenTrait;
use core::poseidon::PoseidonTrait;

#[derive(Drop)]
struct BinaryNode {
    left: felt252,
    right: felt252,
}

#[derive(Drop, Copy)]
struct EdgeNode {
    child: felt252,
    path: felt252,
    length: u8,
}

#[derive(Drop)]
enum TrieNode {
    Binary: BinaryNode,
    Edge: EdgeNode,
}

#[derive(Destruct)]
struct ContractData {
    class_hash: felt252,
    nonce: felt252,
    contract_state_hash_version: felt252,
    storage_proof: Array<TrieNode>
}

#[derive(Destruct)]
struct ContractStateProof {
    class_commitment: felt252,
    contract_proof: Array<TrieNode>,
    contract_data: ContractData
}

/// Verify Starknet storage proof. For reference see:
/// - ([state](https://docs.starknet.io/documentation/architecture_and_concepts/State/starknet-state/))
/// - ([pathfinder_getproof API endpoint](https://github.com/eqlabs/pathfinder/blob/main/doc/rpc/pathfinder_rpc_api.json))
/// - ([pathfinder storage implementation](https://github.com/eqlabs/pathfinder/blob/main/crates/merkle-tree/src/tree.rs))
/// # Arguments
/// * `expected_state_commitment` - state root `proof` is going to be verified against
/// * `contract_address` - `contract_address` of the value to be verified
/// * `storage_address` - `storage_address` of the value to be verified
/// * `proof` - `ContractStateProof` representing storage proof
/// # Returns
/// * `felt252` - `value` at `storage_address` if verified, panic otherwise.
fn verify(
    expected_state_commitment: felt252,
    contract_address: felt252,
    storage_address: felt252,
    proof: ContractStateProof
) -> felt252 {
    let contract_data = proof.contract_data;

    let (contract_root_hash, storage_value) = traverse(
        storage_address, contract_data.storage_proof
    );

    let contract_state_hash = pedersen_hash_4(
        contract_data.class_hash,
        contract_root_hash,
        contract_data.nonce,
        contract_data.contract_state_hash_version
    );

    let (contracts_tree_root, expected_contract_state_hash) = traverse(
        contract_address, proof.contract_proof
    );

    assert(expected_contract_state_hash == contract_state_hash, 'wrong contract_state_hash');

    let state_commitment = poseidon_hash(
        'STARKNET_STATE_V0', contracts_tree_root, proof.class_commitment
    );

    assert(expected_state_commitment == state_commitment, 'wrong state_commitment');

    storage_value
}

fn traverse(expected_path: felt252, proof: Array<TrieNode>) -> (felt252, felt252) {
    let mut nodes = proof.span();
    let expected_path_u256: u256 = expected_path.into();

    let leaf = *match nodes.pop_back().unwrap() {
        TrieNode::Binary(_) => panic!("invalid leaf type"),
        TrieNode::Edge(edge) => edge
    };

    let mut expected_hash = node_hash(@TrieNode::Edge(leaf));
    let value = leaf.child;
    let mut path = leaf.path;
    let mut path_length_pow2 = pow(2, leaf.length);

    loop {
        match nodes.pop_back() {
            Option::Some(node) => {
                match node {
                    TrieNode::Binary(binary_node) => {
                        if expected_path_u256 & path_length_pow2.into() > 0 {
                            assert(expected_hash == *binary_node.right, 'invalid node hash');
                            path += path_length_pow2;
                        } else {
                            assert(expected_hash == *binary_node.left, 'invalid node hash');
                        };
                        path_length_pow2 *= 2;
                    },
                    TrieNode::Edge(edge_node) => {
                        assert(expected_hash == *edge_node.child, 'invalid node hash');
                        path += *edge_node.path * path_length_pow2;
                        path_length_pow2 *= pow(2, *edge_node.length);
                    }
                }
                expected_hash = node_hash(node);
            },
            Option::None => { break; }
        };
    };
    assert(expected_path == path, 'invalid proof path');
    (expected_hash, value)
}

#[inline]
fn node_hash(node: @TrieNode) -> felt252 {
    match node {
        TrieNode::Binary(binary) => pedersen_hash(*binary.left, *binary.right),
        TrieNode::Edge(edge) => pedersen_hash(*edge.child, *edge.path) + (*edge.length).into()
    }
}

// TODO: replace with lookup table once array constants are available in Cairo
fn pow(x: felt252, n: u8) -> felt252 {
    if n == 0 {
        1
    } else if n == 1 {
        x
    } else if (n & 1) == 1 {
        x * pow(x * x, n / 2)
    } else {
        pow(x * x, n / 2)
    }
}

#[inline(always)]
fn pedersen_hash(a: felt252, b: felt252) -> felt252 {
    PedersenTrait::new(a).update(b).finalize()
}

#[inline(always)]
fn pedersen_hash_4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    PedersenTrait::new(a).update(b).update(c).update(d).finalize()
}

#[inline(always)]
fn poseidon_hash(a: felt252, b: felt252, c: felt252) -> felt252 {
    PoseidonTrait::new().update(a).update(b).update(c).finalize()
}

fn balance_proof() -> ContractStateProof {
    // func _balances(user : felt) -> (res : Uint256):
    // get_storage_var_address('_balances', 0x063c94d6B73eA2284338f464f86F33E12642149F763Cd8E76E035E8E6A5Bb0e6)
    // storage_address = 0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ee
    // ./get_storage_proof.sh 0x02f63993df97fb44439d8e2e999c8b9b51efba1eff78e5c994c709c82b442e65 \
    //     0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3 \
    //     0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ee

    ContractStateProof {
        class_commitment: 0x5eed4c30c17df1a41905c9824f2a296b6f77e91f0f017290752a60fbb8f9ff7,
        contract_proof: array![
            TrieNode::Binary(
                BinaryNode {
                    left: 0x74b59299e8315ce3c9d679b0a439f8bd6d55f1f7544b98852c85c953ec57e8,
                    right: 0x2390819e385bb1876e077b5ed4a4bae52c0e16ae7efee4c889c3d5247f6fb60,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x5ef3be75d230f16f9f62058cd51f33fe511f132400e24ede72fe931d9afcd59,
                    right: 0x404d825da685c12746a2b2b7089c13561135ac529a6624b848951993331de4f,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x5cbf312528ca49ab9012f368994adcb85f778360c68d61ddfa94e5db04e39bf,
                    right: 0x4df940db2395b5a8929cf658e36b45e88431aa9b0a1513e5318d81e83af66ca,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x5e002697a7591f4cb36f024142c249493ea69f2820aae9842b085d9cd20a825,
                    right: 0x78e4c02f55114f6b4989788d52e2d03bd3416f720d090215a7f95d1178166c6,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x4ad60a445f0a47f285861868f332f310b405acc3366a44483b534daefc4061b,
                    right: 0x4a3bff604eb492f216f053a8756d7c3cb2f80649c4a3fea7d5ed939b24c784c,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x316045f83427fc1a617bb370fa2b1a7a03d462b264729424f52c6ae00e1f71a,
                    right: 0x7ca38911fbfba4481ea60591a97b01861825c1f908dd7fc3141192b79b55d43,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x17bf798cac821552f0e3d804dd9876e286c63d64d64aca19aea00ea9110ff58,
                    right: 0x33b2593a0e40d4ed0ddb6d8b7b824a2bde13062dc405c2394a8a797c35b4b32,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x1a78b3285e1f816ec7fdeeecbd7de855c3fe50e49cb9d294c0fbe698a8f0964,
                    right: 0x737aebdf31cbf55171144bd658e0e82862541b0af78d3241e13de77015f1ce3,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x7267f91ecdc6e579864613a406750bc80363a2be5ff863f020e5531eb8d947a,
                    right: 0x65bcc933abbb3c71cf3edd535204f34eb58a7329a53688039733420571f45fc,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0xac490c5cda65c26fe042c08d9bec48f399db1b0c551eb3fcbcf5fc51643beb,
                    right: 0x574edd4ea6655ada56844d7b7797af4fb66fa8e86361ee201d817de885ab751,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x54407ae16b65fd67d64fc8528f7240cd4c6914041dd9e3bf7c56cbab58eb42e,
                    right: 0x5e7d51e63c8c33f864418dd61e720cfcda9363d9b6b1c5de11f68b2d0a9a448,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x4550dba3e8b473bc2b4cc6c99c43ec90864930f4ec06affb267f24ad16df0b5,
                    right: 0x545515cd797a277cdb88ab7efaa63ea979220696e51c6173de23984ff1746c4,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x14fa907e7e9633b6f3dcabfe07e8dac02e0aea480949bfd0f8dea13ecb5c50c,
                    right: 0x5448b1aac9acedab60b5401d6330bfabd397f1086ab42948ed1fa81e38a2157,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x1139a46c5e89fbcc483b8726d3e7707122b57ccdf955df4216cb1a93ffffd7a,
                    right: 0x6729ff6fec2dfcc6535bc4eea26fc4eb65e0285d4f8ae0fe6be4c343d9bb720,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x3d7dcabc79ce522ffb88b167edfd51896a6430a456250290f2ac1cdbe6572b3,
                    right: 0x990164dd962c5d48dd9a98cd8845bfdd483cbc07bbbfcd2c19daee84992e28,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x59cc416528b7228ed0064a393ed60462f5e556d5a236f7b94ea8d510641cd64,
                    right: 0x325c342f00e73f97c8a1ff2462c754dbb27b967223954f690e1d069e5088599,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x3c976052cb6c461679e159c1b711e8d0261d240745931ea399edf389848f99d,
                    right: 0x4f65e0c2b833c972c02ad133e6aa152a6e9d15bca277c2b163bc09c8b2e2b1c,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x338b6575ed50d84769024e54decfde68968be33bb266f1faa0a0fd9157e47e9,
                    right: 0x130c2fd7a701ec84b9ef42c9a45cb115581c268de360db13e748c1c2c62cc03,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x57a2288b799d131ce7d6c934ce288e5dcc72214871e92f25420d6cb70de6f57,
                    right: 0x3be816d1fe67968529d322c2d550b3968dc846a938d4878c97f3e974c17f9b,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x14f24c1f2b88d01188f4d72cfe1857668cb5507a92516cf356a618363aa369c,
                    right: 0x19a3203d5b1ec5a02c56f8672694f766a2a1f073430cca00362b71b19dc71f2,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x2b54c34d1145942663561aba685c1afd12e991739a30d109fdbe17ff1416f60,
                    right: 0x547e87abcc29a44e0f57f5bd4c9ca5bddb73a8a24ef1faf188aab963158df04,
                }
            ),
            TrieNode::Binary(
                BinaryNode {
                    left: 0x412b79bf0b5c3ac8eeca6ffc739aa9c48a0fb9834f9f683ef75400023547ea4,
                    right: 0x412022f2d1d47198766e74d76a6933348a922727170ed03c6a73b1c854bc11f,
                }
            ),
            TrieNode::Edge(
                EdgeNode {
                    path: 0x221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3,
                    length: 229,
                    child: 0x1fe7bef4bd2a37b56eab84508f217fd2a85694bbeb95e98049faa0de0a2011c,
                }
            )
        ],
        contract_data: ContractData {
            class_hash: 0x1cb96b938da26c060d5fd807eef8b580c49490926393a5eeb408a89f84b9b46,
            nonce: 0x0,
            contract_state_hash_version: 0,
            storage_proof: array![
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x5b1f6f4ba862f9d83fb1c6cbfc8ab6ccf8864ff40f9cd1e86b653978b7da18e,
                        right: 0x6a14610de840e87de4c10fca04caa9fe93f854b6e3dd528dde1eedddf0ce84,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x1e43960a3be85b1ad5a3b198617b0740b684e87a44e9e688f39cfa491cda57a,
                        right: 0x51ae9c0371c2f844155d26505bb26cf312e37aeae8e5610135579225c63b78e,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x418949d2696cf64b33ea5f45d97bd2b21a0a664bebf96321902a01cd3b48d2a,
                        right: 0x6fd4f5c829467a9ceeb891549993fb83b8003588d8c8cff156bd1c099dbc5ef,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x7d07c08fa0f20455453f16b278ca6f710553339a2dbb8f58e15925a6217643,
                        right: 0x47129129d16cb646a2c34f7c9c067c9acaad81b6839b6fc09e8b80c34bebde7,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x175c91990d2333c3de3f370030f901f1872a24aa5f6da397a213e2a5b0d16b9,
                        right: 0x65a68f50434c58e521c95a1397ed91a10eed6e0aa2c417ca08d54caf39a0708,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x4849c87d07ba2a2b8349c3bf55638b549888e9c04f42220f1df86aa41483a8b,
                        right: 0x19f7fc3721a344be4598e7973ee3b1b5fb1451b4d7d7bab65d6f9528ad171cc,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x68eac761b78dc264977294b7d2971160597048591ddd82a566c69f084d35843,
                        right: 0x384b4f58bf7f2cad7d361fc4f39061e9441f61053cb92aa4ca7591c1d2ce332,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x8530109039a3265f9bed7d53935d934d8b3c243559c824f936212d82568d7,
                        right: 0x609f90d6f706eb20ed763dda2409b873303257a4bd21efec3f0cef4f1e1bb15,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x214a3f760450952ded394c66f9e771c743c8fc1b94408c3d75d7218e3c4ea0d,
                        right: 0x4acaaa512264bfad4c4fae98f7ffc61af4ab6ef12f691a93eb77498e28bd981,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x132a39f6d01334cea3f78df8fc6562de3b12ecbb59c039c04d5114dcc786e4f,
                        right: 0x589c451d11284e28647bd8f69cc52316340bdbb06cc8dfd3e58693521867b8f,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x283b8a927ca6f39030687e134a0fbb62581152c8c356c39398c10d6439137b4,
                        right: 0x26c8829289038b3fd39cbb84a77d5b581d207b02da385fd6bdb784831b7042c,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x5a6263b13773bb2b02b60016825a626f4811d6f4a2015de7c6b1a34475ae518,
                        right: 0x74de5b7ad01a7652cb6f8bdd7eec2087063cd4c1c9774d8c571f42de2de790e,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x19dc54d0aadb395e9592f85ed9ba3766e8427c20ed1511ad626ebfbf61c3f03,
                        right: 0x260370da71cc1846829b69960e450b73a2f0155e2e4a9c2bee14246696c5e20,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x14e0a63dd9f386828c7af13462d186926013c4c21c0665540a7cdbaf8129998,
                        right: 0x22fb7449e5d36d92fedc78b6748bbd197ea244a7154b2535efa1cd83d8922ee,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x4ad9584d03093e399559c74959224dbc546d4fd5645a04663717e7f26e1ae73,
                        right: 0x1c6e23d891ecf1b564372671373a1fb6c532be0125891e8aaafe8426e9795d8,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x9ac60824ab502ac8be539b6dfeb05a3f71b74e948388bf5eb739fa53481afd,
                        right: 0x696b378cb1848e77e9ceaab566a5f42dde26de2fd5cfcbaa2fd97d03aeea47,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x46a09c16ff0771585b796f48e96ddc36e7916b397c7cbd60de12618c427552d,
                        right: 0x12842effc2e3ad5ef995ec99f002b6540049f1368187625c08086a83523fe73,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x70854f31bd97611b9896baad3d44f7de4fc20d4ab1fd4a62fb4fa7eebb2affc,
                        right: 0x518745f6fb6490d53796a377b1c04923a58041d8c8063fcd6d2d3c7e7b06d19,
                    }
                ),
                TrieNode::Edge(
                    EdgeNode {
                        path: 0x3,
                        length: 2,
                        child: 0x1c5f3e73c9e969b9c5a621955d4813de68ca42a777fd4915ac5e71a73219893,
                    }
                ),
                TrieNode::Binary(
                    BinaryNode {
                        left: 0x59e2516845b39a0f0771e257685ac06e3c3f1f479825521be982162dd249b24,
                        right: 0x1e4a53612070bf13d7677c61cb5448713d8479d57fba3d50059227d57ba0522,
                    }
                ),
                TrieNode::Edge(
                    EdgeNode {
                        path: 0x108cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ee,
                        length: 230,
                        child: 0x78bc9be7c9e60005,
                    }
                )
            ],
        }
    }
}

const DAI: felt252 = 0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3;

fn main() -> bool {
    let state_commitment = 0x07dc88984a2d8f9c2a6d2d431b2d8f2c32957da514c16ceef0761b6933121708;
    let contract_address = DAI;
    let storage_address = 0x4ae51d08cd202d1472587dfe63dbf2d5ec767cbf4218b59b7ab71956780c6ef;
    let expected_value = 8700000000000000005;
    let proof = balance_proof();
    let value = verify(state_commitment, contract_address, storage_address, proof);
    assert(expected_value == value, 'wrong value');
    true
}
