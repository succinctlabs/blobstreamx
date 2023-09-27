use ethers::types::H256;

pub fn convert_to_h256(aunts: Vec<[u8; 32]>) -> Vec<H256> {
    let mut aunts_h256 = Vec::new();
    for aunt in aunts {
        aunts_h256.push(H256::from_slice(&aunt));
    }
    aunts_h256
}

// If hash_so_far is on the left, False, else True
pub fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total - 1;
    let mut current_index = index;
    while current_total >= 1 {
        path_indices.push(current_index % 2 == 1);
        current_total /= 2;
        current_index /= 2;
    }
    path_indices
}

pub fn to_be_bits(msg: Vec<u8>) -> Vec<bool> {
    let mut res = Vec::new();
    msg.iter().for_each(|char| {
        for j in 0..8 {
            if (char & (1 << (7 - j))) != 0 {
                res.push(true);
            } else {
                res.push(false);
            }
        }
    });
    res
}

pub fn to_le_bits(msg: Vec<u8>) -> Vec<bool> {
    let mut res = Vec::new();
    msg.iter().for_each(|char| {
        for j in 0..8 {
            if (char & (1 << j)) != 0 {
                res.push(true);
            } else {
                res.push(false);
            }
        }
    });
    res
}
