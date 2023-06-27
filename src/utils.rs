use plonky2::hash::hash_types::RichField;

pub fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let nb_bytes = if bits.len() % 8 == 0 {
        bits.len() / 8
    } else {
        bits.len() / 8 + 1
    };
    for i in 0..nb_bytes {
        let mut byte = 0;
        for j in 0..8 {
            if i * 8 + j >= bits.len() {
                break;
            }
            byte |= (bits[i * 8 + j] as u8) << j;
        }
        bytes.push(byte);
    }
    bytes
}

pub fn f_bits_to_bytes<F: RichField>(bits: &[F]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let nb_bytes = if bits.len() % 8 == 0 {
        bits.len() / 8
    } else {
        bits.len() / 8 + 1
    };
    for i in 0..nb_bytes {
        let mut byte = 0;
        for j in 0..8 {
            if i * 8 + j >= bits.len() {
                break;
            }
            byte |= (bits[i * 8 + j].to_canonical_u64() << j) as u8;
        }
        bytes.push(byte);
    }
    bytes
}

pub fn bytes_to_le_f_bits<F: RichField>(bytes: &[u8]) -> Vec<F> {
    let mut bits = Vec::new();
    for byte in bytes {
        for i in 0..8 {
            bits.push(F::from_bool((byte >> i) & 1 == 1));
        }
    }
    bits
}
