use super::poly::Polynomial;

pub fn dff(f: Polynomial) {
    let q = 2u128.pow(128);
    let z: Vec<(Polynomial, u32)> = vec![];
    let d = 1;
    let f_start = f.clone();

    while f_start.degree() >= 2 * d {}
}
