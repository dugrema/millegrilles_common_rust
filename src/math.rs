/// Compte le nombre de chiffres dans la partie fractionnaire d'un f64
pub fn compter_fract_digits(nombre: f64) -> u8 {
    let str_nombre = nombre.to_string();
    match str_nombre.find(".") {
        Some(position_pt) => {
            (str_nombre.len() - position_pt - 1) as u8
        },
        None => 0
    }
}

/// Arrondis un nombre f64 au nombre de chiffres specifies pour la partie fractionnaire
pub fn arrondir(value: f64, fract: i32) -> f64 {
    let val_fract = 10_f64.powi(fract);
    (value * val_fract).round() / val_fract
}
