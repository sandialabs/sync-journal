use crate::evaluator as s7;
use crate::evaluator::Primitive;
use std::panic;

use crystals_dilithium::dilithium2::*;
use crystals_dilithium::sign::lvl2::*;
use sha2::{Digest, Sha256};

unsafe fn bv2vec(bv: s7::s7_pointer) -> Vec<u8> {
    let mut vec = vec![];
    for i in 0..s7::s7_vector_length(bv) {
        vec.push(s7::s7_byte_vector_ref(bv, i as i64))
    }
    vec
}

unsafe fn vec2bv(sc: *mut s7::s7_scheme, vec: Vec<u8>) -> s7::s7_pointer {
    let bv = s7::s7_make_byte_vector(sc, vec.len() as i64, 1, std::ptr::null_mut());
    for i in 0..vec.len() {
        s7::s7_byte_vector_set(bv, i as i64, vec[i]);
    }
    bv
}

unsafe fn crypto_error(sc: *mut s7::s7_scheme) -> s7::s7_pointer {
    s7::s7_error(
        sc,
        s7::s7_make_symbol(sc, c"crypto-error".as_ptr()),
        s7::s7_list(
            sc,
            1,
            s7::s7_make_string(
                sc,
                c"cryptographic library encountered unexpected error".as_ptr(),
            ),
        ),
    )
}

pub fn primitive_s7_crypto_generate() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let seed = s7::s7_car(args);

        if !s7::s7_is_byte_vector(seed) {
            return s7::s7_wrong_type_arg_error(
                sc,
                c"crypto-sign".as_ptr(),
                1,
                seed,
                c"a byte-vector".as_ptr(),
            );
        }

        let seed_vec = bv2vec(seed);
        let digest_vec = Sha256::digest(seed_vec).to_vec();

        match panic::catch_unwind(|| {
            let mut pk: [u8; PUBLICKEYBYTES] = [0; PUBLICKEYBYTES];
            let mut sk: [u8; SECRETKEYBYTES] = [0; SECRETKEYBYTES];
            keypair(&mut pk, &mut sk, Some(&digest_vec));
            s7::s7_cons(sc, vec2bv(sc, pk.to_vec()), vec2bv(sc, sk.to_vec()))
        }) {
            Ok(result) => result,
            Err(_) => crypto_error(sc),
        }
    }

    Primitive::new(
        code,
        c"crypto-generate",
        c"(crypto-generate seed) returns a public/private key pair derived from the seed",
        1,
        0,
        false,
    )
}

pub fn primitive_s7_crypto_sign() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let private_key = s7::s7_car(args);
        let message = s7::s7_cadr(args);

        for (i, v) in [private_key, message].iter().enumerate() {
            if !s7::s7_is_byte_vector(v.clone()) {
                return s7::s7_wrong_type_arg_error(
                    sc,
                    c"crypto-sign".as_ptr(),
                    i.try_into()
                        .expect("Failed to convert crypto-sign length to correct type"),
                    v.clone(),
                    c"a byte-vector".as_ptr(),
                );
            }
        }

        let message_vec = bv2vec(message);
        let private_key_vec = bv2vec(private_key);
        let digest_vec = Sha256::digest(&message_vec).to_vec();

        match panic::catch_unwind(|| {
            let mut sig: [u8; SIGNBYTES] = [0; SIGNBYTES];
            signature(&mut sig, &digest_vec, &private_key_vec, false);
            vec2bv(sc, sig.to_vec())
        }) {
            Ok(result) => result,
            Err(_) => crypto_error(sc),
        }
    }

    Primitive::new(
        code,
        c"crypto-sign",
        c"(crypto-sign private-key message) return a cryptographic signature",
        2,
        0,
        false,
    )
}

pub fn primitive_s7_crypto_verify() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        let public_key = s7::s7_car(args);
        let signature = s7::s7_cadr(args);
        let message = s7::s7_caddr(args);

        for (i, v) in [public_key, signature, message].iter().enumerate() {
            if !s7::s7_is_byte_vector(v.clone()) {
                return s7::s7_wrong_type_arg_error(
                    sc,
                    c"crypto-sign".as_ptr(),
                    i.try_into()
                        .expect("Failed to convert index to expected type"),
                    v.clone(),
                    c"a byte-vector".as_ptr(),
                );
            }
        }

        let signature_vec = bv2vec(signature);
        let message_vec = bv2vec(message);
        let public_key_vec = bv2vec(public_key);
        let digest_vec = Sha256::digest(message_vec).to_vec();

        match panic::catch_unwind(
            || match verify(&signature_vec, &digest_vec, &public_key_vec) {
                true => s7::s7_make_boolean(sc, true),
                false => s7::s7_make_boolean(sc, false),
            },
        ) {
            Ok(result) => result,
            Err(_) => crypto_error(sc),
        }
    }

    Primitive::new(
        code,
        c"crypto-verify",
        c"(crypto-verify public-key signature message) returns a boolean indicating signature validity",
        3, 0, false,
    )
}
