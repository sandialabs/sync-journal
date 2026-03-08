use crate::evaluator as s7;
use crate::evaluator::Primitive;
use std::ffi::{CStr, CString};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn primitive_s7_system_time_utc() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        unsafe {
            let dt = if s7::s7_is_null(sc, args) {
                OffsetDateTime::now_utc()
            } else {
                let arg = s7::s7_car(args);

                if !s7::s7_is_integer(arg) {
                    return s7::s7_wrong_type_arg_error(
                        sc,
                        c"system-time-utc".as_ptr(),
                        1,
                        arg,
                        c"a unix timestamp integer".as_ptr(),
                    );
                }

                match OffsetDateTime::from_unix_timestamp(s7::s7_integer(arg)) {
                    Ok(value) => value,
                    Err(_) => {
                        return s7::s7_error(
                            sc,
                            s7::s7_make_symbol(sc, c"time-error".as_ptr()),
                            s7::s7_list(
                                sc,
                                1,
                                s7::s7_make_string(sc, c"Invalid unix timestamp range".as_ptr()),
                            ),
                        );
                    }
                }
            };

            match dt.format(&Rfc3339) {
                Ok(timestamp) => match CString::new(timestamp) {
                    Ok(c_timestamp) => s7::s7_make_string(sc, c_timestamp.as_ptr()),
                    Err(_) => s7::s7_error(
                        sc,
                        s7::s7_make_symbol(sc, c"time-error".as_ptr()),
                        s7::s7_list(
                            sc,
                            1,
                            s7::s7_make_string(
                                sc,
                                c"Generated UTC timestamp had invalid bytes".as_ptr(),
                            ),
                        ),
                    ),
                },
                Err(_) => s7::s7_error(
                    sc,
                    s7::s7_make_symbol(sc, c"time-error".as_ptr()),
                    s7::s7_list(
                        sc,
                        1,
                        s7::s7_make_string(sc, c"Failed to format UTC time".as_ptr()),
                    ),
                ),
            }
        }
    }

    Primitive::new(
        code,
        c"system-time-utc",
        c"(system-time-utc [unix]) returns current UTC time or converts unix epoch seconds to RFC3339 UTC",
        0,
        1,
        false,
    )
}

pub fn primitive_s7_system_time_unix() -> Primitive {
    unsafe extern "C" fn code(sc: *mut s7::s7_scheme, args: s7::s7_pointer) -> s7::s7_pointer {
        unsafe {
            if s7::s7_is_null(sc, args) {
                return s7::s7_make_integer(sc, OffsetDateTime::now_utc().unix_timestamp());
            }

            let arg = s7::s7_car(args);
            if !s7::s7_is_string(arg) {
                return s7::s7_wrong_type_arg_error(
                    sc,
                    c"system-time-unix".as_ptr(),
                    1,
                    arg,
                    c"an RFC3339 UTC string".as_ptr(),
                );
            }

            let s7_c_str = s7::s7_string(arg);
            let timestamp = match CStr::from_ptr(s7_c_str).to_str() {
                Ok(value) => value,
                Err(_) => {
                    return s7::s7_error(
                        sc,
                        s7::s7_make_symbol(sc, c"encoding-error".as_ptr()),
                        s7::s7_list(
                            sc,
                            1,
                            s7::s7_make_string(sc, c"Invalid UTF-8 timestamp string".as_ptr()),
                        ),
                    );
                }
            };

            match OffsetDateTime::parse(timestamp, &Rfc3339) {
                Ok(dt) => s7::s7_make_integer(sc, dt.unix_timestamp()),
                Err(_) => s7::s7_error(
                    sc,
                    s7::s7_make_symbol(sc, c"time-error".as_ptr()),
                    s7::s7_list(
                        sc,
                        1,
                        s7::s7_make_string(sc, c"Failed to parse RFC3339 timestamp".as_ptr()),
                    ),
                ),
            }
        }
    }

    Primitive::new(
        code,
        c"system-time-unix",
        c"(system-time-unix [utc]) returns current unix epoch seconds or converts RFC3339 UTC to unix seconds",
        0,
        1,
        false,
    )
}
