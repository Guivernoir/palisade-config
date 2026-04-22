#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_config::ConfigApi;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let _ = ConfigApi::new().load_str(input);
    }
});

