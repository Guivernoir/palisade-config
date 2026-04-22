#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_config::PolicyApi;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = core::str::from_utf8(data) {
        let _ = PolicyApi::new().load_str(input);
    }
});
