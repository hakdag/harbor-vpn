#![no_main]
use ikev2_wire::*;
use libfuzzer_sys::fuzz_target;
fn exercise(data: &[u8]) {
    let limits = Limits::default();
    let _ = raw::decode(data, limits);
    if let Ok(m) = decode(data, limits) {
        let _ = check_support(&m);
        let encoded = encode(&m, limits).expect("decoded message must serialize");
        assert!(encoded.len() <= limits.message_bytes);
        let again = decode(&encoded, limits).expect("serialized message must decode");
        assert_eq!(encode(&again, limits).unwrap(), encoded);
    }
}
fuzz_target!(|data: &[u8]| {
    exercise(data);
    // Also reach body parsing when mutations disrupt the outer length.
    if (28..=Limits::HARD.message_bytes).contains(&data.len()) {
        let mut fixed = data.to_vec();
        fixed[24..28].copy_from_slice(&(data.len() as u32).to_be_bytes());
        exercise(&fixed);
    }
});
