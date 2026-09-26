//! Bounded base64 decoding shared by [`crate::plist`] (tolerant: any
//! non-alphabet byte is skipped) and [`crate::rules::entropy`] (a run
//! decoder: malformed padding stops decoding outright). §3/§11.9: no
//! external crate, no panics, output capped by the caller.

/// Standard base64 alphabet (RFC 4648 §4) value of `b`, or `None` if `b`
/// isn't in it.
pub(crate) fn char_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// How [`decode_bounded`] treats a byte that's neither alphabet nor `=`
/// padding, or an alphabet byte arriving after padding has started.
pub(crate) enum OnInvalid {
    /// Ignore it and keep decoding — [`crate::plist`]'s tolerant `<data>` reader.
    Skip,
    /// End decoding there, keeping bytes already produced —
    /// [`crate::rules::entropy`]'s run decoder.
    Stop,
}

/// Decode up to `max_output` bytes of base64 from `input`, also returning
/// the count of alphabet characters consumed (`=`/`\r`/`\n` not counted) —
/// so a caller judging whether a candidate is long enough doesn't need its
/// own separate counting pass over the same bytes. `\r`/`\n` are always
/// skipped (line-wrapped base64 is common); `=` starts padding. `on_invalid`
/// governs both a byte outside the alphabet/padding and an alphabet byte
/// following padding (malformed input). Never panics: a truncated final
/// group of 2 or 3 symbols decodes to 1 or 2 bytes, 1 leftover symbol is
/// dropped, matching most decoders' handling of malformed input.
pub(crate) fn decode_bounded(
    input: &[u8],
    max_output: usize,
    on_invalid: OnInvalid,
) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut group = [0u8; 4];
    let mut group_len = 0usize;
    let mut padding_started = false;
    let mut alphabet_count = 0usize;
    let stop_on_invalid = matches!(on_invalid, OnInvalid::Stop);

    for &b in input {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        if b == b'=' {
            padding_started = true;
            continue;
        }
        if padding_started && stop_on_invalid {
            break;
        }
        let Some(v) = char_value(b) else {
            if stop_on_invalid {
                break;
            }
            continue;
        };
        alphabet_count += 1;
        group[group_len] = v;
        group_len += 1;
        if group_len == 4 {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
            out.push((group[2] << 6) | group[3]);
            group_len = 0;
            if out.len() >= max_output {
                out.truncate(max_output);
                return (out, alphabet_count);
            }
        }
    }
    match group_len {
        2 => out.push((group[0] << 2) | (group[1] >> 4)),
        3 => {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
        }
        _ => {}
    }
    out.truncate(max_output);
    (out, alphabet_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_stop(input: &[u8], max_output: usize) -> Vec<u8> {
        decode_bounded(input, max_output, OnInvalid::Stop).0
    }

    fn decode_skip(input: &[u8], max_output: usize) -> Vec<u8> {
        decode_bounded(input, max_output, OnInvalid::Skip).0
    }

    #[test]
    fn decode_bounded_returns_alphabet_count() {
        let (decoded, count) = decode_bounded(b"Zm9v\r\n!YmFy==", usize::MAX, OnInvalid::Skip);
        assert_eq!(decoded, b"foobar");
        assert_eq!(count, 8, "\\r\\n, '!', and '=' padding don't count");
    }

    #[test]
    fn decode_rfc4648_vectors() {
        assert_eq!(decode_stop(b"", usize::MAX), b"");
        assert_eq!(decode_stop(b"Zg==", usize::MAX), b"f");
        assert_eq!(decode_stop(b"Zm9vYmFy", usize::MAX), b"foobar");
        assert_eq!(decode_skip(b"Zm9vYmFy", usize::MAX), b"foobar");
    }

    #[test]
    fn decode_crlf_wrapped_input_matches_unwrapped() {
        // "foobar" split across a CRLF-wrapped line.
        assert_eq!(decode_stop(b"Zm9v\r\nYmFy", usize::MAX), b"foobar");
    }

    #[test]
    fn decode_stops_at_invalid_char() {
        // "Zm9v" -> "foo"; '!' is not in the alphabet and ends decoding.
        assert_eq!(decode_stop(b"Zm9v!YmFy", usize::MAX), b"foo");
    }

    #[test]
    fn decode_skips_invalid_char() {
        // Same input, tolerant mode: '!' is dropped and decoding continues.
        assert_eq!(decode_skip(b"Zm9v!YmFy", usize::MAX), b"foobar");
    }

    #[test]
    fn decode_odd_length_and_stray_padding_do_not_panic() {
        assert_eq!(decode_stop(b"A", usize::MAX), b"");
        assert_eq!(decode_stop(b"A=B", usize::MAX), b"");
        assert_eq!(decode_stop(b"====", usize::MAX), b"");
    }

    #[test]
    fn stop_and_skip_diverge_on_embedded_padding() {
        // Stop mode treats padding as ending the run — 'C' arriving after
        // "AB==" is malformed and halts decoding, so only the partial "AB"
        // group (still under 4 symbols) is emitted. Skip mode (plist's
        // tolerant reader) treats the stray '=' as noise and keeps
        // collecting symbols, completing the group.
        assert_eq!(
            decode_stop(b"AB==CD", usize::MAX),
            decode_stop(b"AB", usize::MAX)
        );
        assert_eq!(
            decode_skip(b"AB==CD", usize::MAX),
            decode_skip(b"ABCD", usize::MAX)
        );
    }

    #[test]
    fn decode_respects_output_cap() {
        let encoded = b"Zm9vYmFyYmF6cXV1eA=="; // "foobarbazquux"
        assert_eq!(decode_stop(encoded, 3), b"foo");
        assert_eq!(decode_skip(encoded, 3), b"foo");
    }
}
