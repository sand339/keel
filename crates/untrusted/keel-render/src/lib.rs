#![doc = "Untrusted guest-output frame producer for Keel."]

mod launcher;

pub use launcher::run_launcher;
use std::io::{self, Read, Write};

/// Identifies this crate as outside the trusted computing base.
pub const TRUST_CLASS: &str = "untrusted";

/// Maximum guest bytes read before a display frame is emitted.
pub const MAX_GUEST_FRAME_BYTES: usize = 16 * 1024;

/// Streaming guest-output transformer.
///
/// The producer has one operation: copy guest PTY bytes into normal-mode
/// display frames. It exposes no control or approval message. A trailing
/// carriage return is held until the next guest byte so CRLF normalization is
/// correct even when a pair crosses IPC reads.
pub struct FrameProducer<W> {
    output: W,
    pending_carriage_return: bool,
}

impl<W: Write> FrameProducer<W> {
    /// Creates a producer writing display frames to `output`.
    pub fn new(output: W) -> Self {
        Self {
            output,
            pending_carriage_return: false,
        }
    }

    /// Transforms and emits one bounded guest frame.
    ///
    /// Callers must split larger PTY reads before passing them here.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error for an oversized frame, or propagates an
    /// error from the display IPC writer.
    pub fn push(&mut self, guest: &[u8]) -> io::Result<()> {
        if guest.len() > MAX_GUEST_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest frame exceeds renderer limit",
            ));
        }

        let mut display =
            Vec::with_capacity(guest.len() + usize::from(self.pending_carriage_return));
        let mut index = 0;

        if self.pending_carriage_return {
            if guest.first() == Some(&b'\n') {
                display.push(b'\n');
                index = 1;
            } else {
                display.push(b'\r');
            }
            self.pending_carriage_return = false;
        }

        while index < guest.len() {
            if guest[index] == b'\r' {
                if index + 1 == guest.len() {
                    self.pending_carriage_return = true;
                    break;
                }
                if guest[index + 1] == b'\n' {
                    display.push(b'\n');
                    index += 2;
                    continue;
                }
            }
            display.push(guest[index]);
            index += 1;
        }

        if !display.is_empty() {
            // A terminal frame is mostly cursor addressing and carries few
            // newlines, so a line-buffered writer would hold it back until the
            // session ends. Every frame leaves the renderer immediately.
            self.output.write_all(&display)?;
            self.output.flush()?;
        }
        Ok(())
    }

    /// Flushes a final unmatched carriage return and the IPC output.
    ///
    /// # Errors
    ///
    /// Propagates an error from the display IPC writer.
    pub fn finish(mut self) -> io::Result<W> {
        if self.pending_carriage_return {
            self.output.write_all(b"\r")?;
        }
        self.output.flush()?;
        Ok(self.output)
    }
}

/// Streams guest PTY output from one IPC endpoint to display-only output.
///
/// Memory use is bounded by two [`MAX_GUEST_FRAME_BYTES`] buffers regardless
/// of how long the guest session runs.
///
/// # Errors
///
/// Propagates errors from the guest reader or display writer.
pub fn render_stream<R: Read, W: Write>(mut guest: R, output: W) -> io::Result<W> {
    let mut producer = FrameProducer::new(output);
    let mut frame = [0_u8; MAX_GUEST_FRAME_BYTES];
    loop {
        let count = guest.read(&mut frame)?;
        if count == 0 {
            return producer.finish();
        }
        producer.push(&frame[..count])?;
    }
}

/// Transforms a guest PTY frame into a normal-mode display frame.
///
/// This compatibility helper preserves terminal control sequences and
/// normalizes CRLF pairs. Production IPC should use [`render_stream`].
#[must_use]
pub fn render_frame(guest: &[u8]) -> Vec<u8> {
    let mut display = Vec::with_capacity(guest.len());
    let mut index = 0;
    while index < guest.len() {
        if guest[index..].starts_with(b"\r\n") {
            display.push(b'\n');
            index += 2;
        } else {
            display.push(guest[index]);
            index += 1;
        }
    }
    display
}

#[cfg(test)]
mod tests {
    use super::{FrameProducer, MAX_GUEST_FRAME_BYTES, render_frame, render_stream};
    use std::io::{self, Read};

    struct ShortReads<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl Read for ShortReads<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.position == self.bytes.len() {
                return Ok(0);
            }
            let count = output.len().min(1).min(self.bytes.len() - self.position);
            output[..count].copy_from_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Ok(count)
        }
    }

    #[test]
    fn frame_producer_rejects_oversized_input() {
        let mut producer = FrameProducer::new(Vec::new());
        assert_eq!(
            producer
                .push(&vec![b'x'; MAX_GUEST_FRAME_BYTES + 1])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn stream_output_is_independent_of_read_boundaries() {
        let guest = b"a\r\nb\rc\r\n";
        let output = render_stream(
            ShortReads {
                bytes: guest,
                position: 0,
            },
            Vec::new(),
        )
        .unwrap();
        assert_eq!(output, b"a\nb\rc\n");
        assert_eq!(render_frame(guest), output);
    }
}
