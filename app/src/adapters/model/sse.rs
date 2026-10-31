//! One Server-Sent Events parser for both model providers: `(event, data)` pairs, with
//! multi-line `data` joined by `\n` and frames split anywhere across chunks.
use futures::{stream, Stream, StreamExt};
use opsagent_core::model::ModelError;

/// The events of a streamed response body; a body that breaks mid-stream is an `Outage`.
pub fn events(
    resp: reqwest::Response,
) -> impl Stream<Item = Result<(String, String), ModelError>> + Send {
    parse(resp.bytes_stream())
}

/// The most a line may grow without a newline, and an event (`event` plus `data`) without a
/// blank line; past either the body is an `Outage`.
const LINE_CAP: usize = 1024 * 1024;
const EVENT_CAP: usize = 1024 * 1024;

struct State<S> {
    body: S,
    buf: Vec<u8>,
    event: String,
    data: Vec<String>,
    /// Bytes in `event` and `data` so far.
    size: usize,
    done: bool,
}

/// `events` over any byte-chunk stream (the testable core).
pub fn parse<S, B, E>(body: S) -> impl Stream<Item = Result<(String, String), ModelError>> + Send
where
    S: Stream<Item = Result<B, E>> + Send + Unpin,
    B: AsRef<[u8]>,
{
    let st = State {
        body,
        buf: Vec::new(),
        event: String::new(),
        data: Vec::new(),
        size: 0,
        done: false,
    };
    stream::unfold(st, |mut st| async move {
        loop {
            if st.done {
                return None;
            }
            if let Some(ev) = st.next_frame() {
                st.done = ev.is_err();
                return Some((ev, st));
            }
            // `next_frame` left only an unterminated line.
            if st.buf.len() > LINE_CAP {
                st.done = true;
                return Some((Err(ModelError::Outage), st));
            }
            match st.body.next().await {
                Some(Ok(chunk)) => st.buf.extend_from_slice(chunk.as_ref()),
                Some(Err(_)) => {
                    st.done = true;
                    return Some((Err(ModelError::Outage), st));
                }
                // An unterminated last frame is dropped, as the SSE spec says.
                None => return None,
            }
        }
    })
}

impl<S> State<S> {
    /// Consumes whole lines from the buffer until a frame completes.
    fn next_frame(&mut self) -> Option<Result<(String, String), ModelError>> {
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = self.buf.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&raw);
            let line = line.trim_end_matches(['\n', '\r']);
            if line.is_empty() {
                self.size = 0;
                let event = std::mem::take(&mut self.event);
                if self.data.is_empty() {
                    continue;
                }
                let data = std::mem::take(&mut self.data).join("\n");
                let name = if event.is_empty() {
                    "message".into()
                } else {
                    event
                };
                return Some(Ok((name, data)));
            }
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "event" => {
                    self.size = self.size - self.event.len() + value.len();
                    self.event = value.to_owned();
                }
                "data" => {
                    self.size += value.len();
                    self.data.push(value.to_owned());
                }
                _ => {} // comments (`:`), `id`, `retry`
            }
            if self.size > EVENT_CAP {
                return Some(Err(ModelError::Outage));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn run(chunks: &[&'static str]) -> Vec<Result<(String, String), ModelError>> {
        let body = stream::iter(chunks.iter().map(|c| Ok::<_, ()>(c.as_bytes())));
        parse(body).collect().await
    }

    #[tokio::test]
    async fn sse_parser_handles_split_chunks_and_multiline_data() {
        let got = run(&[
            ": ping\n\nevent: a\nda",
            "ta: {\"x\":\r\ndata: 1}\r\n",
            "\r\ndata:plain\n\nevent: b\n",
            "data: é",
            "\n\nevent: c\ndata: unterminated",
        ])
        .await;
        let got: Vec<_> = got.into_iter().map(Result::unwrap).collect();
        let pair = |e: &str, d: &str| (e.to_owned(), d.to_owned());
        assert_eq!(
            got,
            vec![
                pair("a", "{\"x\":\n1}"),
                pair("message", "plain"),
                pair("b", "é"),
            ]
        );
    }

    #[tokio::test]
    async fn sse_parser_splits_a_multibyte_char_and_reports_a_broken_body() {
        let bytes = "data: é\n\n".as_bytes();
        let (a, b) = bytes.split_at(7);
        let body = stream::iter([Ok(a), Ok(b), Err(())]);
        let got: Vec<_> = parse(body).collect().await;
        assert_eq!(got[0], Ok(("message".into(), "é".into())));
        assert_eq!(got[1], Err(ModelError::Outage));
        assert_eq!(got.len(), 2);
    }

    #[tokio::test]
    async fn sse_parser_refuses_a_line_past_the_cap() {
        let chunk = vec![b'a'; 64 * 1024];
        let body = stream::iter((0..20).map(move |_| Ok::<_, ()>(chunk.clone())));
        let got: Vec<_> = parse(body).collect().await;
        assert_eq!(got, vec![Err(ModelError::Outage)]);
    }

    #[tokio::test]
    async fn sse_parser_refuses_an_event_past_the_cap() {
        let lines = "data: ".to_owned() + &"x".repeat(1000) + "\n";
        let chunk = lines.repeat(64).into_bytes();
        let body = stream::iter((0..20).map(move |_| Ok::<_, ()>(chunk.clone())));
        let got: Vec<_> = parse(body).collect().await;
        assert_eq!(got, vec![Err(ModelError::Outage)]);
    }
}
