use std::collections::VecDeque;

use bytes::Bytes;
use tinyvec::TinyVec;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    TransportError, VarInt,
    frame::{Datagram, FrameStruct, encode_datagram_header},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > Ord::min(max, send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing_total += data.len();
        self.conn
            .datagrams
            .outgoing
            .push_back(OutgoingDatagram::new([data]));
        Ok(())
    }

    /// Queue a datagram assembled from several buffers, without concatenating them
    ///
    /// The scatter-gather counterpart of [`send`](Self::send), for callers that hold a payload and
    /// prepend a header they generate — the shape of every encapsulating protocol. Passing the two
    /// separately saves a copy of the whole payload, since the parts are gathered directly into the
    /// packet buffer.
    ///
    /// Behaves as `send` with `drop` set: previously queued datagrams which are still unsent may be
    /// discarded to make space, oldest first, so this never reports `Blocked`. There is no waiting
    /// counterpart yet, as [`SendDatagramError::Blocked`] can only carry a single buffer back.
    pub fn send_parts(
        &mut self,
        parts: impl IntoIterator<Item = Bytes>,
    ) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;

        let datagram = OutgoingDatagram::new(parts);
        if datagram.len > Ord::min(max, send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }

        self.conn
            .datagrams
            .make_space_for(datagram.len, send_buffer_size);
        self.conn.datagrams.outgoing_total += datagram.len;
        self.conn.datagrams.outgoing.push_back(datagram);
        Ok(())
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

/// A datagram queued for transmission, possibly assembled from several buffers.
///
/// Callers that build a datagram from a header they generate and a payload they already hold —
/// tunnels and encapsulating protocols do this for every packet — would otherwise have to
/// concatenate the two into a fresh allocation, copying the payload once for nothing: the payload
/// is copied again into the packet buffer a moment later, and that second copy could just as well
/// have gathered the parts.
///
/// Two inline slots cover that case without allocating.
#[derive(Default)]
pub(super) struct OutgoingDatagram {
    parts: TinyVec<[Bytes; 2]>,
    /// Total payload length, cached because it is consulted far more often than the parts.
    len: usize,
}

impl OutgoingDatagram {
    fn new(parts: impl IntoIterator<Item = Bytes>) -> Self {
        let parts: TinyVec<[Bytes; 2]> = parts.into_iter().filter(|p| !p.is_empty()).collect();
        let len = parts.iter().map(|p| p.len()).sum();
        Self { parts, len }
    }

    fn encode(&self, length: bool, out: &mut Vec<u8>) {
        encode_datagram_header(self.len, length, out);
        for part in &self.parts {
            out.extend_from_slice(part);
        }
    }

    pub(super) fn size(&self, length: bool) -> usize {
        1 + if length {
            VarInt::from_u64(self.len as u64).unwrap().size()
        } else {
            0
        } + self.len
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<OutgoingDatagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            trace!(len = prev.len, "dropping outgoing datagram");
            self.outgoing_total -= prev.len;
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self.outgoing_total.checked_add(datagram_len) else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        self.outgoing.retain(|datagram| {
            let result = datagram.len < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.len,
                    max_payload
                );
                self.outgoing_total -= datagram.len;
                dropped_any = true;
            }
            result
        });
        dropped_any
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let Some(datagram) = self.outgoing.pop_front() else {
            return false;
        };

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.len, "DATAGRAM");

        self.outgoing_total -= datagram.len;
        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        self.recv_buffered -= x.len();
        Some(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce qui doit être vrai d'une émission scatter-gather : le paquet produit est **exactement**
    /// celui qu'aurait produit la concaténation préalable. C'est la seule garantie que l'appelant
    /// puisse observer, et donc la seule à tester.
    #[test]
    fn les_parts_encodent_comme_la_concatenation() {
        let parts = [
            Bytes::from_static(b"en-tete-genere"),
            Bytes::from_static(b"charge utile deja en memoire"),
        ];
        let concatene: Vec<u8> = parts.iter().flatten().copied().collect();

        for length in [false, true] {
            let mut a = Vec::new();
            OutgoingDatagram::new(parts.clone()).encode(length, &mut a);

            let mut b = Vec::new();
            OutgoingDatagram::new([Bytes::from(concatene.clone())]).encode(length, &mut b);

            assert_eq!(a, b, "encodage divergent avec length={length}");
        }
    }

    /// Les parts vides ne doivent pas occuper de créneau : sinon deux appels équivalents
    /// n'alloueraient pas pareil, et le cas courant (en-tête + charge) déborderait des deux
    /// créneaux en ligne.
    #[test]
    fn les_parts_vides_sont_ecartees() {
        let d = OutgoingDatagram::new([
            Bytes::new(),
            Bytes::from_static(b"utile"),
            Bytes::new(),
        ]);
        assert_eq!(d.parts.len(), 1);
        assert_eq!(d.len, 5);
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(OutgoingDatagram::new([Bytes::from_static(&[0; 7])]));
        state.outgoing.push_back(OutgoingDatagram::new([Bytes::from_static(&[0; 2])]));
        state.outgoing_total = 9;

        state.make_space_for(4, 10);

        assert_eq!(state.outgoing.len(), 1);
        assert_eq!(state.outgoing[0].len, 2);
        assert_eq!(state.outgoing_total, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(OutgoingDatagram::new([Bytes::from_static(&[0])]));
        state.outgoing_total = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing_total, usize::MAX - 2);
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
