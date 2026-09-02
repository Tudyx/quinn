use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tinyvec::TinyVec;
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
    ///
    /// The subtrahend is [`DatagramBuffer::memory_used`], the very quantity
    /// [`DatagramState::has_send_buffer_space`] compares against, so the guarantee above holds
    /// entry for entry: the queue charges one element's overhead **per queued entry**, and an
    /// accessor subtracting a single one over-reported the free space by
    /// `(len - 1) * size_of::<OutgoingDatagram>()`. At a 64 KiB queue of 1.3 kB datagrams that is
    /// some 3.8 kB of room reported at the exact moment every push evicts.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .datagrams
            .send_buffer_space(self.conn.config.datagram_send_buffer_size)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramBuffer<Datagram>,
    pub(super) outgoing: DatagramBuffer<OutgoingDatagram>,
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

        let size_with_overhead = datagram.data.len() + size_of::<Datagram>();

        if size_with_overhead > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.incoming.is_empty();
        while self.incoming.memory_used() + size_with_overhead > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            trace!(len = prev.payload_len(), "dropping outgoing datagram");
        }
    }

    /// Room left before [`Self::has_send_buffer_space`] starts refusing — the accessor's half of
    /// the contract, kept beside the eviction's half so the two cannot be derived apart.
    fn send_buffer_space(&self, send_buffer_size: usize) -> usize {
        send_buffer_size.saturating_sub(self.outgoing.memory_used())
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self.outgoing.memory_used().checked_add(datagram_len) else {
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
        self.outgoing.queue.retain(|datagram| {
            let result = datagram.payload_len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.payload_len(),
                    max_payload
                );
                self.outgoing.payload_bytes -= datagram.payload_len();
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

        trace!(len = datagram.payload_len(), "DATAGRAM");
        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        Some(x)
    }
}

/// What a queued datagram has to answer for the buffer to bill it and put it on the wire.
///
/// The two queues do not hold the same thing — incoming datagrams arrive contiguous, outgoing ones
/// may be assembled from several buffers — but they are billed and framed identically, so the
/// buffer is generic over which and each direction is charged its own element size.
pub(super) trait QueuedDatagram {
    /// Payload length, framing excluded.
    fn payload_len(&self) -> usize;

    /// Length once framed, `length` telling whether the frame carries an explicit length field.
    fn size(&self, length: bool) -> usize;

    /// Append the frame — header, then payload — to `out`.
    fn encode(&self, length: bool, out: &mut Vec<u8>);
}

impl QueuedDatagram for Datagram {
    fn payload_len(&self) -> usize {
        self.data.len()
    }

    fn size(&self, length: bool) -> usize {
        Self::size(self, length)
    }

    fn encode(&self, length: bool, out: &mut Vec<u8>) {
        Self::encode(self, length, out)
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
/// Two inline slots cover that case without allocating. They are what makes this element larger
/// than a `Datagram`, and `DatagramBuffer` charges that difference to the send buffer rather than
/// hiding it.
#[derive(Default)]
pub(crate) struct OutgoingDatagram {
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
}

impl QueuedDatagram for OutgoingDatagram {
    fn payload_len(&self) -> usize {
        self.len
    }

    fn size(&self, length: bool) -> usize {
        1 + if length {
            VarInt::from_u64(self.len as u64).unwrap().size()
        } else {
            0
        } + self.len
    }

    fn encode(&self, length: bool, out: &mut Vec<u8>) {
        encode_datagram_header(self.len, length, out);
        for part in &self.parts {
            out.extend_from_slice(part);
        }
    }
}

pub(super) struct DatagramBuffer<T> {
    queue: VecDeque<T>,
    payload_bytes: usize,
}

/// Hand-written so an empty buffer needs nothing of its element.
impl<T> Default for DatagramBuffer<T> {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            payload_bytes: 0,
        }
    }
}

impl<T: QueuedDatagram> DatagramBuffer<T> {
    fn push_back(&mut self, datagram: T) {
        self.payload_bytes += datagram.payload_len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<T> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.payload_len();
        Some(datagram)
    }

    fn push_front(&mut self, datagram: T) {
        self.payload_bytes += datagram.payload_len();
        self.queue.push_front(datagram);
    }

    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len() * size_of::<T>())
    }

    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.queue.front().is_some_and(|x| x.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What has to hold of a scatter-gather send: the packet produced is **exactly** the one a
    /// prior concatenation would have produced. That is the only guarantee the caller can observe,
    /// hence the only one to test.
    #[test]
    fn parts_encode_as_the_concatenation() {
        let parts = [
            Bytes::from_static(b"generated-header"),
            Bytes::from_static(b"payload already in memory"),
        ];
        let concatenated: Vec<u8> = parts.iter().flatten().copied().collect();

        for length in [false, true] {
            let mut a = Vec::new();
            OutgoingDatagram::new(parts.clone()).encode(length, &mut a);

            let mut b = Vec::new();
            OutgoingDatagram::new([Bytes::from(concatenated.clone())]).encode(length, &mut b);

            assert_eq!(a, b, "encoding diverges with length={length}");
        }
    }

    /// An empty part must not take a slot: otherwise two equivalent calls would not allocate alike,
    /// and the common case — header plus payload — would spill out of the two inline slots.
    #[test]
    fn empty_parts_are_discarded() {
        let d = OutgoingDatagram::new([Bytes::new(), Bytes::from_static(b"useful"), Bytes::new()]);
        assert_eq!(d.parts.len(), 1);
        assert_eq!(d.len, 6);
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state
            .outgoing
            .push_back(OutgoingDatagram::new([Bytes::from_static(&[0; 7])]));
        state
            .outgoing
            .push_back(OutgoingDatagram::new([Bytes::from_static(&[0; 2])]));

        state.make_space_for(4, 10 + 2 * size_of::<OutgoingDatagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].len, 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state
            .outgoing
            .queue
            .push_back(OutgoingDatagram::new([Bytes::from_static(&[0])]));
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    /// **The accessor and the eviction are two halves of one contract**, and they only have to be
    /// confronted at a queue holding **many** entries. `memory_used()` charges one element's
    /// overhead per queued entry; an accessor subtracting a single one over-reports the free space
    /// by `(len - 1) * size_of::<OutgoingDatagram>()`, so at a 64 KiB queue of 1.3 kB datagrams it
    /// announced some 3.8 kB of room at the exact moment every push evicted an older datagram. At a
    /// queue that holds one entry the two arithmetics agree to one element and the defect is
    /// invisible — which is why the case pinned here is the many-entry one.
    #[test]
    fn a_full_queue_of_many_entries_reports_no_room_before_it_evicts() {
        const SIZE: usize = 1318;
        const BUFFER: usize = 65_536;

        let mut state = DatagramState::default();
        let mut queued = 0;
        while state.has_send_buffer_space(SIZE, BUFFER) {
            // The doc comment's guarantee, asserted at every depth rather than only at the end:
            // whatever the accessor announces must be a size the eviction would accept.
            let announced = state.send_buffer_space(BUFFER);
            assert!(
                state.has_send_buffer_space(announced, BUFFER),
                "{announced} bytes announced free with {queued} entries queued, and a datagram of \
                 that size would evict"
            );
            state
                .outgoing
                .push_back(OutgoingDatagram::new([Bytes::from_static(&[0; SIZE])]));
            queued += 1;
        }

        assert!(
            queued > 10,
            "{queued} entries fit: this is the single-entry regime, where the defect is invisible"
        );
        assert!(
            state.send_buffer_space(BUFFER) < SIZE,
            "the queue is full and the accessor still offers room for another datagram"
        );
    }

    #[test]
    fn empty_frame_flood_limit() {
        let mut state = DatagramState::default();
        let datagram = Datagram { data: Bytes::new() };
        let window = 100;
        loop {
            let initial_count = state.incoming.queue.len();
            state.received(datagram.clone(), &Some(window)).unwrap();
            assert!(state.incoming.queue.len() * size_of::<Datagram>() <= window);
            if state.incoming.queue.len() == initial_count {
                // Datagrams are getting dropped
                break;
            }
        }
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
