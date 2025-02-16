// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

pub mod ring_buffers;
pub mod session;
pub mod timers;

use crossbeam::channel::Sender;
use parking_lot::{Mutex, RwLock};
use ring_buffers::{EncryptionTaskData, PLAINTEXT_RING_BUFFER};
use session::Session;

use crate::device::peer::Peer;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU16, AtomicUsize};
use std::sync::Arc;
use std::time::Duration;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

#[derive(Debug)]
pub enum NeptunResult {
    Done,
    Err(WireGuardError),
    WriteToNetwork(usize),
    WriteToTunnelV4(usize, Ipv4Addr),
    WriteToTunnelV6(usize, Ipv6Addr),
}

impl From<WireGuardError> for NeptunResult {
    fn from(err: WireGuardError) -> NeptunResult {
        NeptunResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: Mutex<handshake::Handshake>,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    pub sessions: RwLock<[Option<session::Session>; N_SESSIONS]>,
    /// Index of most recently used session
    pub current: AtomicUsize,
    /// Queue to store blocked packets
    packet_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    pub tx_bytes: AtomicUsize,
    pub rx_bytes: AtomicUsize,
    rate_limiter: RwLock<Arc<RateLimiter>>,
    timers_to_update_mask: AtomicU16,
    encyrpt_tx: Sender<usize>,
    network_tx: Sender<&'static EncryptionTaskData>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    pub counter: u64,
    pub encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Checks the type, as well as the reserved zero fields
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        Ok(match (packet_type, src.len()) {
            (HANDSHAKE_INIT, HANDSHAKE_INIT_SZ) => Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }),
            (HANDSHAKE_RESP, HANDSHAKE_RESP_SZ) => Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }),
            (COOKIE_REPLY, COOKIE_REPLY_SZ) => Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }),
            (DATA, DATA_OVERHEAD_SZ..=std::usize::MAX) => Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }),
            _ => return Err(WireGuardError::InvalidPacket),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.lock().is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        encyrpt_tx: Sender<usize>,
        network_tx: Sender<&'static EncryptionTaskData>,
    ) -> Self {
        let static_public = x25519::PublicKey::from(&static_private);

        Tunn {
            handshake: Mutex::new(Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            )),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: Mutex::new(VecDeque::new()),
            timers: Timers::new(persistent_keepalive, rate_limiter.is_none()),

            rate_limiter: RwLock::new(rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            })),
            timers_to_update_mask: Default::default(),
            encyrpt_tx,
            network_tx,
        }
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers
            .should_reset_rr
            .store(rate_limiter.is_none(), Ordering::Relaxed);
        *(self.rate_limiter.write()) = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .lock()
            .set_static_private(static_private, static_public);

        self.clear_sessions();
    }

    pub(super) fn clear_sessions(&self) {
        let mut sessions = self.sessions.write();
        for s in sessions.iter_mut() {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least src.len() + 32, and no less than 148 bytes.
    pub fn encapsulate(
        &self,
        len: usize,
        element: &'static mut EncryptionTaskData,
        iter: usize,
        peer: Arc<Peer>,
    ) {
        let current = self.current.load(Ordering::Relaxed);
        if let Some(ref session) = self.sessions.read()[current % N_SESSIONS] {
            element.is_element_free.store(false, Ordering::Relaxed);
            // Send the packet using an established session
            element.buf_len = len;
            element.sending_index = session.sending_index;
            element.sender = Some(session.sender.clone());
            element.sending_key_counter = session.sending_key_counter.clone();
            element.peer = Some(peer.clone());

            self.mark_timer_to_update(TimerName::TimeLastPacketSent);
            // Exclude Keepalive packets from timer update.
            if len == 0 {
                self.mark_timer_to_update(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes.fetch_add(len, Ordering::Relaxed);
            let _ = self.encyrpt_tx.send(iter);
            return;
        }

        // Q the packet
        self.queue_packet(&element.data[..len]);
        // Initiate handshake
        self.initiate_handshake(peer.clone(), false);
    }

    pub fn initiate_handshake(&self, peer: Arc<Peer>, force_resend: bool) {
        // TODO: Have to fix this. This can't be a hardcoded 0th iter
        let (dst, _) = unsafe { PLAINTEXT_RING_BUFFER.get_next() };
        {
            dst.peer = Some(peer.clone());
            let res = self.format_handshake_initiation(dst.data.as_mut_slice(), force_resend);
            match res {
                NeptunResult::Done => return,
                NeptunResult::Err(e) => {
                    tracing::error!(message = "Handshake initiation error", error = ?e);
                    return;
                }
                NeptunResult::WriteToNetwork(n) => dst.res = NeptunResult::WriteToNetwork(n),
                _ => panic!("Unexpected result from handshake initiation"),
            }
        };
        // This has to change. Atm, can handle only 1 and only
        // at the beginning
        dst.is_element_free.store(false, Ordering::Relaxed);
        let _ = self.network_tx.send(dst);
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        // if datagram.is_empty() {
        //     // Indicates a repeated call
        //     return self.send_queued_packet(dst);
        // }

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .read()
            .verify_packet(src_addr, datagram, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                dst[..cookie.len()].copy_from_slice(cookie);
                return TunnResult::WriteToNetwork(&mut dst[..cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            _ => Ok(TunnResult::Done),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let (packet, session) = self
            .handshake
            .lock()
            .receive_handshake_initialization(p, dst)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions.write()[index % N_SESSIONS] = Some(session);

        self.mark_timer_to_update(TimerName::TimeLastPacketReceived);
        self.mark_timer_to_update(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(packet))
    }

    fn handle_handshake_response<'a>(
        &self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.lock().receive_handshake_response(p)?;

        let (keepalive_packet, _) = {
            Session::encrypt_data_pkt(
                session.sending_key_counter.clone(),
                session.sending_index,
                session.sender.clone(),
                0,
                dst,
            )
        };
        // Store new session in ring buffer
        let l_idx = session.receiving_index as usize;
        let index = l_idx % N_SESSIONS;
        self.sessions.write()[index] = Some(session);

        self.mark_timer_to_update(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.lock().receive_cookie_reply(p)?;
        self.mark_timer_to_update(TimerName::TimeLastPacketReceived);
        self.mark_timer_to_update(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    pub fn set_current_session(&self, new_idx: usize) {
        let cur_idx = self.current.load(Ordering::Relaxed);
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions.read()[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS].time()
                >= self.timers.session_timers[cur_idx % N_SESSIONS].time()
        {
            self.current.store(new_idx, Ordering::Relaxed);
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        {
            let sessions = self.sessions.read();
            let session = sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            // let decapsulated_packet = Session::decrypt_data_pkt(
            //     packet,
            //     session.receiving_index,
            //     session.receiver.clone(),
            //     session.receiving_key_counter.clone(),
            //     dst,
            // )?;
            // Tunn::validate_decapsulated_packet(decapsulated_packet);
        };

        self.set_current_session(r_idx);

        self.mark_timer_to_update(TimerName::TimeLastPacketReceived);

        Ok(TunnResult::Done)
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out)
    pub fn format_handshake_initiation(&self, dst: &mut [u8], force_resend: bool) -> NeptunResult {
        let mut handshake = self.handshake.lock();
        if handshake.is_in_progress() && !force_resend {
            return NeptunResult::Done;
        }

        if handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !handshake.is_in_progress();

        match handshake.format_handshake_initiation(dst) {
            Ok(packet) => {
                tracing::debug!("Sending handshake_initiation");

                if starting_new_handshake {
                    self.mark_timer_to_update(TimerName::TimeLastHandshakeStarted);
                }
                self.mark_timer_to_update(TimerName::TimeLastPacketSent);
                NeptunResult::WriteToNetwork(packet.len())
            }
            Err(e) => NeptunResult::Err(e),
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet(packet: &mut [u8]) -> NeptunResult {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return NeptunResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => return NeptunResult::Err(WireGuardError::InvalidPacket),
        };

        if computed_len > packet.len() {
            return NeptunResult::Err(WireGuardError::InvalidPacket);
        }

        // Moved to send_to_tunnel worker

        match src_ip_address {
            IpAddr::V4(addr) => NeptunResult::WriteToTunnelV4(computed_len, addr),
            IpAddr::V6(addr) => NeptunResult::WriteToTunnelV6(computed_len, addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    /// TODO. Ignoring this for now!!
    // fn send_queued_packet(&mut self, dst: &mut [u8]) -> TunnResult {
    //     if let Some(packet) = self.dequeue_packet() {
    //         match self.encapsulate(&packet, dst) {
    //             TunnResult::Err(_) => {
    //                 // On error, return packet to the queue
    //                 self.requeue_packet(packet);
    //             }
    //             r => return r,
    //         }
    //     }
    //     TunnResult::Done
    // }

    /// Push packet to the back of the queue
    pub fn queue_packet(&self, packet: &[u8]) {
        let mut queue = self.packet_queue.lock();
        if queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&self, packet: Vec<u8>) {
        let mut queue = self.packet_queue.lock();
        if queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            queue.push_front(packet);
        }
    }

    fn dequeue_packet(&self) -> Option<Vec<u8>> {
        let mut queue = self.packet_queue.lock();
        queue.pop_front()
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current.load(Ordering::Relaxed);

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) =
                self.sessions.write()[(session_idx.wrapping_sub(i)) % N_SESSIONS]
            {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let loss = self.estimate_loss();
        let rtt = self.handshake.lock().last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

// #[cfg(test)]
// mod tests {
//     #[cfg(feature = "mock-instant")]
//     use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

//     use super::*;
//     use rand_core::{OsRng, RngCore};

//     fn create_two_tuns() -> (Tunn, Tunn) {
//         let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
//         let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
//         let my_idx = OsRng.next_u32();

//         let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
//         let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
//         let their_idx = OsRng.next_u32();

//         let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

//         let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

//         (my_tun, their_tun)
//     }

//     fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
//         let mut dst = vec![0u8; 2048];
//         let handshake_init = tun.format_handshake_initiation(&mut dst, false);
//         assert!(matches!(handshake_init, NeptunResult::WriteToNetwork(_)));
//         let handshake_init = if let NeptunResult::WriteToNetwork(sent) = handshake_init {
//             sent
//         } else {
//             unreachable!();
//         };

//         handshake_init.into()
//     }

//     fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
//         let mut dst = vec![0u8; 2048];
//         let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
//         assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

//         let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
//             sent
//         } else {
//             unreachable!();
//         };

//         handshake_resp.into()
//     }

//     fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
//         let mut dst = vec![0u8; 2048];
//         let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
//         assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

//         let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
//             sent
//         } else {
//             unreachable!();
//         };

//         keepalive.into()
//     }

//     fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
//         let mut dst = vec![0u8; 2048];
//         let keepalive = tun.decapsulate(None, keepalive, &mut dst);
//         assert!(matches!(keepalive, TunnResult::Done));
//     }

//     fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
//         let (mut my_tun, mut their_tun) = create_two_tuns();
//         let init = create_handshake_init(&mut my_tun);
//         let resp = create_handshake_response(&mut their_tun, &init);
//         let keepalive = parse_handshake_resp(&mut my_tun, &resp);
//         parse_keepalive(&mut their_tun, &keepalive);

//         (my_tun, their_tun)
//     }

//     fn create_ipv4_udp_packet() -> Vec<u8> {
//         let header =
//             etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
//         let payload = [0, 1, 2, 3];
//         let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
//         header.write(&mut packet, &payload).unwrap();
//         packet
//     }

//     #[cfg(feature = "mock-instant")]
//     fn update_timer_results_in_handshake(tun: &mut Tunn) {
//         let mut dst = vec![0u8; 2048];
//         let result = tun.update_timers(&mut dst);
//         assert!(matches!(result, TunnResult::WriteToNetwork(_)));
//         let packet_data = if let TunnResult::WriteToNetwork(data) = result {
//             data
//         } else {
//             unreachable!();
//         };
//         let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
//         assert!(matches!(packet, Packet::HandshakeInit(_)));
//     }

//     #[test]
//     fn create_two_tunnels_linked_to_eachother() {
//         let (_my_tun, _their_tun) = create_two_tuns();
//     }

//     #[test]
//     fn handshake_init() {
//         let (mut my_tun, _their_tun) = create_two_tuns();
//         let init = create_handshake_init(&mut my_tun);
//         let packet = Tunn::parse_incoming_packet(&init).unwrap();
//         assert!(matches!(packet, Packet::HandshakeInit(_)));
//     }

//     #[test]
//     fn handshake_init_and_response() {
//         let (mut my_tun, mut their_tun) = create_two_tuns();
//         let init = create_handshake_init(&mut my_tun);
//         let resp = create_handshake_response(&mut their_tun, &init);
//         let packet = Tunn::parse_incoming_packet(&resp).unwrap();
//         assert!(matches!(packet, Packet::HandshakeResponse(_)));
//     }

//     #[test]
//     fn full_handshake() {
//         let (mut my_tun, mut their_tun) = create_two_tuns();
//         let init = create_handshake_init(&mut my_tun);
//         let resp = create_handshake_response(&mut their_tun, &init);
//         let keepalive = parse_handshake_resp(&mut my_tun, &resp);
//         let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
//         assert!(matches!(packet, Packet::PacketData(_)));
//     }

//     #[test]
//     fn full_handshake_plus_timers() {
//         let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
//         // Time has not yet advanced so their is nothing to do
//         assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
//         assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
//     }

//     #[test]
//     #[cfg(feature = "mock-instant")]
//     fn new_handshake_after_two_mins() {
//         let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
//         let mut my_dst = [0u8; 1024];

//         // Advance time 1 second and "send" 1 packet so that we send a handshake
//         // after the timeout
//         mock_instant::MockClock::advance(Duration::from_secs(1));
//         assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
//         assert!(matches!(
//             my_tun.update_timers(&mut my_dst),
//             TunnResult::Done
//         ));
//         let sent_packet_buf = create_ipv4_udp_packet();
//         let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
//         assert!(matches!(data, TunnResult::WriteToNetwork(_)));

//         //Advance to timeout
//         mock_instant::MockClock::advance(REKEY_AFTER_TIME);
//         assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
//         update_timer_results_in_handshake(&mut my_tun);
//     }

//     #[test]
//     #[cfg(feature = "mock-instant")]
//     fn handshake_no_resp_rekey_timeout() {
//         let (mut my_tun, _their_tun) = create_two_tuns();

//         let init = create_handshake_init(&mut my_tun);
//         let packet = Tunn::parse_incoming_packet(&init).unwrap();
//         assert!(matches!(packet, Packet::HandshakeInit(_)));

//         mock_instant::MockClock::advance(REKEY_TIMEOUT);
//         update_timer_results_in_handshake(&mut my_tun)
//     }

//     #[test]
//     fn one_ip_packet() {
//         let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
//         let mut my_dst = [0u8; 1024];
//         let mut their_dst = [0u8; 1024];

//         let sent_packet_buf = create_ipv4_udp_packet();

//         let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
//         assert!(matches!(data, TunnResult::WriteToNetwork(_)));
//         let data = if let TunnResult::WriteToNetwork(sent) = data {
//             sent
//         } else {
//             unreachable!();
//         };

//         let data = their_tun.decapsulate(None, data, &mut their_dst);
//         assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
//         let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
//             recv
//         } else {
//             unreachable!();
//         };
//         assert_eq!(sent_packet_buf, recv_packet_buf);
//     }
// }
