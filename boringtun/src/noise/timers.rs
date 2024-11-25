// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::errors::WireGuardError;
use crate::noise::{Tunn, TunnResult};
use std::mem;
use std::ops::{Index, IndexMut};

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;
use parking_lot::Mutex;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

// Some constants, represent time in seconds
// https://www.wireguard.com/papers/wireguard.pdf#page=14
pub(crate) const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub(crate) const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const COOKIE_EXPIRATION_TIME: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy)]
pub enum TimerName {
    /// Current time, updated each call to `update_timers`
    TimeCurrent,
    /// Time when last handshake was completed
    TimeSessionEstablished,
    /// Time the last attempt for a new handshake began
    TimeLastHandshakeStarted,
    /// Time we last received and authenticated a packet
    TimeLastPacketReceived,
    /// Time we last send a packet
    TimeLastPacketSent,
    /// Time we last received and authenticated a DATA packet
    TimeLastDataPacketReceived,
    /// Time we last send a DATA packet
    TimeLastDataPacketSent,
    /// Time we last received a cookie
    TimeCookieReceived,
    /// Time we last sent persistent keepalive
    TimePersistentKeepalive,
    Top,
}

impl TimerName {
    pub const VALUES: [Self; TimerName::Top as usize] = [
        Self::TimeCurrent,
        Self::TimeSessionEstablished,
        Self::TimeLastHandshakeStarted,
        Self::TimeLastPacketReceived,
        Self::TimeLastPacketSent,
        Self::TimeLastDataPacketReceived,
        Self::TimeLastDataPacketSent,
        Self::TimeCookieReceived,
        Self::TimePersistentKeepalive,
    ];
}

use self::TimerName::*;

#[derive(Default, Debug)]
pub struct Timer {
    time: AtomicUsize,
}

impl Timer {
    pub(super) fn time(&self) -> Duration {
        Duration::from_secs(self.time.load(Ordering::Relaxed) as _)
    }

    fn set(&self, val: Duration) {
        self.time.store(val.as_secs() as _, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct Timers {
    /// Is the owner of the timer the initiator or the responder for the last handshake?
    is_initiator: AtomicBool,
    /// Start time of the tunnel
    time_started: Instant,
    timers: [Timer; TimerName::Top as usize],
    pub(super) session_timers: [Timer; super::N_SESSIONS],
    /// Did we receive data without sending anything back?
    want_keepalive: AtomicBool,
    /// Did we send data without hearing back?
    want_handshake: AtomicBool,
    persistent_keepalive: usize,
    /// Should this timer call reset rr function (if not a shared rr instance)
    pub(super) should_reset_rr: AtomicBool,
}

impl Timers {
    pub(super) fn new(persistent_keepalive: Option<u16>, reset_rr: bool) -> Timers {
        Timers {
            is_initiator: AtomicBool::new(false),
            time_started: Instant::now(),
            timers: Default::default(),
            session_timers: Default::default(),
            want_keepalive: Default::default(),
            want_handshake: Default::default(),
            persistent_keepalive: usize::from(persistent_keepalive.unwrap_or(0)),
            should_reset_rr: AtomicBool::new(reset_rr),
        }
    }

    fn is_initiator(&self) -> bool {
        self.is_initiator.load(Ordering::Relaxed)
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    pub(super) fn clear(&self) {
        let now = Instant::now().duration_since(self.time_started);
        for t in &self.timers[..] {
            t.set(now);
        }
        self.want_handshake.store(false, Ordering::Relaxed);
        self.want_keepalive.store(false, Ordering::Relaxed);
    }
}

impl Index<TimerName> for Timers {
    type Output = Timer;
    fn index(&self, index: TimerName) -> &Timer {
        &self.timers[index as usize]
    }
}

// impl IndexMut<TimerName> for Timers {
//     fn index_mut(&mut self, index: TimerName) -> &mut Duration {
//         &mut self.timers[index as usize]
//     }
// }

impl Tunn {
    pub fn mark_timer_to_update(&self, timer_name: TimerName) {
        self.timers_to_update_mask
            .fetch_or(1 << timer_name as u16, Ordering::Relaxed);
    }

    fn timer_tick(&self, timer_name: TimerName) {
        match timer_name {
            TimeLastPacketReceived => {
                self.timers.want_keepalive.store(true, Ordering::Relaxed);
                self.timers.want_handshake.store(false, Ordering::Relaxed);
            }
            TimeLastPacketSent => {
                self.timers.want_handshake.store(true, Ordering::Relaxed);
                self.timers.want_keepalive.store(false, Ordering::Relaxed);
            }
            _ => {}
        }

        self.timers[timer_name].set(self.timers[TimeCurrent].time());
    }

    pub(super) fn timer_tick_session_established(&self, is_initiator: bool, session_idx: usize) {
        self.timer_tick(TimeSessionEstablished);
        self.timers.session_timers[session_idx % crate::noise::N_SESSIONS]
            .set(self.timers[TimeCurrent].time());
        self.timers
            .is_initiator
            .store(is_initiator, Ordering::Relaxed);
    }

    // We don't really clear the timers, but we set them to the current time to
    // so the reference time frame is the same
    fn clear_all(&self) {
        self.clear_sessions();

        self.packet_queue.lock().clear();

        self.timers.clear();
    }

    fn update_session_timers(&self, time_now: Duration) {
        let timers = &self.timers;

        for (i, t) in timers.session_timers.iter().enumerate() {
            if time_now - t.time() > REJECT_AFTER_TIME {
                if let Some(session) = self.sessions.write()[i].take() {
                    tracing::debug!(
                        message = "SESSION_EXPIRED(REJECT_AFTER_TIME)",
                        session = session.receiving_index
                    );
                }
                t.set(time_now);
            }
        }
    }

    pub fn update_timers<'a>(&self, dst: &'a mut [u8]) -> TunnResult<'a> {
        let mut handshake_initiation_required = false;
        let mut keepalive_required = false;

        let time = Instant::now();

        if self.timers.should_reset_rr.load(Ordering::Relaxed) {
            self.rate_limiter.read().reset_count();
        }

        // All the times are counted from tunnel initiation, for efficiency our timers are rounded
        // to a second, as there is no real benefit to having highly accurate timers.
        let now = time.duration_since(self.timers.time_started);
        {
            self.timers[TimeCurrent].set(now);

            // Check which timers to update, and update them
            let timer_mask = self
                .timers_to_update_mask
                .load(std::sync::atomic::Ordering::Relaxed);
            for timer_name in TimerName::VALUES {
                if (timer_mask & (1 << (timer_name as u16))) != 0 {
                    self.timer_tick(timer_name);
                }
            }

            self.update_session_timers(now);
        }

        // Load timers only once:
        let session_established = self.timers[TimeSessionEstablished].time();
        let handshake_started = self.timers[TimeLastHandshakeStarted].time();
        let aut_packet_received = self.timers[TimeLastPacketReceived].time();
        let aut_packet_sent = self.timers[TimeLastPacketSent].time();
        let data_packet_received = self.timers[TimeLastDataPacketReceived].time();
        let data_packet_sent = self.timers[TimeLastDataPacketSent].time();
        let persistent_keepalive = self.timers.persistent_keepalive;

        {
            let mut handshake = match self.handshake.try_lock() {
                Some(handshake) => handshake,
                None => return TunnResult::Done,
            };

            if handshake.is_expired() {
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            // Clear cookie after COOKIE_EXPIRATION_TIME
            if handshake.has_cookie()
                && now - self.timers[TimeCookieReceived].time() >= COOKIE_EXPIRATION_TIME
            {
                handshake.clear_cookie();
            }

            // All ephemeral private keys and symmetric session keys are zeroed out after
            // (REJECT_AFTER_TIME * 3) ms if no new keys have been exchanged.
            if now - session_established >= REJECT_AFTER_TIME * 3 {
                tracing::error!("CONNECTION_EXPIRED(REJECT_AFTER_TIME * 3)");
                handshake.set_expired();
                self.clear_all();
                return TunnResult::Err(WireGuardError::ConnectionExpired);
            }

            if let Some(time_init_sent) = handshake.timer() {
                // Handshake Initiation Retransmission
                if now - handshake_started >= REKEY_ATTEMPT_TIME {
                    // After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake,
                    // the retries give up and cease, and clear all existing packets queued
                    // up to be sent. If a packet is explicitly queued up to be sent, then
                    // this timer is reset.
                    tracing::error!("CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME)");
                    handshake.set_expired();
                    self.clear_all();
                    return TunnResult::Err(WireGuardError::ConnectionExpired);
                }

                if time_init_sent.elapsed() >= REKEY_TIMEOUT {
                    // We avoid using `time` here, because it can be earlier than `time_init_sent`.
                    // Once `checked_duration_since` is stable we can use that.
                    // A handshake initiation is retried after REKEY_TIMEOUT + jitter ms,
                    // if a response has not been received, where jitter is some random
                    // value between 0 and 333 ms.
                    tracing::warn!("HANDSHAKE(REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }
            } else {
                if self.timers.is_initiator() {
                    // After sending a packet, if the sender was the original initiator
                    // of the handshake and if the current session key is REKEY_AFTER_TIME
                    // ms old, we initiate a new handshake. If the sender was the original
                    // responder of the handshake, it does not re-initiate a new handshake
                    // after REKEY_AFTER_TIME ms like the original initiator does.
                    if session_established < data_packet_sent
                        && now - session_established >= REKEY_AFTER_TIME
                    {
                        tracing::debug!("HANDSHAKE(REKEY_AFTER_TIME (on send))");
                        handshake_initiation_required = true;
                    }

                    // After receiving a packet, if the receiver was the original initiator
                    // of the handshake and if the current session key is REJECT_AFTER_TIME
                    // - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new
                    // handshake.
                    if session_established < data_packet_received
                        && now - session_established
                            >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
                    {
                        tracing::warn!(
                            "HANDSHAKE(REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - \
                        REKEY_TIMEOUT \
                        (on receive))"
                        );
                        handshake_initiation_required = true;
                    }
                }

                // If we have sent a packet to a given peer but have not received a
                // packet after from that peer for (KEEPALIVE + REKEY_TIMEOUT) ms,
                // we initiate a new handshake.
                if data_packet_sent > aut_packet_received
                    && now - aut_packet_received >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT
                    && self.timers.want_handshake.swap(false, Ordering::Relaxed)
                {
                    tracing::warn!("HANDSHAKE(KEEPALIVE + REKEY_TIMEOUT)");
                    handshake_initiation_required = true;
                }

                if !handshake_initiation_required {
                    // If a packet has been received from a given peer, but we have not sent one back
                    // to the given peer in KEEPALIVE ms, we send an empty packet.
                    if data_packet_received > aut_packet_sent
                        && now - aut_packet_sent >= KEEPALIVE_TIMEOUT
                        && self.timers.want_keepalive.swap(false, Ordering::Relaxed)
                    {
                        tracing::debug!("KEEPALIVE(KEEPALIVE_TIMEOUT)");
                        keepalive_required = true;
                    }

                    // Persistent KEEPALIVE
                    if persistent_keepalive > 0
                        && (now - self.timers[TimePersistentKeepalive].time()
                            >= Duration::from_secs(persistent_keepalive as _))
                    {
                        tracing::debug!("KEEPALIVE(PERSISTENT_KEEPALIVE)");
                        self.timer_tick(TimePersistentKeepalive);
                        keepalive_required = true;
                    }
                }
            }
        }

        // if handshake_initiation_required {
        //     return self.format_handshake_initiation(dst, true);
        // }

        // if keepalive_required {
        //     return self.encapsulate(&[], dst);
        // }

        TunnResult::Done
    }

    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        let current_session = self.current.load(std::sync::atomic::Ordering::Relaxed);
        if self.sessions.read()[current_session % super::N_SESSIONS].is_some() {
            let duration_since_tun_start = Instant::now().duration_since(self.timers.time_started);
            let duration_since_session_established = self.timers[TimeSessionEstablished].time();

            Some(duration_since_tun_start - duration_since_session_established)
        } else {
            None
        }
    }

    pub fn last_handshake_time(&self) -> Option<std::time::Duration> {
        self.time_since_last_handshake().and_then(|d| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|t| t - d)
        })
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        let keepalive = self.timers.persistent_keepalive;

        if keepalive > 0 {
            Some(keepalive as u16)
        } else {
            None
        }
    }
}
