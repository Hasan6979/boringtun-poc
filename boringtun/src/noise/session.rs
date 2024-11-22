// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{
    ring_buffers::{
        DecryptionTaskData, EncryptionTaskData, NetworkTaskData, DECRYPTED_RING_BUFFER,
        ENCRYPTED_RING_BUFFER, PLAINTEXT_RING_BUFFER, RB_SIZE, RX_RING_BUFFER,
    },
    NeptunResult, PacketData, Tunn,
};
use crate::noise::errors::WireGuardError;
use crossbeam::channel::{Receiver, Sender};
use parking_lot::Mutex;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

pub struct Session {
    pub receiving_index: u32,
    pub sending_index: u32,
    pub receiver: Arc<LessSafeKey>,
    pub sender: Arc<LessSafeKey>,
    pub sending_key_counter: Arc<AtomicUsize>,
    pub receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
}

static mut ENCRYPT_ITER: usize = 0;
static mut DECRYPT_ITER: usize = 0;

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
pub struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Clear the word that contains idx
    #[inline(always)]
    fn clear_word(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        self.bitmap[word] = 0;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        if counter - self.next >= N_BITS {
            // Too far ahead, clear all the bits
            for c in self.bitmap.iter_mut() {
                *c = 0;
            }
        } else {
            let mut i = self.next;
            while i % WORD_SIZE != 0 && i < counter {
                // Clear until i aligned to word size
                self.clear_bit(i);
                i += 1;
            }
            while i + WORD_SIZE < counter {
                // Clear whole word at a time
                self.clear_word(i);
                i = (i + WORD_SIZE) & 0u64.wrapping_sub(WORD_SIZE);
            }
            while i < counter {
                // Clear any remaining bits
                self.clear_bit(i);
                i += 1;
            }
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: Arc::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            )),
            sender: Arc::new(LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap(),
            )),
            sending_key_counter: Arc::new(AtomicUsize::new(0)),
            receiving_key_counter: Arc::new(Mutex::new(Default::default())),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(
        receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
        counter: u64,
    ) -> Result<(), WireGuardError> {
        let counter_validator = receiving_key_counter.lock();
        counter_validator.will_accept(counter)
    }

    /// Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(
        receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
        counter: u64,
    ) -> Result<(), WireGuardError> {
        let mut counter_validator = receiving_key_counter.lock();
        let ret = counter_validator.mark_did_receive(counter);
        if ret.is_ok() {
            counter_validator.receive_cnt += 1;
        }
        ret
    }

    pub fn encrypt_data_worker(
        encrypt_rx: Receiver<&EncryptionTaskData>,
        network_tx: Sender<&NetworkTaskData>,
    ) {
        while let Ok(encryption_data) = encrypt_rx.recv() {
            let network_data = unsafe { &mut ENCRYPTED_RING_BUFFER[ENCRYPT_ITER] };
            if network_data.is_element_free.load(Ordering::Relaxed) {
                let data_len = encryption_data.buf_len;
                let (_, data_len) = Session::encrypt_data_pkt(
                    encryption_data.sending_key_counter.clone(),
                    encryption_data.sending_index,
                    encryption_data.sender.as_ref().unwrap().clone(),
                    &encryption_data.data.as_slice()[..data_len],
                    network_data.data.as_mut_slice(),
                );
                network_data.peer = Some(encryption_data.peer.as_ref().unwrap().clone());
                network_data.buf_len = data_len;
                network_data.res = NeptunResult::WriteToNetwork(data_len);

                network_data.is_element_free.store(false, Ordering::Relaxed);
                let _ = network_tx.send(network_data);
            }
            if unsafe { ENCRYPT_ITER != (RB_SIZE - 1) } {
                unsafe { ENCRYPT_ITER += 1 };
            } else {
                // Reset the write iterator
                unsafe { ENCRYPT_ITER = 0 };
            }
            encryption_data
                .is_element_free
                .store(true, Ordering::Relaxed);
        }
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    pub fn encrypt_data_pkt<'a>(
        sending_key_counter: Arc<AtomicUsize>,
        sending_index: u32,
        sender: Arc<LessSafeKey>,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> (&'a mut [u8], usize) {
        if dst.len() < src.len() + super::DATA_OVERHEAD_SZ {
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            data[..src.len()].copy_from_slice(src);
            sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..src.len()],
                )
                .map(|tag| {
                    data[src.len()..src.len() + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    src.len() + AEAD_SIZE
                })
                .unwrap()
        };

        (&mut dst[..DATA_OFFSET + n], DATA_OFFSET + n)
    }

    pub fn decrypt_data_worker(
        decrypt_rx: Receiver<&DecryptionTaskData>,
        tunnel_tx: Sender<&NetworkTaskData>,
    ) {
        while let Ok(decryption_data) = decrypt_rx.recv() {
            let network_data = unsafe { &mut DECRYPTED_RING_BUFFER[DECRYPT_ITER] };
            if network_data.is_element_free.load(Ordering::Relaxed) {
                let data_len = decryption_data.buf_len;
                let decapsulated_packet = Session::decrypt_data_pkt(
                    PacketData {
                        receiver_idx: u32::from_le_bytes(
                            decryption_data.data[4..8].try_into().unwrap(),
                        ),
                        counter: decryption_data.counter,
                        encrypted_encapsulated_packet: &decryption_data.data[16..data_len],
                    },
                    decryption_data.receiving_index,
                    decryption_data.receiver.as_ref().unwrap().clone(),
                    decryption_data.receiving_key_counter.clone(),
                    network_data.data.as_mut_slice(),
                );
                network_data.res = match decapsulated_packet {
                    Ok(len) => Tunn::validate_decapsulated_packet(
                        &mut network_data.data.as_mut_slice()[..len],
                    ),
                    Err(e) => NeptunResult::Err(e),
                };
                network_data.peer = Some(decryption_data.peer.as_ref().unwrap().clone());

                network_data.is_element_free.store(false, Ordering::Relaxed);
                let _ = tunnel_tx.send(network_data);

                if unsafe { DECRYPT_ITER != (RB_SIZE - 1) } {
                    unsafe { DECRYPT_ITER += 1 };
                } else {
                    // Reset the write iterator
                    unsafe { DECRYPT_ITER = 0 };
                }
                decryption_data
                    .is_element_free
                    .store(true, Ordering::Relaxed);
            }
        }
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub fn decrypt_data_pkt<'a>(
        packet: PacketData,
        receiving_index: u32,
        receiver: Arc<LessSafeKey>,
        receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
        dst: &'a mut [u8],
    ) -> Result<usize, WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        if packet.receiver_idx != receiving_index {
            tracing::debug!("pkt rx {} rx_idx {}", packet.receiver_idx, receiving_index);
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        Session::receiving_counter_quick_check(receiving_key_counter.clone(), packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
            receiver
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut dst[..ct_len],
                )
                .map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        Session::receiving_counter_mark(receiving_key_counter.clone(), packet.counter)?;
        Ok(ret.len())
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let counter_validator = self.receiving_key_counter.lock();
        (counter_validator.next, counter_validator.receive_cnt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_task() {
        let local_index = 1;
        let peer_index = 1;
        let receiving_key = [1; 32];
        let sending_key = [2; 32];
        let (tx, rx) = crossbeam::channel::bounded(10);
        let (tx1, rx1) = crossbeam::channel::bounded(10);
        let session = Session::new(local_index, peer_index, receiving_key, sending_key);

        let rx_clone = rx.clone();
        std::thread::spawn(move || Session::encrypt_data_worker(rx_clone, tx1));

        // Generate some data
        if let Some(item) = unsafe { PLAINTEXT_RING_BUFFER.get_mut(0) } {
            {
                let x = item.data.as_mut_slice();
                for i in 0..10 {
                    x[i] = i as u8;
                }
                item.sender = Some(session.sender.clone());
                item.sending_index = session.sending_index;
                item.buf_len = 10;
                println!("data {:?}", &item.data[..item.buf_len]);
                item.sending_key_counter = session.sending_key_counter.clone();
            }
            let _ = tx.send(item);
        }
        if rx1.recv().is_ok() {
            if let Some(en_msg) = unsafe { ENCRYPTED_RING_BUFFER.pop_back() } {
                let src = &en_msg.data[..en_msg.buf_len];
                println!("encrypted data {:?}", src);
                unsafe {
                    ENCRYPTED_RING_BUFFER.push_front(en_msg);
                }
            }
        }
    }

    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
