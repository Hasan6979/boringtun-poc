use super::{session::ReceivingKeyCounterValidator, NeptunResult};
use crate::device::peer::Peer;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use ring::aead::LessSafeKey;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Arc,
};
const MAX_UDP_SIZE: usize = (1 << 14) - 1;

pub const RB_SIZE: usize = 10;

pub struct RingBuffer<T> {
    pub ring_buffer: Vec<T>,
    iter: Mutex<usize>,
}

impl<T> RingBuffer<T> {
    // Returns the next element in ring buffer
    // and moves the ring buffer iterator forward
    pub fn get_next(&mut self) -> (&mut T, usize) {
        let mut idx = self.iter.lock();
        if *idx == RB_SIZE {
            // Reset the write iterator
            *idx = 0;
        }
        let element = &mut self.ring_buffer[*idx];
        let ret_iter = *idx;
        *idx += 1;
        (element, ret_iter)
    }
}

pub struct DecryptionTaskData {
    pub receiver_idx: u32,
    pub counter: u64,
    pub receiving_index: u32,
    pub receiver: Option<Arc<LessSafeKey>>,
    pub receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub peer: Option<Arc<Peer>>,
    pub is_element_free: AtomicBool,
}

pub static mut RX_RING_BUFFER: Lazy<RingBuffer<DecryptionTaskData>> = Lazy::new(|| {
    let mut deque = Vec::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push(DecryptionTaskData {
            receiver_idx: 0,
            counter: 0,
            data: [0u8; MAX_UDP_SIZE],
            buf_len: 0,
            receiver: None,
            receiving_key_counter: Arc::default(),
            receiving_index: 0,
            peer: None,
            is_element_free: AtomicBool::new(true),
        });
    }
    RingBuffer {
        ring_buffer: deque,
        iter: Mutex::new(0),
    }
});

pub struct EncryptionTaskData {
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub sender: Option<Arc<LessSafeKey>>,
    pub sending_key_counter: Arc<AtomicUsize>,
    pub sending_index: u32,
    pub peer: Option<Arc<Peer>>,
    pub is_element_free: AtomicBool,
    pub res: NeptunResult,
}

pub static mut PLAINTEXT_RING_BUFFER: Lazy<RingBuffer<EncryptionTaskData>> = Lazy::new(|| {
    let mut deque = Vec::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push(EncryptionTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            sender: None,
            sending_key_counter: Arc::default(),
            sending_index: 0,
            peer: None,
            is_element_free: AtomicBool::new(true),
            res: NeptunResult::Done,
        });
    }
    RingBuffer {
        ring_buffer: deque,
        iter: Mutex::new(0),
    }
});

pub struct NetworkTaskData {
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub peer: Option<Arc<Peer>>,
    pub res: NeptunResult,
    pub is_element_free: AtomicBool,
}

pub static mut ENCRYPTED_RING_BUFFER: Lazy<RingBuffer<NetworkTaskData>> = Lazy::new(|| {
    let mut deque = Vec::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push(NetworkTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            peer: None,
            res: NeptunResult::Done,
            is_element_free: AtomicBool::new(true),
        });
    }
    RingBuffer {
        ring_buffer: deque,
        iter: AtomicUsize::new(0),
    }
});

pub static mut DECRYPTED_RING_BUFFER: Lazy<RingBuffer<NetworkTaskData>> = Lazy::new(|| {
    let mut deque = Vec::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push(NetworkTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            peer: None,
            res: NeptunResult::Done,
            is_element_free: AtomicBool::new(true),
        });
    }
    RingBuffer {
        ring_buffer: deque,
        iter: Mutex::new(0),
    }
});
