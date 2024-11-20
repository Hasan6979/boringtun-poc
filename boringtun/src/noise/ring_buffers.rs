use super::{session::ReceivingKeyCounterValidator, NeptunResult, PacketData};
use crate::device::peer::Peer;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use ring::aead::LessSafeKey;
use std::{
    collections::VecDeque,
    sync::{atomic::AtomicUsize, Arc},
};
const MAX_UDP_SIZE: usize = (1 << 16) - 1;

pub const RB_SIZE: usize = 100;

pub struct DecryptionTaskData {
    pub receiver_idx: u32,
    pub counter: u64,
    pub receiving_index: u32,
    pub receiver: Option<Arc<LessSafeKey>>,
    pub receiving_key_counter: Arc<Mutex<ReceivingKeyCounterValidator>>,
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub peer: Option<Arc<Peer>>,
}

pub static mut RX_RING_BUFFER: Lazy<VecDeque<Mutex<DecryptionTaskData>>> = Lazy::new(|| {
    let mut deque = VecDeque::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push_back(Mutex::new(DecryptionTaskData {
            receiver_idx: 0,
            counter: 0,
            data: [0u8; MAX_UDP_SIZE],
            buf_len: 0,
            receiver: None,
            receiving_key_counter: Arc::default(),
            receiving_index: 0,
            peer: None,
        }));
    }
    deque
});

pub struct EncryptionTaskData {
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub sender: Option<Arc<LessSafeKey>>,
    pub sending_key_counter: Arc<AtomicUsize>,
    pub sending_index: u32,
    pub peer: Option<Arc<Peer>>,
}

pub static mut PLAINTEXT_RING_BUFFER: Lazy<VecDeque<Mutex<EncryptionTaskData>>> = Lazy::new(|| {
    let mut deque = VecDeque::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push_back(Mutex::new(EncryptionTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            sender: None,
            sending_key_counter: Arc::default(),
            sending_index: 0,
            peer: None,
        }));
    }
    deque
});

pub struct NetworkTaskData {
    pub data: [u8; MAX_UDP_SIZE],
    pub buf_len: usize,
    pub peer: Option<Arc<Peer>>,
    pub res: NeptunResult,
}

pub static mut ENCRYPTED_RING_BUFFER: Lazy<VecDeque<Mutex<NetworkTaskData>>> = Lazy::new(|| {
    let mut deque = VecDeque::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push_back(Mutex::new(NetworkTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            peer: None,
            res: NeptunResult::Done,
        }));
    }
    deque
});

pub static mut DECRYPTED_RING_BUFFER: Lazy<VecDeque<Mutex<NetworkTaskData>>> = Lazy::new(|| {
    let mut deque = VecDeque::with_capacity(RB_SIZE);
    for _ in 0..RB_SIZE {
        deque.push_back(Mutex::new(NetworkTaskData {
            data: [0; MAX_UDP_SIZE],
            buf_len: 0,
            peer: None,
            res: NeptunResult::Done,
        }));
    }
    deque
});
