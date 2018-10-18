// Copyright (c) 2018, Alessandro Ghedini
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use ::Result;

use std::cmp;
use std::collections::hash_map;
use std::collections::BinaryHeap;
use std::collections::VecDeque;
use std::ops::Deref;

#[derive(Default)]
pub struct Stream {
    recv: RecvBuf,
    send: SendBuf,
}

impl Stream {
    pub fn new() -> Stream {
        Self::default()
    }

    pub fn push_recv(&mut self, buf: RangeBuf) -> Result<()> {
        self.recv.push(buf)
    }

    pub fn pop_recv(&mut self) -> Result<RangeBuf> {
        self.recv.pop()
    }

    pub fn push_send(&mut self, data: &[u8]) -> Result<usize> {
        self.send.push(data)
    }

    pub fn pop_send(&mut self, max_len: usize) -> Result<RangeBuf> {
        self.send.pop(max_len)
    }

    pub fn can_read(&self) -> bool {
        self.recv.ready()
    }

    pub fn can_write(&self) -> bool {
        self.send.ready()
    }
}

pub struct StreamIterator<'a> {
    streams: hash_map::Iter<'a, u64, Stream>,
}

impl<'a> StreamIterator<'a> {
    pub fn new(streams: hash_map::Iter<'a, u64, Stream>) -> StreamIterator {
        StreamIterator {
            streams,
        }
    }
}

impl<'a> Iterator for StreamIterator<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.streams.next() {
                Some((k, s)) => {
                    if !s.can_read() {
                        continue;
                    }

                    return Some(*k);
                },

                None => return None,
            }
        }
    }
}

#[derive(Default)]
struct RecvBuf {
    data: BinaryHeap<RangeBuf>,
    off: usize,
    len: usize,
}

impl RecvBuf {
    fn push(&mut self, buf: RangeBuf) -> Result<()> {
        self.len = cmp::max(self.len, buf.off + buf.len());

        self.data.push(buf);

        Ok(())
    }

    fn pop(&mut self) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();

        while self.ready() {
            let mut buf = match self.data.pop() {
                Some(v) => v,
                None => break,
            };

            self.off += buf.len();
            self.len -= buf.len();

            out.data.append(&mut buf.data);
        }

        Ok(out)
    }

    fn ready(&self) -> bool {
        let buf = match self.data.peek() {
            Some(v) => v,
            None => return false,
        };

        buf.off == self.off
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Default)]
struct SendBuf {
    data: VecDeque<RangeBuf>,
    off: usize,
    len: usize,
}

impl SendBuf {
    fn push(&mut self, data: &[u8]) -> Result<usize> {
        let buf = RangeBuf::from(data, self.off);

        self.len += buf.len();

        self.data.push_back(buf);

        Ok(self.off)
    }

    fn pop(&mut self, max_len: usize) -> Result<RangeBuf> {
        let mut out = RangeBuf::default();
        let mut out_len = max_len;

        while out_len > 0 && self.ready() {
            let mut buf = match self.data.pop_front() {
                Some(v) => v,
                None => break,
            };

            self.off += buf.len();
            self.len -= buf.len();

            out_len -= buf.len();

            out.data.append(&mut buf.data);
        }

        Ok(out)
    }

    fn ready(&self) -> bool {
        self.len() > 0
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug, Default, Eq)]
pub struct RangeBuf {
    data: Vec<u8>,
    off: usize,
}

impl RangeBuf {
    pub fn from(buf: &[u8], off: usize) -> RangeBuf {
        RangeBuf {
            data: Vec::from(buf),
            off,
        }
    }

    pub fn off(&self) -> usize {
        self.off
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.data
    }
}

impl Ord for RangeBuf {
    fn cmp(&self, other: &RangeBuf) -> cmp::Ordering {
        // Invert ordering to implement min-heap.
        self.off.cmp(&other.off).reverse()
    }
}

impl PartialOrd for RangeBuf {
    fn partial_cmp(&self, other: &RangeBuf) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RangeBuf {
    fn eq(&self, other: &RangeBuf) -> bool {
        self.off == other.off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_read() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);
    }

    #[test]
    fn ordered_read() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let first = RangeBuf::from(b"hello", 0);
        let second = RangeBuf::from(b"world", 5);
        let third = RangeBuf::from(b"something", 10);

        assert!(buf.push(second).is_ok());
        assert_eq!(buf.len(), 10);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);

        assert!(buf.push(third).is_ok());
        assert_eq!(buf.len(), 19);

        assert!(buf.push(first).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 19);
        assert_eq!(&read[..], b"helloworldsomething");
        assert_eq!(buf.len(), 0);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);
    }

    #[test]
    fn incomplete_read() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let first = RangeBuf::from(b"something", 0);
        let second = RangeBuf::from(b"helloworld", 9);

        assert!(buf.push(second).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 0);

        assert!(buf.push(first).is_ok());
        assert_eq!(buf.len(), 19);

        let read = buf.pop().unwrap();
        assert_eq!(read.len(), 19);
        assert_eq!(&read[..], b"somethinghelloworld");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn empty_write() {
        let mut buf = RecvBuf::default();
        assert_eq!(buf.len(), 0);

        let write = buf.pop().unwrap();
        assert_eq!(write.len(), 0);
    }

    #[test]
    fn multi_write() {
        let mut buf = SendBuf::default();
        assert_eq!(buf.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(buf.push(&first).is_ok());
        assert_eq!(buf.len(), 9);

        assert!(buf.push(&second).is_ok());
        assert_eq!(buf.len(), 19);

        let write = buf.pop(128).unwrap();
        assert_eq!(write.len(), 19);
        assert_eq!(&write[..], b"somethinghelloworld");
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn split_write() {
        let mut buf = SendBuf::default();
        assert_eq!(buf.len(), 0);

        let first: [u8; 9] = *b"something";
        let second: [u8; 10] = *b"helloworld";

        assert!(buf.push(&first).is_ok());
        assert_eq!(buf.len(), 9);

        assert!(buf.push(&second).is_ok());
        assert_eq!(buf.len(), 19);

        let write = buf.pop(9).unwrap();
        assert_eq!(write.len(), 9);
        assert_eq!(&write[..], b"something");
        assert_eq!(buf.len(), 10);

        let write = buf.pop(10).unwrap();
        assert_eq!(write.len(), 10);
        assert_eq!(&write[..], b"helloworld");
        assert_eq!(buf.len(), 0);
    }
}