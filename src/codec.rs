use std::convert::TryInto;

use bytes::{BufMut, BytesMut};
use prost::Message;

use tokio_util::codec::{Decoder, Encoder};

use crate::proto::NetworkMsg;

// MAX_FRAME_LEN must be the same on all peers.
// Sending a msg larger than the targeting peer's MAX_FRAME_LEN will be rejected.
// I prefer not to add this to config.
const MAX_FRAME_LEN: u32 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("can't decode msg: {0}")]
    InvalidMsg(#[from] prost::DecodeError),
    #[error("msg too large, expect no more than {}, received {0}", MAX_FRAME_LEN)]
    InvalidLength(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("frame limit exceed: {0}")]
    FrameLimitExceed(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy)]
pub struct Codec;

impl Decoder for Codec {
    type Item = NetworkMsg;
    type Error = DecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let header_len = std::mem::size_of::<u32>();
        if src.len() < header_len {
            return Ok(None);
        }

        let content_len = u32::from_be_bytes(src[..4].try_into().unwrap()) as usize;
        let frame_len = header_len + content_len;

        if content_len > MAX_FRAME_LEN as usize {
            return Err(DecodeError::InvalidLength(frame_len));
        }

        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        let frame = src.split_to(frame_len);
        let msg = NetworkMsg::decode(&frame[header_len..])?;
        Ok(Some(msg))
    }
}

impl Encoder<NetworkMsg> for Codec {
    type Error = EncodeError;

    fn encode(&mut self, item: NetworkMsg, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encoded_len = item.encoded_len();
        let frame_len = encoded_len + std::mem::size_of::<u32>();

        if encoded_len > MAX_FRAME_LEN as usize {
            return Err(EncodeError::FrameLimitExceed(encoded_len));
        }

        dst.reserve(frame_len);

        dst.put_u32(encoded_len as u32);
        item.encode(dst).unwrap();

        Ok(())
    }
}
