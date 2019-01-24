
// Copyright (C) 2019, Cloudflare, Inc.
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

//mod qpack;
mod frame;

use crate::octets;
use super::Result;

pub struct H3Config {
    pub quiche_config: super::Config,

}

impl H3Config {

    /// Creates a config object with the given version.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(version: u32) -> Result<H3Config> {

        Ok(H3Config {
            quiche_config: super::Config::new(version).unwrap(),
        })
    }
}

/// An HTTP/3 connection.
pub struct H3Connection {
    pub quic_conn: Box<super::Connection>,
}

impl H3Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(scid: &[u8], odcid: Option<&[u8]>, config: &mut H3Config,
           is_server: bool) -> Result<H3Connection> {

            Ok(H3Connection {
                quic_conn: super::Connection::new(scid, None, &mut config.quiche_config, false)?,
            })
    }

    pub fn send_request(&mut self, request: std::string::String ) {
        let reqFrame = frame::H3Frame::Headers{header_block:request.as_bytes().to_vec()};
        let mut d: [u8; 128] = [42; 128];
        let mut b = octets::Octets::with_slice(&mut d);
        reqFrame.to_bytes(&mut b).unwrap();

        self.quic_conn.stream_send(4, &b.to_vec(), true).unwrap();
    }
}

/// Creates a new client-side connection.
///
/// The `scid` parameter is used as the connection's source connection ID,
/// while the optional `server_name` parameter is used to verify the peer's
/// certificate.
pub fn connect(server_name: Option<&str>, scid: &[u8], config: &mut H3Config)
                                                -> Result<H3Connection> {


    let conn = H3Connection::new(scid, None, config, false)?;

    if server_name.is_some() {
        conn.quic_conn.tls_state.set_host_name(server_name.unwrap())
                      .map_err(|_| super::Error::TlsFail)?;
    }

    Ok(conn)
}