// Copyright (c) 2015 [rust-rcon developers]
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use err_derive::Error;
use packet::{Packet, PacketType};
use std::io;
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::delay_for;

mod packet;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "authentication failed")]
    Auth,
    #[error(display = "command exceeds the maximum length")]
    CommandTooLong,
    #[error(display = "{}", _0)]
    Io(#[error(source)] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Connection {
    stream: TcpStream,
    next_packet_id: i32,
}

fn initial_packet_id() -> i32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    // State seeded by the os rng on first use here or in a hash map
    // Each call to new increments the state
    let s = RandomState::new();

    // SipHash is the default hashing algorithm for rust Because SipHash
    // is a MAC an attacker should not be able to predict the value of state
    // by the hash result. Even without hashing anything the state of the
    // secret is protected and not let attackers predict future packet ids
    let hash: u64 = s.build_hasher().finish();

    // Use all 64 bits of hash and makes it more dificult to get the state
    // The absolute value op removes 1 bit of randomness but that is fine
    ((hash ^ hash >> 32) as i32)
        // On abs overflow you get a negative value. This corrects for that.
        .checked_abs()
        .unwrap_or(PACKET_ID_START)
}

const PACKET_ID_START: i32 = 1;

const DELAY_TIME_MILLIS: u64 = 3;

impl Connection {
    pub async fn connect<T: ToSocketAddrs>(address: T, password: &str) -> Result<Connection> {
        let stream = TcpStream::connect(address).await?;
        let mut conn = Connection {
            stream,
            next_packet_id: initial_packet_id(),
        };

        conn.auth(password).await?;

        Ok(conn)
    }

    pub async fn cmd(&mut self, cmd: &str) -> Result<String> {
        // Minecraft only supports a request payload length of max 1446 byte.
        // However some tests showed that only requests with a payload length
        // of 1413 byte or lower work reliable.
        if cmd.len() > 1413 {
            return Err(Error::CommandTooLong);
        }

        self.send(PacketType::ExecCommand, cmd).await?;

        if cfg!(feature = "delay") {
            // We are simply too swift for the Notchian minecraft server
            // Give it some time to breath and not kill out connection
            // Issue described here https://bugs.mojang.com/browse/MC-72390
            delay_for(Duration::from_millis(DELAY_TIME_MILLIS)).await;
        }

        // the server processes packets in order, so send an empty packet and
        // remember its id to detect the end of a multi-packet response
        let end_id = self.send(PacketType::ExecCommand, "").await?;

        let mut result = String::new();

        loop {
            let received_packet = self.recv().await?;

            if received_packet.get_id() == end_id {
                // This is the response to the end-marker packet
                break;
            }

            result += received_packet.get_body();
        }

        Ok(result)
    }

    async fn auth(&mut self, password: &str) -> Result<()> {
        self.send(PacketType::Auth, password).await?;
        let received_packet = loop {
            let received_packet = self.recv().await?;
            if received_packet.get_type() == PacketType::AuthResponse {
                break received_packet;
            }
        };

        if received_packet.is_error() {
            Err(Error::Auth)
        } else {
            Ok(())
        }
    }

    async fn send(&mut self, ptype: PacketType, body: &str) -> io::Result<i32> {
        let id = self.generate_packet_id();

        let packet = Packet::new(id, ptype, body.into());

        packet.serialize(&mut self.stream).await?;

        Ok(id)
    }

    async fn recv(&mut self) -> io::Result<Packet> {
        Packet::deserialize(&mut self.stream).await
    }

    fn generate_packet_id(&mut self) -> i32 {
        let id = self.next_packet_id;

        // only use positive ids as the server uses negative ids to signal
        // a failed authentication request
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .unwrap_or(PACKET_ID_START);

        id
    }
}
