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
use std::{f32::MIN, io};
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};

mod packet;

const INITIAL_PACKET_ID: i32 = 1;
const DELAY_TIME_MILLIS: u64 = 3;
const MINECRAFT_MAX_PAYLOAD_SIZE: usize = 1413;

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

pub trait Quirks {
    fn limit_payload_size(&self) -> bool;
    fn add_packet_delay(&self) -> bool;
    fn use_single_packet(&self) -> bool;
}

pub struct Minecraft;

impl Quirks for Minecraft {
    fn limit_payload_size(&self) -> bool {
        true
    }

    fn add_packet_delay(&self) -> bool {
        true
    }

    fn use_single_packet(&self) -> bool {
        false
    }
}

pub struct Connection<Q: Quirks> {
    stream: TcpStream,
    next_packet_id: i32,
    quirks: Q
}

impl Connection<QuirkBuilder> {
    /// Create a connectiion builder.
    /// Allows configuring the rcon connection.
    pub fn builder() -> QuirkBuilder {
        QuirkBuilder::new()
    }
}

impl<Q: Quirks>  Connection<Q> {
    /// Connect to an rcon server.
    /// By default this enables minecraft quirks.
    /// If you need to customize this behaviour, use a Builder.
    pub async fn connect<T: ToSocketAddrs>(address: T, password: &str) -> Result<Connection<Minecraft>> {
        let stream = TcpStream::connect(address).await?;
        let mut conn = Connection {
            stream,
            next_packet_id: INITIAL_PACKET_ID,
            quirks: Minecraft
        };

        conn.auth(password).await?;

        Ok(conn)
    }

    pub async fn cmd(&mut self, cmd: &str) -> Result<String> {
        if self.quirks.limit_payload_size() && cmd.len() > MINECRAFT_MAX_PAYLOAD_SIZE {
            return Err(Error::CommandTooLong);
        }

        self.send(PacketType::ExecCommand, cmd).await?;

        if self.quirks.add_packet_delay() {
            tokio::time::sleep(Duration::from_millis(DELAY_TIME_MILLIS)).await;
        }

        let response = self.receive_response().await?;

        Ok(response)
    }

    async fn receive_response(&mut self) -> Result<String> {
        if self.quirks.use_single_packet() {
            self.receive_single_packet_response().await
        } else {
            self.receive_multi_packet_response().await
        }
    }

    async fn receive_single_packet_response(&mut self) -> Result<String> {
        let received_packet = self.receive_packet().await?;

        Ok(received_packet.get_body().into())
    }

    async fn receive_multi_packet_response(&mut self) -> Result<String> {
        // the server processes packets in order, so send an empty packet and
        // remember its id to detect the end of a multi-packet response
        let end_id = self.send(PacketType::ExecCommand, "").await?;

        let mut result = String::new();

        loop {
            let received_packet = self.receive_packet().await?;

            if received_packet.get_id() == end_id {
                // This is the response to the end-marker packet
                return Ok(result);
            }

            result += received_packet.get_body();
        }
    }

    async fn auth(&mut self, password: &str) -> Result<()> {
        self.send(PacketType::Auth, password).await?;
        let received_packet = loop {
            let received_packet = self.receive_packet().await?;
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

    async fn receive_packet(&mut self) -> io::Result<Packet> {
        Packet::deserialize(&mut self.stream).await
    }

    fn generate_packet_id(&mut self) -> i32 {
        let id = self.next_packet_id;

        // only use positive ids as the server uses negative ids to signal
        // a failed authentication request
        self.next_packet_id = self
            .next_packet_id
            .checked_add(1)
            .unwrap_or(INITIAL_PACKET_ID);

        id
    }
}

#[derive(Default, Debug)]
pub struct QuirkBuilder {
    limit_payload_size: bool,
    add_packet_delay: bool,
    use_single_packet: bool
}

impl Quirks for QuirkBuilder {
    fn limit_payload_size(&self) -> bool {
        self.limit_payload_size
    }

    fn add_packet_delay(&self) -> bool {
        self.add_packet_delay
    }

    fn use_single_packet(&self) -> bool {
        self.use_single_packet
    }
}

impl QuirkBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// This enables the following quirks for Minecraft:
    ///
    /// Commands are delayed by 3ms to reduce the chance of crashing the server.
    /// See https://bugs.mojang.com/browse/MC-72390
    ///
    /// The command length is limited to 1413 bytes.
    /// Tests have shown the server to not work reliably
    /// with greater command lengths.
    pub fn enable_minecraft_quirks(mut self, value: bool) -> Self {
        self.limit_payload_size = value;
        self.add_packet_delay = value;
        self
    }

    /// This enables the following quirks for Factorio:
    ///
    /// Only single-packet responses are enabled.
    /// Multi-packets appear to work differently than in other server implementations
    /// (an empty packet gives no response).
    pub fn enable_factorio_quirks(mut self, value: bool) -> Self {
        self.use_single_packet = value;
        self
    }

    pub async fn connect<A>(self, address: A, password: &str) -> Result<Connection<QuirkBuilder>>
    where
        A: ToSocketAddrs
    {
        let stream = TcpStream::connect(address).await?;
        let mut conn = Connection {
            stream,
            next_packet_id: INITIAL_PACKET_ID,
            quirks: self
        };

        conn.auth(password).await?;

        Ok(conn)
    }
}
