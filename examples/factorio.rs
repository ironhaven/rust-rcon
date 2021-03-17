use rcon::{Connection, Error, Quirks};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let address = "localhost:1234";
    let mut conn = Connection::builder()
        .enable_factorio_quirks(true)
        .connect(address, "test").await?;

    demo(&mut conn, "/c print('hello')").await?;
    demo(&mut conn, "/c print('world')").await?;
    println!("commands finished");

    Ok(())
}

async fn demo<Q: Quirks>(conn: &mut Connection<Q>, cmd: &str) -> Result<(), Error> {
    println!("request: {}", cmd);
    let resp = conn.cmd(cmd).await?;
    println!("response: {}", resp);
    Ok(())
}
