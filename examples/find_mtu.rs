use std::sync::Arc;

use anyhow::Result;
use netlink_ops::netlink::{NLDriver, NLHandle, VPairKey};
use tokio::main;

// Run this in a new netns
#[main]
async fn main() -> Result<()> {
    let wh = NLHandle::new_self_proc_tokio()?;
    let mut nl = NLDriver::new(wh);
    nl.fill().await?;
    dbg!(nl);

    Ok(())
}
