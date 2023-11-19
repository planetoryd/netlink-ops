use std::sync::Arc;

use anyhow::Result;
use netlink_ops::netlink::{NLHandle, NLStateful, NLWrapped, VPairKey};
use tokio::main;

// Run this in a new netns
#[main]
async fn main() -> Result<()> {
    let wh = NLWrapped::new(NLHandle::new_self_proc_tokio()?);
    let mut nl = NLStateful::new(&wh);
    nl.new_veth_pair("ve1".parse()?).await?;
    let mut nl = NLStateful::new(&wh);
    nl.fill().await?;
    dbg!(&nl);
    Ok(())
}
