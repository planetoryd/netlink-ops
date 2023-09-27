use std::{
    fmt::Display,
    ops::Deref,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
use anyhow::Result;
use derivative::Derivative;
use nix::{fcntl::FdFlag, sched::CloneFlags};
use rtnetlink::NetworkNamespace;
use serde::{Deserialize, Serialize};

use crate::*;

#[derive(Debug)]
pub struct Netns {
    pub id: NSID,
    pub netlink: NLStateful,
}

#[derive(Derivative, Serialize, Deserialize, Debug, Clone)]
#[serde_with::skip_serializing_none]
#[derivative(Hash, PartialEq, Eq)]
pub struct NSID {
    /// Only Inode is used as key
    pub inode: u64,
    #[serde(skip)]
    #[serde(default)]
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub path: Option<Arc<PathBuf>>,
}

impl Display for NSID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("[NS{}]", self.inode))
    }
}

pub const NETNS_PATH: &str = "/run/netns";

pub mod flags {
    use bitflags::bitflags;

    bitflags! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct NSCreate: u8 {
            const Path = 1;
            const Named = 2;
        }
    }
}
pub use flags::*;

use crate::netlink::NLStateful;

#[derive(Derivative, Serialize, Deserialize, Clone)]
#[derivative(Debug)]
pub enum NSIDFrom {
    #[derivative(Debug = "transparent")]
    Named(String),
    #[derivative(Debug = "transparent")]
    Pid(Pid),
    #[derivative(Debug = "transparent")]
    Path(PathBuf),
    Root,
    Thread,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, Hash, PartialEq, Eq, Copy)]
#[serde(transparent)]
pub struct Pid(pub u32);

impl NSIDFrom {
    pub async fn ino(path: &Path) -> Result<u64> {
        let file = tokio::fs::File::open(path).await?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(stat.st_ino)
    }
    pub fn ino_sync(path: &Path) -> Result<u64> {
        let file = std::fs::File::open(path)?;
        let stat = nix::sys::stat::fstat(file.as_raw_fd())?;
        Ok(stat.st_ino)
    }
    pub async fn to_id(self, create: NSCreate) -> Result<NSID> {
        let path = self.path();
        if !path.exists() {
            if (create.intersects(NSCreate::Named) && matches!(self, NSIDFrom::Named(_)))
                || (create.intersects(NSCreate::Path) && matches!(self, NSIDFrom::Path(_)))
            {
                NetworkNamespace::add_w_path(&path)?;
            } else {
                bail!("Ns does not exist, creation disabled");
            }
        }
        Ok(NSID {
            inode: Self::ino(&path).await?,
            path: Some(Arc::new(path.to_owned())),
        })
    }
    pub fn to_id_sync(self, create: NSCreate) -> Result<NSID> {
        let path = self.path();
        if !path.exists() {
            if (create.intersects(NSCreate::Named) && matches!(self, NSIDFrom::Named(_)))
                || (create.intersects(NSCreate::Path) && matches!(self, NSIDFrom::Path(_)))
            {
                NetworkNamespace::add_w_path(&path)?;
            } else {
                bail!("Ns does not exist, creation disabled");
            }
        }
        Ok(NSID {
            inode: Self::ino_sync(&path)?,
            path: Some(Arc::new(path.to_owned())),
        })
    }
    pub fn path(&self) -> PathBuf {
        match &self {
            NSIDFrom::Named(p) => Path::new(NETNS_PATH).join(p),
            NSIDFrom::Pid(p) => PathBuf::from(format!("/proc/{}/ns/net", p.0)),
            NSIDFrom::Path(path) => path.to_owned(),
            NSIDFrom::Root => {
                // currently, perceivable, most "root" ns I can get
                NSIDFrom::Pid(Pid(1)).path()
            }
            NSIDFrom::Thread => PathBuf::from("/proc/self/ns/net"),
        }
    }
    pub async fn open(&self) -> Result<NsFile<tokio::fs::File>> {
        let p = self.path();
        let f = tokio::fs::File::open(p).await?;
        Ok(NsFile::<tokio::fs::File>(f))
    }
    pub fn open_sync(&self) -> Result<NsFile<std::fs::File>> {
        let p = self.path();
        let f = std::fs::File::open(p)?;
        Ok(NsFile::<std::fs::File>(f))
    }
    pub fn can_del(&self) -> bool {
        matches!(self, Self::Named(_)) || matches!(self, Self::Path(_))
    }
    pub fn del(&self) -> Result<()> {
        let p = self.path();
        if self.can_del() {
            NetworkNamespace::del_path(&p)?;
        }
        Ok(())
    }
    pub fn exist(&self) -> Result<bool> {
        let p = self.path();
        Ok(p.exists())
    }
}

impl NSID {
    pub async fn open(&self) -> Result<NsFile<tokio::fs::File>> {
        if let Some(path) = &self.path {
            // validated implies path Some
            let f = tokio::fs::File::open(path.deref()).await?;
            Ok(NsFile::<_>(f))
        } else {
            // This happens when you are getting NSID by deserailzing.
            bail!("NSID hasn't been validated. Programming error")
        }
    }
}

pub struct NsFile<F: AsRawFd>(pub F);

impl<F: AsRawFd> NsFile<F> {
    pub fn enter(&self) -> Result<()> {
        nix::sched::setns(self.0.as_raw_fd(), CloneFlags::CLONE_NEWNET)?;
        Ok(())
    }
    pub fn set_cloexec(&self) -> Result<i32> {
        self.0.set_cloexec()
    }
    pub fn unset_cloexec(&self) -> Result<i32> {
        self.0.unset_cloexec()
    }
}

pub trait Fcntl: AsRawFd {
    /// This flag specifies that the file descriptor should be closed when an exec function is invoked
    fn set_cloexec(&self) -> Result<i32> {
        nix::fcntl::fcntl(
            self.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
        )
        .map_err(anyhow::Error::from)
    }
    fn unset_cloexec(&self) -> Result<i32> {
        nix::fcntl::fcntl(
            self.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFD(FdFlag::empty()),
        )
        .map_err(anyhow::Error::from)
    }
}

impl<F: AsRawFd> Fcntl for F {}
