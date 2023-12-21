use crate::nft::{redirect_dns, Mergeable, NftState};
use derivative::Derivative;

use fixed_map::{Key, Map};
use fully_pub::fully_pub;
use futures::{future::Ready, Future, FutureExt, SinkExt, StreamExt, TryFutureExt};
use ipnetwork::IpNetwork;

use libc::pid_t;
use nsproxy_common::{ExactNS, NSFrom, NSSource, PidPath};
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{oneshot, RwLock},
};

use anyhow::{anyhow, bail, Ok, Result};

use nix::{fcntl::FdFlag, sched::CloneFlags};

use std::{
    any::{Any, TypeId},
    collections::{BTreeMap, BTreeSet, HashSet},
    default,
    fmt::Debug,
    hash::Hash,
    net::Ipv6Addr,
    ops::{Deref, Index},
    os::fd::{AsFd, FromRawFd},
    pin::Pin,
    process::Stdio,
    str::FromStr,
    sync::Arc,
};

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{
    ffi::OsString,
    net::Ipv4Addr,
    os::fd::RawFd,
    path::{Path, PathBuf},
};
use tokio::{self, fs::File, io::AsyncReadExt};

use rtnetlink::{
    netlink_packet_route::{nlas::link::InfoKind, rtnl::link::nlas, IFF_LOWER_UP},
    netlink_proto::{new_connection_from_socket, NetlinkCodec},
    netlink_sys::{protocols::NETLINK_ROUTE, AsyncSocket, TokioSocket},
};

use crate::errors::*;
use crate::state::*;
use crate::*;
use derive_new::new;

/// Creates an RAII context
pub macro nl_ctx( $sub:ident, $conn:ident, $nl:expr ) {
    let (mut $sub, mut $conn) = $nl.$sub();
}

use futures::stream::TryStreamExt;
use rtnetlink::netlink_packet_route::{rtnl::link::LinkMessage, AddressMessage, IFF_UP};
use rtnetlink::{Handle, NetworkNamespace};

#[derive(Clone, Debug, derive_new::new, Derivative)]
#[derivative(PartialEq, Eq)]
/// Handle with relevant information
/// Eq iff NS equals
pub struct NLHandle {
    #[derivative(PartialEq = "ignore")]
    pub rawh: Handle,
    pub id: ExactNS,
}

#[derive(Derivative, new)]
#[derivative(PartialEq, Eq, Debug)]
/// Netlink manipulator with locally duplicated state
pub struct NLDriver {
    #[derivative(PartialEq = "ignore")]
    #[derivative(Debug = "ignore")]
    pub conn: NLHandle,
    #[new(default)]
    veths: BTreeMap<VPairKey, VethPair>,
    #[new(default)]
    /// msg.header.index
    links_index: BTreeMap<u32, LinkKey>,
    #[new(default)]
    links: BTreeMap<LinkKey, Existence<LinkDev>>,
    #[new(default)]
    routes: HashMap<RouteFor, Existence<()>>,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum RouteFor {
    TUNIpv4,
    TUNIpv6,
}

pub trait GetPidOrFd {
    fn open(&self) -> Result<PidOrFd>;
}

impl GetPidOrFd for NLHandle {
    fn open(&self) -> Result<PidOrFd> {
        Ok(match &self.id.source {
            NSSource::Pid(p) => PidOrFd::Pid((*p).try_into()?),
            NSSource::Path(p) => PidOrFd::Fd(Box::new(std::fs::File::open(&p)?)),
            NSSource::Unavail => unreachable!(),
        })
    }
}

#[fully_pub]
impl NLHandle {
    async fn set_up(&self, link: &mut LinkDev) -> Result<()> {
        if link.up.get() == Some(&true) {
            Ok(())
        } else {
            self.set_link_up(link.index).await?;
            link.up.trans_to(Exp::Expect(true))?;
            Ok(())
        }
    }
    async fn add_addr(&mut self, link: &mut LinkDev, ip: IpNetwork) -> Result<()> {
        if let Result::Ok(k) = link.addrs.filled()?.not_absent(&ip)
            && (matches!(k, Existence::Exist(_)) || matches!(k, Existence::ShouldExist))
        {
            // we don't error here.
        } else {
            link.addrs
                .filled()?
                .trans_to(&ip, LExistence::ShouldExist)
                .await?;
            self.add_addr_dev(ip, link.index).await?;
        }
        Ok(())
    }
    async fn remove_addr(&mut self, link: &mut LinkDev, addr: IpNetwork) -> Result<()> {
        let msg = link.addrs.filled()?.not_absent(&addr)?;
        let swap = msg.trans_to(LExistence::ExpectAbsent).await?;

        self.rawh.address().del(swap.exist()?).execute().await?;
        Ok(())
    }
    async fn remove_addrs(&mut self, link: &mut LinkDev, addrs: Vec<IpNetwork>) -> Result<()> {
        for addr in addrs {
            self.remove_addr(link, addr).await?;
        }
        Ok(())
    }
    async fn ensure_addrs_46(
        &mut self,
        link: &mut LinkDev,
        v4: IpNetwork,
        v6: IpNetwork,
    ) -> Result<()> {
        self.add_addr(link, v4).await?;
        self.add_addr(link, v6).await?;
        let mut pending: Vec<IpNetwork> = Default::default();
        for (k, msg) in link.addrs.filled()? {
            if *k != v4 && *k != v6 && matches!(msg, Existence::Exist(_)) {
                pending.push(k.clone());
            }
        }
        self.remove_addrs(link, pending).await?;
        Ok(())
    }
}

/// Use .parse()
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
pub struct LinkKey(String);

impl FromStr for LinkKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > 15 {
            bail!("Link name too long");
        }
        Result::Ok(LinkKey(s.to_owned()))
    }
}

impl From<LinkKey> for String {
    fn from(value: LinkKey) -> Self {
        value.0
    }
}

/// Use .parse()
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Clone, Debug, PartialOrd, Ord)]
pub struct VPairKey(String);

impl FromStr for VPairKey {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() > 11 {
            bail!("Veth base name too long");
        }
        Result::Ok(VPairKey(s.to_owned()))
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Key, Copy)]
pub enum LinkAB {
    /// Subject
    A,
    /// Target
    B,
}

impl VPairKey {
    pub fn link(&self, ab: LinkAB) -> LinkKey {
        let basename = &self.0;

        LinkKey(match ab {
            LinkAB::A => format!("{basename}_a"),
            LinkAB::B => format!("{basename}_b"),
        })
    }
    pub fn parse(k: &LinkKey) -> Option<(VPairKey, LinkAB)> {
        let name = &k.0;
        let tr = name.split_at(name.len() - 2).0.to_owned();
        if name.ends_with("_a") {
            Some((VPairKey(tr), LinkAB::A))
        } else if name.ends_with("_b") {
            Some((VPairKey(tr), LinkAB::B))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum VPairP {
    A,
    B,
    Both,
}

impl Trans for LinkKey {
    fn trans(&self, to: &Self) -> bool {
        self == to
    }
}

fn new_link_ctx<'m>(
    links: &'m mut BTreeMap<LinkKey, Existence<LinkDev>>,
    veths: &'m mut BTreeMap<VPairKey, VethPair>,
) -> NLCtx<
    'm,
    LinkKey,
    BTreeMap<LinkKey, Existence<LinkDev>>,
    impl FnMut(&LinkKey, Option<&mut Existence<LinkDev>>) + 'm,
> {
    NLCtx {
        map: links,
        set: |k, v| {
            if let Some((vp, ab)) = VPairKey::parse(k) {
                if let Some(v) = v {
                    match v {
                        Existence::Exist(att) => {
                            let pass = if let Some(k) = &att.kind {
                                matches!(k, InfoKind::Veth)
                            } else {
                                true
                            };
                            if pass {
                                att.pair = Some(vp.clone());
                            }
                        }
                        _ => (),
                    }
                    veths.set_dep(&vp, &ab, v.to(k.to_owned()));
                } else {
                    veths.set_absent_dep(&vp, &ab);
                }
            }
        },
        _k: Default::default(),
    }
}

#[fully_pub]
impl NLDriver {
    /// Get a context to manipulate link objects
    /// Loans many references out.
    fn link<'m>(
        &'m mut self,
    ) -> (
        NLCtx<
            'm,
            LinkKey,
            BTreeMap<LinkKey, Existence<LinkDev>>,
            impl FnMut(&LinkKey, Option<&mut Existence<LinkDev>>) + 'm,
        >,
        &mut NLHandle,
    ) {
        (
            new_link_ctx(&mut self.links, &mut self.veths),
            &mut self.conn,
        )
    }
    async fn fill(&mut self) -> Result<()> {
        let netlink = &self.conn;
        let mut links = netlink.rawh.link().get().execute();
        while let Some(link) = links.try_next().await? {
            let mut li: LinkDev = link.try_into()?;
            li.addrs.to_filled()?;
            let Self { links, veths, .. } = self;
            let mut link = new_link_ctx(links, veths);
            let lk: LinkKey = li.name.as_ref().ok_or(DevianceError)?.parse()?;
            let index = li.index;
            link.fill(&lk, Existence::Exist(li))?;
            let k = self.links_index.insert(index, lk);
            assert!(k.is_none());
        }
        // the filter is not done by kernel. hence just do it here.
        let addrs = netlink.rawh.address().get().execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        for addr in addrs.into_iter() {
            let index_of_the_link_too = addr.header.index.clone(); // as observed.
            let mut ipnet: Option<IpNetwork> = None;
            for msg in addr.nlas.iter() {
                match msg {
                    rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                        // one addr msg for one addr I guess ?
                        if ipnet.is_some() {
                            log::warn!("More than one address in one AddressMessage, {:?}", addr);
                            break;
                        }
                        if a.len() == 4 {
                            let con: [u8; 4] = a.to_owned().try_into().unwrap();
                            let ip4: Ipv4Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip4.into(), addr.header.prefix_len)?);
                        } else if a.len() == 16 {
                            let con: [u8; 16] = a.to_owned().try_into().unwrap();
                            let ip6: Ipv6Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip6.into(), addr.header.prefix_len)?);
                        }
                    }
                    _ => (),
                }
            }
            let exp = btreemap_chain_mut(
                &mut self.links_index,
                &mut self.links,
                &index_of_the_link_too,
            )
            .unwrap()
            .exist_mut()?
            .addrs
            .to_filled()?;
            if let Some(ip) = ipnet {
                exp.fill(&ip, Existence::Exist(addr))?;
            }
        }
        Ok(())
    }

    // Some methods change state of self, which are therefore placed here
    async fn remove_link<'at>(&'at mut self, k: &'at LinkKey) -> Result<LinkDev> {
        // we want to reflect the state of links as that vector
        log::trace!("remove link {:?}", k);
        nl_ctx!(link, conn, self);
        // It needs link.index
        let link_removed = link.nset(k, Existence::ExpectAbsent)?.exist()?;
        conn.rm_link(link_removed.index).await?;
        Ok(link_removed)
    }
    /// move link from this ns to dst
    async fn move_link_to_ns(
        &mut self,
        k: &LinkKey,
        dst: &mut NLDriver,
        pf: &PidOrFd,
    ) -> Result<()> {
        self.refresh_link(k.to_owned()).await?;
        nl_ctx!(link, conn, self);

        let v = link.nset(k, Existence::ExpectAbsent)?.exist()?;
        conn.ip_setns(pf, v.index).await?;

        nl_ctx!(link, _conn, dst);
        let _ = link.trans_to(k, LExistence::ShouldExist).await;
        Ok(())
    }
    async fn refresh_link(&mut self, name: LinkKey) -> Result<()> {
        log::trace!("refresh {:?}", name);
        nl_ctx!(link, conn, self);

        let n = link
            .trans_to(
                &name,
                LExistence::Exist(LazyVal::Todo(Box::pin(async {
                    let k = conn.get_link(name.clone()).await?;
                    let mut la: LinkDev = k.try_into()?;
                    let addrs = conn.get_link_addrs(la.index).await?;
                    la.fill_addrs(addrs)?;
                    Ok(la)
                }))),
            )
            .await;
        match n {
            Err(e) => {
                if let Some(_) = e.downcast_ref::<MissingError>() {
                    link.set_absent(&name);
                } else {
                    return Err(e);
                }
            }
            _ => (),
        }

        Ok(())
    }
    async fn get_veth(&mut self, base: &VPairKey) -> Result<()> {
        let lka = base.link(LinkAB::A);
        let lkb = base.link(LinkAB::B);
        for link_name in [lka, lkb] {
            let result = self.refresh_link(link_name).await;
            if let Err(ref e) = result {
                if let Some(_e) = e.downcast_ref::<MissingError>() {
                    // ignore
                } else {
                    return result;
                }
            }
        }
        Ok(())
    }
    /// Errors if something already exists
    async fn new_veth_pair(&mut self, name: VPairKey) -> Result<()> {
        log::debug!("Create new veth pair, {:?}", name);
        if let Some(v) = self.veths.g(&name) {
            bail!("programming error: Veth already exists. {:?}", v);
        }

        nl_ctx!(link, conn, self);
        conn.add_veth_pair(&name).await?;
        link.trans_to(&name.link(LinkAB::A), LExistence::ShouldExist)
            .await?;
        link.trans_to(&name.link(LinkAB::B), LExistence::ShouldExist)
            .await?;
        Ok(())
    }
    async fn ip_add_route(
        &mut self,
        index: u32,
        dst: Option<IpNetwork>,
        v4: Option<bool>,
        purpose: RouteFor,
    ) -> Result<()> {
        self.routes
            .trans_to(&purpose, LExistence::ShouldExist)
            .await?;
        self.conn.ip_add_route(index, dst, v4).await
    }
}

#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LinkDev {
    pub up: Exp<bool>,
    pub index: u32,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    pub addrs: ExpCollection<HashMap<IpNetwork, Existence<AddressMessage>>>,
    /// associated veth pair if any
    pub pair: Option<VPairKey>,
    pub max_mtu: Option<u32>,
    #[derivative(Hash = "ignore")]
    #[derivative(PartialEq = "ignore")]
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    pub kind: Option<nlas::InfoKind>,
    pub name: Option<String>,
}

impl LinkDev {
    pub fn fill_addrs(&mut self, msgs: Vec<AddressMessage>) -> Result<()> {
        let exp = self.addrs.to_filled()?;
        for addr in msgs.into_iter() {
            let mut ipnet: Option<IpNetwork> = None;
            for msg in addr.nlas.iter() {
                match msg {
                    rtnetlink::netlink_packet_route::address::Nla::Address(a) => {
                        // one addr msg for one addr I guess ?
                        if ipnet.is_some() {
                            log::warn!("More than one address in one AddressMessage, {:?}", addr);
                            break;
                        }
                        if a.len() == 4 {
                            let con: [u8; 4] = a.to_owned().try_into().unwrap();
                            let ip4: Ipv4Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip4.into(), addr.header.prefix_len)?);
                        } else if a.len() == 16 {
                            let con: [u8; 16] = a.to_owned().try_into().unwrap();
                            let ip6: Ipv6Addr = con.into();
                            ipnet = Some(IpNetwork::new(ip6.into(), addr.header.prefix_len)?);
                        }
                    }
                    _ => (),
                }
            }
            if let Some(ip) = ipnet {
                exp.fill(&ip, Existence::Exist(addr))?;
            }
        }
        Ok(())
    }
}

impl Trans for AddressMessage {
    fn trans(&self, to: &Self) -> bool {
        self == to
    }
}

impl Trans for LinkDev {
    /// What is allowed to change when perceiving changes
    fn trans(&self, to: &Self) -> bool {
        self.up.trans(&to.up)
    }
}

impl DependentEMap<VPairKey, LinkAB, VethPair> for BTreeMap<VPairKey, VethPair> {}
impl DepedentEMapE<VPairKey, LinkAB, LinkKey, VethPair> for BTreeMap<VPairKey, VethPair> {}

type VethPair = Map<LinkAB, Existence<LinkKey>>;

impl TryFrom<LinkMessage> for LinkDev {
    type Error = anyhow::Error;
    fn try_from(link: LinkMessage) -> Result<Self> {
        use rtnetlink::netlink_packet_route::rtnl::link::nlas::Nla;
        let mut name = None;
        let up = link.header.flags & IFF_UP != 0;
        let index = link.header.index;
        let mut max_mtu = None;
        let mut link_kind = None;
        for n in link.nlas {
            match n {
                Nla::IfName(n) => name = Some(n),
                Nla::OperState(s) => match s {
                    _ => (),
                },
                Nla::Info(k) => {
                    for i in k {
                        match i {
                            nlas::Info::Kind(x) => {
                                link_kind = Some(x);
                            }
                            _ => (),
                        }
                    }
                }
                Nla::MaxMtu(max) => {
                    max_mtu = Some(max);
                }
                _ => (),
            }
        }
        let mut li = LinkDev {
            up: Exp::Confirmed(up),
            index,
            addrs: Default::default(),
            pair: None,
            max_mtu,
            kind: link_kind,
            name,
        };

        Ok(li)
    }
}

impl NLHandle {
    pub fn new_self_proc_tokio() -> Result<Self> {
        use rtnetlink::new_connection;
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        Ok(Self {
            rawh: handle,
            id: ExactNS::from_source((PidPath::Selfproc, "net"))?,
        })
    }
}

pub enum PidOrFd {
    Pid(u32),
    Fd(Box<dyn AsFd>),
}

#[fully_pub]
impl NLHandle {
    async fn rm_link(&self, index: u32) -> Result<()> {
        self.rawh
            .link()
            .del(index)
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    async fn get_link(&self, name: LinkKey) -> Result<LinkMessage> {
        let mut links = self.rawh.link().get().match_name(name.into()).execute();
        if let Some(link) = links.try_next().await? {
            Ok(link)
        } else {
            Err(MissingError.into())
        }
    }
    async fn get_link_addrs(&self, index: u32) -> Result<Vec<AddressMessage>> {
        let addrs = self
            .rawh
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let addrs: Vec<AddressMessage> = addrs.try_collect().await?;
        Ok(addrs)
    }
    async fn set_link_up(&self, index: u32) -> Result<()> {
        self.rawh
            .link()
            .set(index)
            .up()
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    async fn add_veth_pair(&self, base_name: &VPairKey) -> Result<()> {
        self.rawh
            .link()
            .add()
            .veth(
                base_name.link(LinkAB::A).into(),
                base_name.link(LinkAB::B).into(),
            )
            .execute()
            .await
            .map_err(|e| anyhow!("adding {base_name:?} veth pair fails. {e}"))
    }
    async fn add_addr_dev(&self, addr: IpNetwork, dev: u32) -> Result<()> {
        // assuming the desired IP has not been added
        self.rawh
            .address()
            .add(dev, addr.ip(), addr.prefix())
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    async fn del_addr(&self, addr: AddressMessage) -> Result<()> {
        self.rawh
            .address()
            .del(addr)
            .execute()
            .await
            .map_err(anyhow::Error::from)
    }
    async fn ip_setns(&self, fd: &PidOrFd, dev: u32) -> Result<()> {
        let p = self.rawh.link().set(dev);
        match fd {
            PidOrFd::Fd(f) => p.setns_by_fd(f.as_fd().as_raw_fd()),
            PidOrFd::Pid(f) => p.setns_by_pid(*f),
        }
        .execute()
        .await
        .map_err(anyhow::Error::from)
    }
    // one of dst and v4 must be Some
    // XXX must have run once in exec paths
    async fn ip_add_route(
        &self,
        index: u32,
        dst: Option<IpNetwork>,
        v4: Option<bool>,
    ) -> Result<()> {
        let req = self.rawh.route().add().output_interface(index);
        match dst {
            Some(IpNetwork::V4(ip)) => req
                .v4()
                .destination_prefix(ip.ip(), ip.prefix())
                .execute()
                .await
                .map_err(anyhow::Error::from),
            Some(IpNetwork::V6(ip)) => req
                .v6()
                .destination_prefix(ip.ip(), ip.prefix())
                .execute()
                .await
                .map_err(anyhow::Error::from),
            _ => {
                if v4.is_some() {
                    if v4.unwrap() {
                        req.v4().execute().await.map_err(anyhow::Error::from)
                    } else {
                        req.v6().execute().await.map_err(anyhow::Error::from)
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }
}

/// a for subject ns, b for target ns
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VethConn {
    pub subnet_veth: IpNetwork,
    pub subnet6_veth: IpNetwork,
    pub ip_va: IpNetwork,
    pub ip6_va: IpNetwork,
    pub ip_vb: IpNetwork,
    pub ip6_vb: IpNetwork,
    pub key: VPairKey,
}

impl VethConn {
    /// Adaptive application of Veth connection, accepting dirty state
    pub async fn apply<'n>(&self, na: &'n mut NLDriver, nb: &'n mut NLDriver) -> Result<()>
    where
        NLHandle: GetPidOrFd,
    {
        let fd = nb.conn.open()?;
        if na.conn == nb.conn {
            bail!("Invalid VethConn, subject and target NS can not be the same");
        }
        let mut redo = false;
        let (mut a, mut b) = (false, false);
        let mut a_in_t = false;
        if let Some(v) = na.veths.g(&self.key) {
            if v.lenient(&LinkAB::A) {
                a = true;
                if v.lenient(&LinkAB::B) {
                    na.move_link_to_ns(&self.key.link(LinkAB::B), nb, &fd)
                        .await?;
                    nb.refresh_link(self.key.link(LinkAB::B)).await?;
                }
            } else {
                redo = true;
            }
        } else {
            redo = true;
        }
        if let Some(v) = nb.veths.g(&self.key) {
            if v.lenient(&LinkAB::B) {
                b = true;
                if v.lenient(&LinkAB::A) {
                    // Weird situation. Just redo
                    redo = true;
                    a_in_t = true;
                }
            }
        }
        if !(a && b) {
            redo = true;
        }
        if redo {
            if a {
                na.remove_link(&self.key.link(LinkAB::A)).await?;
            }
            if a_in_t {
                nb.remove_link(&self.key.link(LinkAB::A)).await?;
            }
            if b {
                nb.remove_link(&self.key.link(LinkAB::B)).await?;
            }
            na.new_veth_pair(self.key.clone()).await?;
            na.move_link_to_ns(&self.key.link(LinkAB::B), nb, &fd)
                .await?;
        }
        Ok(())
    }
    pub async fn apply_addr_up<'n>(
        &self,
        na: &'n mut NLDriver,
        nb: &'n mut NLDriver,
    ) -> Result<()> {
        na.refresh_link(self.key.link(LinkAB::A)).await?;
        nl_ctx!(link, conn, na);
        let la = link.not_absent(&self.key.link(LinkAB::A))?.exist_mut()?;
        conn.set_up(la).await?;
        conn.ensure_addrs_46(la, self.ip_va, self.ip6_va).await?;
        nl_ctx!(link, conn, nb);
        let lk = self.key.link(LinkAB::B);
        let la = link.not_absent(&lk)?.exist_mut()?;
        conn.set_up(la).await?;
        conn.ensure_addrs_46(la, self.ip_vb, self.ip6_vb).await?;
        Ok(())
    }
}

pub fn btreemap_chain_mut<'a, A, B, C>(
    ma: &'a mut BTreeMap<A, B>,
    mb: &'a mut BTreeMap<B, C>,
    k_in_ma: &'a A,
) -> Option<&'a mut C>
where
    A: Ord,
    B: Ord,
    C: Ord,
{
    ma.get_mut(k_in_ma).and_then(|r| mb.get_mut(r))
}
