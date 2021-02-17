#[macro_use]
extern crate log;

use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, convert::TryFrom};

use anyhow::Error;
use futures::{StreamExt, TryStreamExt};
use ifstructs::ifreq;
use ipnetwork::IpNetwork;
use libc::pid_t;
use nix::errno::Errno;
use nix::ioctl_write_ptr_bad;
use nix::mount::{mount as nix_mount, umount, umount2, MntFlags, MsFlags};
use nix::sys::socket::SockAddr;
use nix::sys::{
    self,
    stat::Mode,
    wait::{waitpid, WaitPidFlag, WaitStatus},
};
use nix::unistd::{
    chdir as nix_chdir, chown, chroot as nix_chroot, close, fchown, mkdir as nix_mkdir,
    sethostname, symlinkat, sync, Gid, Group, Uid, User,
};
use nix::NixPath;
use os_pipe::pipe;
use sys::socket::{AddressFamily, SockFlag, SockType};
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio_vsock::VsockListener;

use fly_init::{ImageConfig, RunConfig};

#[derive(Debug, thiserror::Error)]
enum InitError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("couldn't mount {} onto {}, because: {}", source, target, error)]
    Mount {
        source: String,
        target: String,
        #[source]
        error: nix::Error,
    },

    #[error("couldn't mkdir {}, because: {}", path, error)]
    Mkdir {
        path: String,
        #[source]
        error: nix::Error,
    },

    #[error("couldn't chroot to {}, because: {}", path, error)]
    Chroot {
        path: String,
        #[source]
        error: nix::Error,
    },

    #[error("couldn't chdir to {}, because: {}", path, error)]
    Chdir {
        path: String,
        #[source]
        error: nix::Error,
    },

    #[error(r#"couldn't find user "{}""#, 0)]
    UserNotFound(String),
    #[error(r#"couldn't find group "{}""#, 0)]
    GroupNotFound(String),

    #[error("an unhandled error occurred: {}", 0)]
    UnhandledNixError(#[from] nix::Error),

    #[error("an unhandled IO error occurred: {}", 0)]
    UnhandledIoError(#[from] io::Error),

    #[error("an unhandled netlink error occurred: {}", 0)]
    UnhandledNetlinkError(#[from] rtnetlink::Error),

    #[error("an unhandled error occurred: {}", 0)]
    UnhandledError(#[from] Error),
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("error reading fly json config: {}", 0)]
    Read(#[from] io::Error),
    #[error("error parsing fly json config: {}", 0)]
    Parse(#[from] serde_json::Error),
}

const SIOCETHTOOL: u32 = 0x8946;
const IFA_F_NODAD: u8 = 0x02;

//const ETHTOOL_GRXCSUM: u32 = 0x00000014;
const ETHTOOL_SRXCSUM: u32 = 0x00000015;
//const ETHTOOL_GTXCSUM: u32 = 0x00000016;
const ETHTOOL_STXCSUM: u32 = 0x00000017;

#[repr(C)]
pub struct EthtoolValue {
    cmd: u32,
    value: u32,
}

ioctl_write_ptr_bad!(ethtoolset, SIOCETHTOOL, ifreq);

pub fn ethtool_set(name: &str, cmd: u32, value: u32) -> nix::Result<()> {
    let mut ifres = ifreq::from_name(name);
    if let Ok(ref mut ifr) = ifres {
        let mut ev = EthtoolValue {
            cmd: cmd,
            value: value,
        };

        ifr.ifr_ifru.ifr_data = (&mut ev as *mut EthtoolValue).cast::<_>();

        let sfd = sys::socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            None,
        )?;

        let res = unsafe { ethtoolset(sfd, ifr) };

        close(sfd)?;

        match res {
            Ok(_) => {
                return Ok(());
            }
            Err(v) => {
                return Err(v);
            }
        }
    }

    return Err(nix::Error::invalid_argument());
}

pub fn log_init() {
    // default to "info" level, just for this bin
    let level = env::var("LOG_FILTER").unwrap_or_else(|_| "init=info".into());

    env_logger::builder()
        .parse_filters(&level)
        .write_style(env_logger::WriteStyle::Never)
        .default_format_level(false)
        .default_format_module_path(false)
        .default_format_timestamp(false)
        .init();
}

#[tokio::main]
async fn main() -> Result<(), InitError> {
    log_init();

    // can't put these as const unfortunately...
    let chmod_0755: Mode =
        Mode::S_IRWXU | Mode::S_IRGRP | Mode::S_IXGRP | Mode::S_IROTH | Mode::S_IXOTH;
    let chmod_0555: Mode = Mode::S_IRUSR
        | Mode::S_IXUSR
        | Mode::S_IRGRP
        | Mode::S_IXGRP
        | Mode::S_IROTH
        | Mode::S_IXOTH;
    let chmod_1777: Mode = Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO | Mode::S_ISVTX;
    // let chmod_0777 = Mode::S_IRWXU | Mode::S_IRWXG | Mode::S_IRWXO;
    let common_mnt_flags: MsFlags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;

    info!("Starting init (commit: {})...", env!("VERGEN_SHA_SHORT"));

    let conf_reader = BufReader::new(File::open("/fly/run.json").map_err(ConfigError::from)?);
    let conf: RunConfig = serde_json::from_reader(conf_reader).map_err(ConfigError::from)?;
    trace!("run conf: {:?}", conf);

    debug!("Mounting /dev");
    mkdir("/dev", chmod_0755).ok();
    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        MsFlags::MS_NOSUID,
        Some("mode=0755"),
    )?;

    mkdir("/newroot", chmod_0755)?;

    let root_device = if let Some(rd) = conf.root_device {
        rd
    } else {
        "/dev/vdb".to_owned()
    };

    debug!("Mounting newroot fs");
    mount::<_, _, _, [u8]>(
        Some(root_device.as_str()),
        "/newroot",
        Some("ext4"),
        MsFlags::MS_RELATIME,
        None,
    )?;

    // Move /dev so we don't have to re-mount it
    debug!("Mounting (move) /dev");
    mkdir("/newroot/dev", chmod_0755).ok();
    mount::<_, _, [u8], [u8]>(Some("/dev"), "/newroot/dev", None, MsFlags::MS_MOVE, None)?;

    // Saving some space
    debug!("Removing /fly");
    fs::remove_dir_all("/fly")?;

    // Our own hacky switch_root
    debug!("Switching root");
    // Change directory to the new root
    chdir("/newroot")?;
    // Mount the new root over /
    mount::<_, _, [u8], [u8]>(Some("."), "/", None, MsFlags::MS_MOVE, None)?;
    // Change root to the current directory (new root)
    chroot(".")?;
    // Change directory to /
    chdir("/")?;

    debug!("Mounting /dev/pts");
    mkdir("/dev/pts", chmod_0755).ok();
    mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NOATIME,
        Some("mode=0620,gid=5,ptmxmode=666"),
    )?;

    debug!("Mounting /dev/mqueue");
    mkdir("/dev/mqueue", chmod_0755).ok();
    mount::<_, _, _, [u8]>(
        Some("mqueue"),
        "/dev/mqueue",
        Some("mqueue"),
        common_mnt_flags,
        None,
    )?;

    debug!("Mounting /dev/shm");
    mkdir("/dev/shm", chmod_1777).ok();
    mount::<_, _, _, [u8]>(
        Some("shm"),
        "/dev/shm",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None,
    )?;

    debug!("Mounting /dev/hugepages");
    mkdir("/dev/hugepages", chmod_0755).ok();
    mount(
        Some("hugetlbfs"),
        "/dev/hugepages",
        Some("hugetlbfs"),
        MsFlags::MS_RELATIME,
        Some("pagesize=2M"),
    )?;

    debug!("Mounting /proc");
    mkdir("/proc", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("proc"), "/proc", Some("proc"), common_mnt_flags, None)?;
    mount::<_, _, _, [u8]>(
        Some("binfmt_misc"),
        "/proc/sys/fs/binfmt_misc",
        Some("binfmt_misc"),
        common_mnt_flags | MsFlags::MS_RELATIME,
        None,
    )?;

    debug!("Mounting /sys");
    mkdir("/sys", chmod_0555).ok();
    mount::<_, _, _, [u8]>(Some("sys"), "/sys", Some("sysfs"), common_mnt_flags, None)?;

    debug!("Mounting /run");
    mkdir("/run", chmod_0755).ok();
    mount(
        Some("run"),
        "/run",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755"),
    )?;
    mkdir("/run/lock", Mode::all()).ok();

    symlinkat("/proc/self/fd", None, "/dev/fd").ok();
    symlinkat("/proc/self/fd/0", None, "/dev/stdin").ok();
    symlinkat("/proc/self/fd/1", None, "/dev/stdout").ok();
    symlinkat("/proc/self/fd/2", None, "/dev/stderr").ok();

    mkdir("/root", Mode::S_IRWXU).ok();

    let common_cgroup_mnt_flags =
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_RELATIME;

    debug!("Mounting cgroup");
    mount(
        Some("tmpfs"),
        "/sys/fs/cgroup",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV, // | MsFlags::MS_RDONLY,
        Some("mode=755"),
    )?;

    debug!("Mounting cgroup2");
    mkdir("/sys/fs/cgroup/unified", chmod_0555)?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup/unified",
        Some("cgroup2"),
        common_mnt_flags | MsFlags::MS_RELATIME,
        Some("nsdelegate"),
    )?;

    debug!("Mounting /sys/fs/cgroup/net_cls,net_prio");
    mkdir("/sys/fs/cgroup/net_cls,net_prio", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/net_cls,net_prio",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("net_cls,net_prio"),
    )?;

    debug!("Mounting /sys/fs/cgroup/hugetlb");
    mkdir("/sys/fs/cgroup/hugetlb", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/hugetlb",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("hugetlb"),
    )?;

    debug!("Mounting /sys/fs/cgroup/pids");
    mkdir("/sys/fs/cgroup/pids", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/pids",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("pids"),
    )?;

    debug!("Mounting /sys/fs/cgroup/freezer");
    mkdir("/sys/fs/cgroup/freezer", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/freezer",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("freezer"),
    )?;

    debug!("Mounting /sys/fs/cgroup/cpu,cpuacct");
    mkdir("/sys/fs/cgroup/cpu,cpuacct", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/cpu,cpuacct",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("cpu,cpuacct"),
    )?;

    debug!("Mounting /sys/fs/cgroup/devices");
    mkdir("/sys/fs/cgroup/devices", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/devices",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("devices"),
    )?;

    debug!("Mounting /sys/fs/cgroup/blkio");
    mkdir("/sys/fs/cgroup/blkio", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/blkio",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("blkio"),
    )?;

    debug!("Mounting cgroup/memory");
    mkdir("/sys/fs/cgroup/memory", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/memory",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("memory"),
    )?;

    debug!("Mounting /sys/fs/cgroup/perf_event");
    mkdir("/sys/fs/cgroup/perf_event", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/perf_event",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("perf_event"),
    )?;

    debug!("Mounting /sys/fs/cgroup/cpuset");
    mkdir("/sys/fs/cgroup/cpuset", chmod_0555)?;
    mount(
        Some("cgroup"),
        "/sys/fs/cgroup/cpuset",
        Some("cgroup"),
        common_cgroup_mnt_flags,
        Some("cpuset"),
    )?;

    rlimit::setrlimit(rlimit::Resource::NOFILE, 10240, 10240).ok();

    let image_conf = conf
        .image_config
        .clone()
        .unwrap_or_else(|| ImageConfig::default());

    let user = if let Some(user_override) = conf.user_override {
        user_override
    } else if let Some(user) = image_conf.user {
        user
    } else {
        "root".to_owned()
    };

    let mut user_split = user.split(":");

    let user = user_split
        .next()
        .expect("no user defined, this should not happen, please contact support!");
    let group = user_split.next();

    debug!("searching for user '{}", user);

    let (uid, mut gid, home_dir) = match User::from_name(user) {
        Ok(Some(u)) => (u.uid, u.gid, u.dir),
        Ok(None) => {
            if let Ok(uid) = user.parse::<u32>() {
                match User::from_uid(Uid::from_raw(uid)) {
                    Ok(Some(u)) => (u.uid, u.gid, u.dir),
                    _ => (Uid::from_raw(uid), Gid::from_raw(uid), "/".into()),
                }
            } else {
                return Err(InitError::UserNotFound(user.into()).into());
            }
        }
        Err(e) => {
            if user != "root" {
                return Err(InitError::UserNotFound(user.into()).into());
            }
            debug!("error getting user '{}' by name => {}", user, e);
            match User::from_name("root") {
                Ok(Some(u)) => (u.uid, u.gid, u.dir),
                _ => (Uid::from_raw(0), Gid::from_raw(0), "/root".into()),
            }
        }
    };

    if let Some(group) = group {
        debug!("searching for group '{}'", group);
        match Group::from_name(group) {
            Err(_e) => {
                return Err(InitError::GroupNotFound(group.into()).into());
            }
            Ok(Some(g)) => gid = g.gid,
            Ok(None) => {
                if let Ok(raw_gid) = group.parse::<u32>() {
                    gid = Gid::from_raw(raw_gid);
                } else {
                    return Err(InitError::GroupNotFound(group.into()).into());
                }
            }
        }
    }

    let envs = image_conf.env.clone().unwrap_or_else(|| vec![]);

    let mut envs: HashMap<String, String> = envs
        .iter()
        .map(|e| {
            let mut splitted = e.splitn(2, "=");
            (
                splitted.next().unwrap().to_owned(),
                splitted.next().unwrap().to_owned(),
            )
        })
        .collect();

    if let Some(ref extras) = conf.extra_env {
        envs.extend(extras.clone());
    }

    // if we have a PATH, set it on the OS to be able to find argv[0]
    if let Some(p) = envs.get("PATH") {
        if p != "" {
            env::set_var("PATH", p);
        }
    }

    envs.entry("HOME".to_owned())
        .or_insert(home_dir.to_string_lossy().into_owned());

    let incoming = VsockListener::bind(&SockAddr::new_vsock(3, 10000))?.incoming();

    let waitpid_mutex = Arc::new(Mutex::new(()));

    let (api, tx, mut rx_sig) =
        fly_init::api::server(envs.clone(), waitpid_mutex.clone(), incoming);
    tokio::spawn(api);

    if let Some(ref mounts) = conf.mounts {
        for m in mounts {
            info!("Mounting {} at {}", m.device_path, m.mount_path);

            if let Err(e) = nix_mkdir(m.mount_path.as_str(), chmod_0755) {
                if let Some(nix::errno::Errno::EEXIST) = e.as_errno() {
                    warn!("directory {} already exists", m.mount_path);
                } else {
                    panic!("could not create directory {}: {}", m.mount_path, e);
                }
            }

            mount::<_, _, _, [u8]>(
                Some(m.device_path.as_str()),
                m.mount_path.as_str(),
                Some("ext4"),
                MsFlags::MS_RELATIME,
                None,
            )?;

            if let Err(e) = chown(m.mount_path.as_str(), Some(uid), Some(gid)) {
                warn!(
                    "could not chown directory {} with uid {} and gid {}: {}",
                    m.mount_path, uid, gid, e
                );
            };
        }
    }

    // command argv
    let mut argv: Vec<String> = vec![];

    match conf.exec_override {
        Some(ref ovrd) => argv = ovrd.clone(),
        None => {
            match image_conf.entrypoint {
                Some(ref entry) => {
                    argv = entry.clone();
                }
                _ => {}
            };
            match conf.cmd_override {
                Some(ref ovrd) => {
                    argv.push(ovrd.clone());
                }
                None => match image_conf.cmd {
                    Some(ref c) => {
                        argv.append(&mut c.clone());
                    }
                    _ => {}
                },
            };
        }
    };

    match sethostname(&conf.hostname) {
        Err(e) => warn!("error setting hostname: {}", e),
        Ok(_) => {}
    };

    mkdir("/etc", chmod_0755).ok();

    // Some programs might prefer this
    fs::write("/etc/hostname", conf.hostname).ok();

    if let Some(ref etc_hosts) = conf.etc_hosts {
        debug!("Populating /etc/hosts");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("/etc/hosts")?;

        for entry in etc_hosts {
            if let Some(ref desc) = entry.desc {
                write!(&mut f, "\n# {}\n{}\t{}\n", desc, entry.ip, entry.host).ok();
            } else {
                write!(&mut f, "\n{}\t{}\n", entry.ip, entry.host).ok();
            }
        }
    }

    if let Some(ref etc_resolv) = conf.etc_resolv {
        debug!("Populating /etc/resolv.conf");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("/etc/resolv.conf")?;

        for ns in etc_resolv.nameservers.iter() {
            write!(&mut f, "\nnameserver\t{}", ns).ok();
        }

        write!(&mut f, "\n").ok();
    }

    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    debug!("netlink: getting lo link");
    let lo = handle
        .link()
        .get()
        .set_name_filter("lo".into())
        .execute()
        .try_next()
        .await?
        .expect("no lo link found");

    debug!("netlink: setting lo link \"up\"");
    handle.link().set(lo.header.index).up().execute().await?;

    debug!("netlink: getting eth0 link");
    let eth0 = handle
        .link()
        .get()
        .set_name_filter("eth0".into())
        .execute()
        .try_next()
        .await?
        .expect("no eth0 link found");

    debug!("netlink: setting eth0 link \"up\"");
    handle
        .link()
        .set(eth0.header.index)
        .up()
        .mtu(1420)
        .execute()
        .await?;

    let _ = ethtool_set("eth0", ETHTOOL_SRXCSUM, 0);
    ethtool_set("eth0", ETHTOOL_STXCSUM, 0)?;

    if let Some(ref ip_configs) = conf.ip_configs {
        let address = handle.address();
        let route = handle.route();

        for ipc in ip_configs {
            debug!("netlink: adding ip {}/{}", ipc.ip.ip(), ipc.mask);
            let mut addr_req = address.add(eth0.header.index, ipc.ip.ip(), ipc.mask);
            addr_req.message_mut().header.flags |= IFA_F_NODAD;
            addr_req.execute().await?;

            if let IpNetwork::V4(ipn) = ipc.ip {
                if ipc.mask < 30 {
                    let ipint: u32 = ipn.ip().into();
                    let nextip: std::net::Ipv4Addr = (ipint + 1).into();

                    address
                        .add(eth0.header.index, std::net::IpAddr::V4(nextip), ipc.mask)
                        .execute()
                        .await?;
                }
            }

            debug!("netlink: adding default route via {}", ipc.gateway);
            match ipc.gateway {
                IpNetwork::V4(gateway) => {
                    route.add_v4().gateway(gateway.ip()).execute().await?;
                }
                IpNetwork::V6(gateway) => {
                    if ipc.mask != 112 {
                        route.add_v6().gateway(gateway.ip()).execute().await?;
                    }
                }
            }
        }
    }

    info!("Running: `{}` as {}", argv.join(" "), user);

    let (reader, writer) = pipe().expect("could not create read/write pipe for process");
    let writer_clone = writer
        .try_clone()
        .expect("could not clone pipe writer for process");

    fchown(reader.as_raw_fd(), Some(uid), Some(gid)).expect("could not fchown pipe reader");
    fchown(writer.as_raw_fd(), Some(uid), Some(gid)).expect("could not fchown pipe writer");

    let mut command = Command::new(argv.remove(0));
    command
        .args(&argv)
        .envs(&envs)
        .stdout(writer)
        .stderr(writer_clone);
    command.uid(uid.as_raw()).gid(gid.as_raw());

    if let Some(ref wd) = image_conf.working_dir {
        if wd != "" {
            debug!("Setting current dir on command to: {}", wd);
            command.current_dir(&wd);
        }
    }

    let child = command.spawn()?;
    let pid = child.id() as pid_t;
    debug!("child pid: {}", pid);

    let mut stdouterr: tokio::fs::File =
        unsafe { std::fs::File::from_raw_fd(reader.as_raw_fd()) }.into();

    tokio::spawn(async move {
        let mut own_stdout = tokio::io::stdout();
        if let Err(e) = tokio::io::copy(&mut stdouterr, &mut own_stdout).await {
            debug!("stdout/err copy ended with error: {}", e);
        };
    });

    let mut exit_status = -1;

    loop {
        // wait for a signal for 1 second!
        let mut deadline = tokio::time::delay_for(Duration::from_secs(1));
        let sig_fut = rx_sig.recv();
        tokio::pin!(sig_fut);
        tokio::select! {
            _ = &mut deadline => {
                // deadline expired
            },
            maybe_sig = &mut sig_fut => match maybe_sig {
                Some(sig) => {
                    info!("Sending signal {} to main child process w/ PID {}", sig, pid);
                    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig) {
                        Ok(_) => {
                            debug!("kill signal sent successfully");
                        },
                        Err(e) => {
                            error!("error signaling ({}) main child process: {}", sig, e);
                        }
                    }
                },
                None => {
                    debug!("all signal senders dropped! that should not happen!");
                }
            }
        }

        // ward off the zombies! this will also detect if the main child has exited
        let child_exited = {
            let _guard = waitpid_mutex.lock().await;
            reap_zombies(pid, &mut exit_status)
        };

        if child_exited {
            break;
        }
    }

    // match child.await {
    //     Ok(status) => {
    //         if let Some(sig) = status.signal() {
    //             info!(
    //                 "Program exited with code: {:?} signal: {} ({})",
    //                 status.code(),
    //                 nix::sys::signal::Signal::try_from(sig)
    //                     .map(|s| s.to_string())
    //                     .unwrap_or_else(|_| sig.to_string()),
    //                 sig
    //             );
    //         } else if let Some(code) = status.code() {
    //             info!("Program exited with code: {}", code);
    //             exit_status = code;
    //         } else {
    //             info!("Program exited with an unknown code and was not signaled");
    //         }
    //     }
    //     Err(e) => {
    //         debug!("error waiting for main child to exit: {}", e)
    //     }
    // }

    let mut oom_killed = false;
    match tokio::fs::File::open("/dev/kmsg").await {
        Err(e) => error!("error opening /dev/kmsg: {}", e),
        Ok(f) => {
            let bf = tokio::io::BufReader::new(f);
            let mut lines = bf.lines();

            let matcher = format!("Killed process {}", pid);
            trace!("attempting to match '{}' from kernel logs", matcher);

            loop {
                let mut delay = tokio::time::delay_for(Duration::from_millis(10));
                tokio::select! {
                    _ = &mut delay => {
                        trace!("timed out waiting for OOM message");
                        break;
                    }
                    line = lines.next() => match line {
                        Some(Ok(line)) => {
                            if line.contains(&matcher) {
                                info!("Process appears to have been OOM killed!");
                                oom_killed = true;
                                break;
                            }
                        },
                        _ => {
                            break;
                        }
                    }
                }
            }
        }
    }

    tx.send((exit_status, oom_killed)).ok();

    if let Some(mounts) = conf.mounts {
        for m in mounts {
            info!("Umounting {} from {}", m.device_path, m.mount_path);

            let mut attempts = 5;

            loop {
                debug!("Attempting umount");
                if let Err(e) = umount(m.mount_path.as_str()) {
                    attempts -= 1;
                    if attempts > 0 {
                        error!("error umounting {}: {}, retrying in a bit", m.mount_path, e);
                        tokio::time::delay_for(Duration::from_millis(750)).await;
                        continue;
                    } else {
                        if let Err(e) = umount2(m.mount_path.as_str(), MntFlags::MNT_DETACH) {
                            error!("error lazy umounting {}: {}, not retrying", m.mount_path, e);
                        } else {
                            debug!("Syncing after lazy umount...");
                            sync();
                        }
                        break;
                    }
                } else {
                    debug!(
                        "Successfully umounted {} from {}",
                        m.device_path, m.mount_path
                    );
                }

                break;
            }
        }
    }

    tokio::time::delay_for(Duration::from_secs(1)).await;

    debug!("exiting after delay");

    exit_cleanly().map_err(InitError::from)
}

fn exit_cleanly() -> nix::Result<()> {
    nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT).map(|_| {})
}

fn reap_zombies(pid: i32, exit_status: &mut i32) -> bool {
    let mut child_exited = false;
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(status) => {
                if Some(pid) == status.pid().map(nix::unistd::Pid::as_raw) {
                    // main process pid exited
                    child_exited = true;
                }
                match status {
                    WaitStatus::Exited(child_pid, exit_code) => {
                        if child_pid.as_raw() == pid {
                            info!("Main child exited normally with code: {}", exit_code);
                            *exit_status = exit_code;
                        } else {
                            warn!(
                                "Reaped child process with pid: {}, exit code: {}",
                                child_pid, exit_code
                            )
                        }
                    }
                    WaitStatus::Signaled(child_pid, signal, core_dumped) => {
                        if child_pid.as_raw() == pid {
                            info!(
                                "Main child exited with signal (with signal '{}', core dumped? {})",
                                signal, core_dumped
                            );
                            *exit_status = 128 + (signal as i32);
                        } else {
                            warn!(
                                "Reaped child process with pid: {} and signal: {}, core dumped? {}",
                                child_pid, signal, core_dumped
                            )
                        }
                    }
                    WaitStatus::Stopped(child_pid, signal) => {
                        debug!(
                            "waitpid Stopped: surprising (pid: {}, signal: {})",
                            child_pid, signal
                        );
                    }
                    WaitStatus::PtraceEvent(child_pid, signal, event) => {
                        debug!(
                            "waitpid PtraceEvent: interesting (pid: {}, signal: {}, event: {})",
                            child_pid, signal, event
                        );
                    }
                    WaitStatus::PtraceSyscall(child_pid) => {
                        debug!("waitpid PtraceSyscall: unfathomable (pid: {})", child_pid);
                    }
                    WaitStatus::Continued(child_pid) => {
                        debug!("waitpid Continue: not supposed to! (pid: {})", child_pid);
                    }
                    WaitStatus::StillAlive => {
                        trace!("no more children to reap");
                        break;
                    }
                }
            }
            Err(e) => match e {
                nix::Error::Sys(Errno::ECHILD) => {
                    debug!("no child to wait");
                    break;
                }
                nix::Error::Sys(Errno::EINTR) => {
                    debug!("got EINTR waiting for pids, continuing...");
                    continue;
                }
                _ => {
                    debug!("error calling waitpid: {}", e);
                    // TODO: return an error? handle it?
                    return false;
                }
            },
        }
    }
    child_exited
}

fn mount<P1: ?Sized + NixPath, P2: ?Sized + NixPath, P3: ?Sized + NixPath, P4: ?Sized + NixPath>(
    source: Option<&P1>,
    target: &P2,
    fstype: Option<&P3>,
    flags: MsFlags,
    data: Option<&P4>,
) -> Result<(), InitError> {
    nix_mount(source, target, fstype, flags, data).map_err(|error| InitError::Mount {
        source: source
            .map(|p| {
                p.with_nix_path(|cs| {
                    cs.to_owned()
                        .into_string()
                        .ok()
                        .unwrap_or_else(|| String::new())
                })
                .unwrap_or_else(|_| String::new())
            })
            .unwrap_or_else(|| String::new()),
        target: target
            .with_nix_path(|cs| {
                cs.to_owned()
                    .into_string()
                    .ok()
                    .unwrap_or_else(|| String::new())
            })
            .unwrap_or_else(|_| String::new()),
        error,
    })
}

fn chdir<P: ?Sized + NixPath>(path: &P) -> Result<(), InitError> {
    nix_chdir(path).map_err(|error| InitError::Chdir {
        path: path
            .with_nix_path(|cs| {
                cs.to_owned()
                    .into_string()
                    .ok()
                    .unwrap_or_else(|| String::new())
            })
            .unwrap_or_else(|_| String::new()),
        error,
    })
}

fn mkdir<P: ?Sized + NixPath>(path: &P, mode: Mode) -> Result<(), InitError> {
    nix_mkdir(path, mode).map_err(|error| InitError::Mkdir {
        path: path
            .with_nix_path(|cs| {
                cs.to_owned()
                    .into_string()
                    .ok()
                    .unwrap_or_else(|| String::new())
            })
            .unwrap_or_else(|_| String::new()),
        error,
    })
}

fn chroot<P: ?Sized + NixPath>(path: &P) -> Result<(), InitError> {
    nix_chroot(path).map_err(|error| InitError::Chroot {
        path: path
            .with_nix_path(|cs| {
                cs.to_owned()
                    .into_string()
                    .ok()
                    .unwrap_or_else(|| String::new())
            })
            .unwrap_or_else(|_| String::new()),
        error,
    })
}
