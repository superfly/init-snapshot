use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use super::{ApiReply, ErrorMessage};
use anyhow::Error;
use warp::http::StatusCode;

#[derive(Debug, Serialize, Clone)]
pub struct SysInfo {
    memory: Memory,
    load_average: [f32; 3],
    cpus: HashMap<usize, Cpu>,
    disks: Vec<DiskStat>,
    net: Vec<NetworkDevice>,
    filefd: FileFd,
}

#[derive(Debug, Serialize, Clone)]
pub struct FileFd {
    allocated: usize,
    maximum: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct Cpu {
    user: f32,
    nice: f32,
    system: f32,
    idle: f32,
    iowait: Option<f32>,
    irq: Option<f32>,
    softirq: Option<f32>,
    steal: Option<f32>,
    guest: Option<f32>,
    guest_nice: Option<f32>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Memory {
    mem_total: u64,
    mem_free: u64,
    mem_available: Option<u64>,
    buffers: u64,
    cached: u64,
    swap_cached: u64,
    active: u64,
    inactive: u64,
    swap_total: u64,
    swap_free: u64,
    dirty: u64,
    writeback: u64,
    slab: u64,
    shmem: Option<u64>,
    vmalloc_total: u64,
    vmalloc_used: u64,
    vmalloc_chunk: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct NetworkDevice {
    name: String,
    recv_bytes: u64,
    recv_packets: u64,
    recv_errs: u64,
    recv_drop: u64,
    recv_fifo: u64,
    recv_frame: u64,
    recv_compressed: u64,
    recv_multicast: u64,
    sent_bytes: u64,
    sent_packets: u64,
    sent_errs: u64,
    sent_drop: u64,
    sent_fifo: u64,
    sent_colls: u64,
    sent_carrier: u64,
    sent_compressed: u64,
}

fn collect_sysinfo() -> Result<SysInfo, Error> {
    let meminfo = procfs::Meminfo::new()?;
    let load_avg = procfs::LoadAverage::new()?;
    let kernel = procfs::KernelStats::new()?;

    let mut file = File::open("/proc/sys/fs/file-nr")?;
    let mut raw_filefd = String::new();
    file.read_to_string(&mut raw_filefd)?;

    let mut splitted_fd = raw_filefd.split_whitespace();

    let filefd = FileFd {
        allocated: splitted_fd.next().unwrap_or("0").trim().parse()?,
        maximum: splitted_fd.skip(1).next().unwrap_or("0").trim().parse()?,
    };

    Ok(SysInfo {
        filefd,
        memory: Memory {
            mem_total: meminfo.mem_total,
            mem_free: meminfo.mem_free,
            mem_available: meminfo.mem_available,
            buffers: meminfo.buffers,
            cached: meminfo.cached,
            swap_cached: meminfo.swap_cached,
            active: meminfo.active,
            inactive: meminfo.inactive,
            swap_total: meminfo.swap_total,
            swap_free: meminfo.swap_free,
            dirty: meminfo.dirty,
            writeback: meminfo.writeback,
            slab: meminfo.slab,
            shmem: meminfo.shmem,
            vmalloc_total: meminfo.vmalloc_total,
            vmalloc_used: meminfo.vmalloc_used,
            vmalloc_chunk: meminfo.vmalloc_chunk,
        },
        load_average: [load_avg.one, load_avg.five, load_avg.fifteen],
        cpus: kernel
            .cpu_time
            .iter()
            .enumerate()
            .map(|(i, ct)| {
                (
                    i,
                    Cpu {
                        user: ct.user,
                        nice: ct.nice,
                        system: ct.system,
                        idle: ct.idle,
                        iowait: ct.iowait,
                        irq: ct.irq,
                        softirq: ct.softirq,
                        steal: ct.steal,
                        guest: ct.guest,
                        guest_nice: ct.guest_nice,
                    },
                )
            })
            .collect(),
        disks: DiskStat::get_all()?,
        net: procfs::net::dev_status()?
            .into_iter()
            .filter(|(_, n)| n.name != "lo")
            .map(|(_, n)| NetworkDevice {
                name: n.name,
                recv_bytes: n.recv_bytes,
                recv_packets: n.recv_packets,
                recv_errs: n.recv_errs,
                recv_drop: n.recv_drop,
                recv_fifo: n.recv_fifo,
                recv_frame: n.recv_frame,
                recv_compressed: n.recv_compressed,
                recv_multicast: n.recv_multicast,
                sent_bytes: n.sent_bytes,
                sent_packets: n.sent_packets,
                sent_errs: n.sent_errs,
                sent_drop: n.sent_drop,
                sent_fifo: n.sent_fifo,
                sent_colls: n.sent_colls,
                sent_carrier: n.sent_carrier,
                sent_compressed: n.sent_compressed,
            })
            .collect(),
    })
}

pub fn list_sysinfo() -> impl warp::Reply {
    let res = collect_sysinfo();

    debug!("sysinfo: {:?}", res);

    match res {
        Ok(s) => ApiReply::Ok(warp::reply::with_status(
            warp::reply::json(&s),
            StatusCode::OK,
        )),
        Err(e) => ApiReply::Err(warp::reply::with_status(
            warp::reply::json(&ErrorMessage {
                message: format!("{}", e),
            }),
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskStat {
    name: String,
    reads_completed: u64,
    reads_merged: u64,
    sectors_read: u64,
    time_reading: u64,
    writes_completed: u64,
    writes_merged: u64,
    sectors_written: u64,
    // in ms
    time_writing: u64,
    io_in_progress: u64,
    // in ms
    time_io: u64,
    // in ms
    time_io_weighted: u64,
}

impl DiskStat {
    fn get_all() -> Result<Vec<DiskStat>, Error> {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(std::fs::File::open("/proc/diskstats")?);
        let mut disks = vec![];
        for line in reader.lines() {
            if let Some(ds) = DiskStat::from_line(&line?)? {
                disks.push(ds);
            }
        }
        Ok(disks)
    }

    fn from_line(line: &str) -> Result<Option<DiskStat>, Error> {
        let mut split = line.trim_start().split_whitespace();
        let name = split
            .nth(2)
            .ok_or_else(|| StringError::from("name missing".to_owned()))?
            .to_string();

        if !name.starts_with("vd") {
            return Ok(None);
        }

        Ok(Some(DiskStat {
            name,
            reads_completed: split
                .next()
                .ok_or_else(|| StringError::from("reads_completed missing".to_owned()))?
                .parse()?,
            reads_merged: split
                .next()
                .ok_or_else(|| StringError::from("reads_merged missing".to_owned()))?
                .parse()?,
            sectors_read: split
                .next()
                .ok_or_else(|| StringError::from("sectors_read missing".to_owned()))?
                .parse()?,
            time_reading: split
                .next()
                .ok_or_else(|| StringError::from("time_reading missing".to_owned()))?
                .parse()?,
            writes_completed: split
                .next()
                .ok_or_else(|| StringError::from("writes_completed missing".to_owned()))?
                .parse()?,
            writes_merged: split
                .next()
                .ok_or_else(|| StringError::from("writes_merged missing".to_owned()))?
                .parse()?,
            sectors_written: split
                .next()
                .ok_or_else(|| StringError::from("sectors_written missing".to_owned()))?
                .parse()?,
            time_writing: split
                .next()
                .ok_or_else(|| StringError::from("time_writing missing".to_owned()))?
                .parse()?,
            io_in_progress: split
                .next()
                .ok_or_else(|| StringError::from("io_in_progress missing".to_owned()))?
                .parse()?,
            time_io: split
                .next()
                .ok_or_else(|| StringError::from("time_io missing".to_owned()))?
                .parse()?,
            time_io_weighted: split
                .next()
                .ok_or_else(|| StringError::from("time_io_weighted missing".to_owned()))?
                .parse()?,
        }))
    }
}

pub struct StringError(String);

impl From<String> for StringError {
    fn from(f: String) -> StringError {
        StringError(f)
    }
}

impl<'a> From<&'a str> for StringError {
    fn from(f: &str) -> StringError {
        StringError(f.into())
    }
}

use std::fmt;

impl fmt::Debug for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for StringError {}
