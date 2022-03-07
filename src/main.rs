use anyhow::{bail, Result};
use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use structopt::StructOpt;
//use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::thread;

#[path = "bpf/.output/ebpf_sockhash.skel.rs"]
mod ebpf_sockhash;
use ebpf_sockhash::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = EbpfSockhashSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let bpf_redir = skel.progs();
    let bpf_redir = bpf_redir.bpf_redir();
    println!("bpf_redir prog_type:{}", bpf_redir.prog_type());
    println!("bpf_redir attach_type:{}", bpf_redir.attach_type());
    println!("bpf_redir name:{:?}", bpf_redir.name());
    println!("bpf_redir section:{:?}", bpf_redir.section());

    let sock_ops_map_fd = skel.maps_mut().sock_ops_map().fd();
    let _bpf_redir = skel
        .progs_mut()
        .bpf_redir()
        .attach_sockmap(sock_ops_map_fd)?;



    let bpf_sockmap = skel.progs();
    let bpf_sockmap = bpf_sockmap.bpf_sockmap();
    println!("bpf_sockmap prog_type:{}", bpf_sockmap.prog_type());
    println!("bpf_sockmap attach_type:{}", bpf_sockmap.attach_type());
    println!("bpf_sockmap name:{:?}", bpf_sockmap.name());
    println!("bpf_sockmap section:{:?}", bpf_sockmap.section());

    let cgroup_fd = std::fs::OpenOptions::new()
        //.custom_flags(libc::O_DIRECTORY)
        //.create(true)
        .read(true)
        .write(false)
        .open("/sys/fs/cgroup/unified/")
        .map_err(|e| anyhow::anyhow!("open e:{}", e))?
        .as_raw_fd();
    let _bpf_sockmap = skel
        .progs_mut()
        .bpf_sockmap()
        .attach_cgroup(cgroup_fd)?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}