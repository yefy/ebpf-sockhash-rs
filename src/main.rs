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

    let progs = skel.progs();
    let bpf_sk_msg_verdict = progs.bpf_sk_msg_verdict();
    println!("bpf_sk_msg_verdict prog_type:{}", bpf_sk_msg_verdict.prog_type());
    println!("bpf_sk_msg_verdict attach_type:{}", bpf_sk_msg_verdict.attach_type());
    println!("bpf_sk_msg_verdict name:{:?}", bpf_sk_msg_verdict.name());
    println!("bpf_sk_msg_verdict section:{:?}", bpf_sk_msg_verdict.section());

    let sock_hash_fd = skel.maps_mut().sock_hash().fd();
    let _bpf_sk_msg_verdict = skel
        .progs_mut()
        .bpf_sk_msg_verdict()
        .attach_sockmap(sock_hash_fd)?;



    let progs = skel.progs();
    let bpf_sockops = progs.bpf_sockops();
    println!("bpf_sockops prog_type:{}", bpf_sockops.prog_type());
    println!("bpf_sockops attach_type:{}", bpf_sockops.attach_type());
    println!("bpf_sockops name:{:?}", bpf_sockops.name());
    println!("bpf_sockops section:{:?}", bpf_sockops.section());

    let cgroup_fd = std::fs::OpenOptions::new()
        //.custom_flags(libc::O_DIRECTORY)
        //.create(true)
        .read(true)
        .write(false)
        .open("/sys/fs/cgroup/unified/")
        .map_err(|e| anyhow::anyhow!("open e:{}", e))?
        .as_raw_fd();
    let _bpf_sockops = skel
        .progs_mut()
        .bpf_sockops()
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