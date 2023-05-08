use std::{path::Path, fs, io::{BufReader, BufRead}, time::Duration, thread};

use libbpf_rs::{libbpf_sys::BPF_ANY, MapFlags, OpenObject};
use sysinfo::CpuRefreshKind;

use crate::bpf::{UdpflowSkelBuilder,CpuusageSkelBuilder};

pub fn bump_memlock_rlimit() -> Result<(), Box<dyn std::error::Error>> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        println!("Failed to increase rlimit");
    }
    Ok(())
}
pub fn udp_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mut skel_builder = UdpflowSkelBuilder::default();
    bump_memlock_rlimit();
    let mut open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach();
    let trace_file = Path::new("/sys/kernel/debug/tracing/trace_pipe");
    let file = fs::File::open(trace_file).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(l) = line {
            println!("{}", l);
        }
    }
    Ok(())
}

struct val_v {
    totle : f64,
    idle : f64,
    last_time : u64,
    cpu :u64,
}

pub fn cpu_usage() -> Result<(), Box<dyn std::error::Error>> {
    let mut skel_builder = CpuusageSkelBuilder::default();
    bump_memlock_rlimit();
    let mut open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach();
    loop{
    let keys : Vec<_>= skel.maps().cpu_info_map().keys().collect();
    let mut cpu_0: f64 = 0.0;
    let mut cpu_1: f64 = 0.0;
    for key in keys {
        let array: [u8; 2] = [0,1]; 
        let slice:&[u8] = &array;
        let time = skel.maps().cpu_info_map().lookup(&key, MapFlags::ANY)?.unwrap();
        let times :&[u8] = &time;
        
        println!("--------------------");
        unsafe {
            let val_ptr:*const val_v = times.as_ptr() as *const val_v;
            let val_ref: &val_v = &*val_ptr;
            match val_ref.cpu {
                0 => cpu_0 = (val_ref.totle-val_ref.idle)/val_ref.totle,
                1 => cpu_1 = (val_ref.totle-val_ref.idle)/val_ref.totle,
                _ => println!(""),
            };
            println!("cpu processer id is 0,The usage is {}",cpu_0);
            println!("cpu processer id is 1,The usage is {}",cpu_1);
            println!("--------------------");
        }; 
    }
    thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}