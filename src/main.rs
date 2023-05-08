use std::{ env};
mod bpf;
mod lib;
mod bpf_test;
// use bpf_test::cpu_usage_skel::*;
use lib::{mem_usage::*, bpf_load::{udp_flow, cpu_usage}};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args :Vec<String>= env::args().collect(); 
    let command = args.get(1).unwrap();
    match command.as_str() {
        "udp" => udp_flow()?,
        "cpu" => cpu_usage()?,
        "mem" => mem_usage(),
        "nfs" => println!(" "),
        _ => println!("Unknow command"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::mem_usage;
    #[test]
    fn test_mem_usage() {
        mem_usage();
    }
}