use std::{fs, thread::sleep, time::Duration};

pub fn mem_usage() {
    loop{
     let content = fs::read_to_string("/proc/meminfo").expect("something went wrong reading the file");
     let lines:Vec<&str>= content.split('\n').collect();
     // 获取内存总数&&空闲内存数
     let total_mem = lines[0].split_whitespace().nth(1).unwrap().parse::<u64>().unwrap();
     let free_mem = lines[1].split_whitespace().nth(1).unwrap().parse::<u64>().unwrap();
 
     let used_mem = total_mem - free_mem;
     let mem_used_ratio = used_mem as f64 / total_mem as f64;
     println!("Memory used is: {:.2}%",mem_used_ratio * 100.0);
     sleep(Duration::from_secs(5));
    }
 }