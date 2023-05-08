use std::{time::Duration, fs, thread::sleep};

pub fn cpu_usage_test() {
    let interval = Duration::from_secs(5);
    let mut prev_idle = 0;
    let mut prev_total = 0;

    loop {
        let cpu_data = fs::read_to_string("/proc/stat").unwrap();
        let mut cpu_parts = cpu_data.lines().next().unwrap().split_whitespace().skip(1);
        let user: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let nice: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let system: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let idle: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let iowait: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let irq: u64 = cpu_parts.next().unwrap().parse().unwrap();
        let softirq: u64 = cpu_parts.next().unwrap().parse().unwrap();

        let total = user + nice + system + idle + iowait + irq + softirq;
        let diff_idle = idle - prev_idle;
        let diff_total = total - prev_total;
        let diff_usage = (100.0 * (diff_total as f64 - diff_idle as f64) / diff_total as f64).round();
        println!("CPU usage: {:.2}%", diff_usage);

        prev_idle = idle;
        prev_total = total;
        sleep(interval);
    }
}