use std::{net::IpAddr, process::Command};
use etherparse::{IpHeader, PacketHeaders};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use reqwest;
use std::{fs, path::Path, io::Write};
use tokio::runtime::Runtime; // Make sure this is included in your imports

fn get_sot_pid(s: &System) -> Option<u32> {
    for process in s.processes_by_name("SoTGame.exe") {
        return Some(process.pid().as_u32());
    }
    None
}

fn get_sot_ports(pid: u32) -> Vec<u16> {
    let p = &pid.to_string();
    let cmd = Command::new("netstat")
        .arg("-anop")
        .arg("udp")
        .output()
        .unwrap();

    let filtered_stdout = cmd
        .stdout
        .iter()
        .filter(|c| c.is_ascii())
        .copied()
        .collect();

    String::from_utf8(filtered_stdout)
        .unwrap()
        .lines()
        .filter(|line| line.contains(p))
        .map(|f| {
            let addr = f.split_whitespace().skip(1).next().unwrap();
            let port = addr.split(':').last().unwrap();
            port.parse::<u16>().unwrap()
        })
        .collect()
}

fn main() {

    println!("Insane Sea Of Thieves Server ip Gatherer\n");

    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        let secret = if Path::new("secret.txt").exists() {
            fs::read_to_string("secret.txt").expect("Failed to read secret.txt")
        } else {
            println!("Enter the secret from https://sot.insane.software:");
            let mut secret = String::new();
            std::io::stdin().read_line(&mut secret).expect("Failed to read line");
            let secret = secret.trim().to_string();

            println!("\n");
            let mut file = fs::File::create("secret.txt").expect("Failed to create secret.txt");
            file.write_all(secret.as_bytes()).expect("Failed to write to secret.txt");
            secret
        };

        let name = if Path::new("name.txt").exists() {
            fs::read_to_string("name.txt").expect("Failed to read name.txt")
        } else {
            println!("Enter your name/identifier");
            let mut name = String::new();
            std::io::stdin().read_line(&mut name).expect("Failed to read line");
            let name = name.trim().to_string();

            println!("\n");
            let mut file = fs::File::create("name.txt").expect("Failed to create name.txt");
            file.write_all(name.as_bytes()).expect("Failed to write to name.txt");
            name
        };

        println!("Making sure you have Npcap installed...");


    unsafe {
        let try_load_wpcap = libloading::Library::new("wpcap.dll");
        if try_load_wpcap.is_err() {
            println!("{}", "*".repeat(80));
            println!("ERROR: It doesn't seem like you've installed Npcap.");
            println!("Please install Npcap from\n    https://npcap.com/dist/npcap-1.72.exe\n");
            println!("*** MAKE SURE TO INSTALL WITH 'WinPcap API Compatibility' TURNED ON ***");
            println!("{}\n", "*".repeat(80));
            println!("Want to continue anyway? Enter 'yes' or 'no':");
            
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let input = input.trim().to_lowercase();
            if !(input == "y" || input == "yes") {
                std::process::exit(1);
            }
        }
    }

    println!("Npcap found! lets continue...\n");

    // wait until we get a sot pid
     println!("Finding your Sea of thieves game...");
          let mut s = System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
          let sot_pid = loop {
              if let Some(pid) = get_sot_pid(&s) {
                  break pid;
              }
              s.refresh_processes();
          };

    println!("Found! PID: {} \n", sot_pid);

    let devices = pcap::Device::list().unwrap();
    let auto_found_dev = devices.iter().find(|d| {
        d.addresses.iter().any(|addr| {
            if let IpAddr::V4(addr) = addr.addr {
                addr.octets()[0] == 192 && addr.octets()[1] == 168
            } else {
                false
            }
        })
    });

    let dev = match auto_found_dev {
        Some(d) => d.clone(),
        None => {
            println!("Couldn't guess which network adapter to use. Please select one manually.");
            println!("Network adapters attached to your PC: ");

            let devices = pcap::Device::list().expect("device lookup failed");
            let mut i = 1;

            for device in devices.clone() {
                println!(
                    "    {i}. {:?}",
                    device.desc.clone().unwrap_or(device.name.clone())
                );
                i += 1;
            }

            // prompt user for their device
            println!(
                "Please select your WiFi or Ethernet card, or if you're on a VPN, select the VPN: "
            );
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            let n = input.trim().parse::<usize>().unwrap() - 1;

            (&devices[n]).clone()
        }
    };

     let mut cap = pcap::Capture::from_device(dev)
                .unwrap()
                .immediate_mode(true)
                .open()
                .unwrap();

    println!("Waiting for you to connect to a game in Sea of Thieves...\n");

    // iterate udp packets
           loop {
               if let Ok(raw_packet) = cap.next_packet() {
                   if let Ok(packet) = PacketHeaders::from_ethernet_slice(raw_packet.data) {
                       if let Some(IpHeader::Version4(ipv4, _)) = packet.ip {
                           if let Some(transport) = packet.transport {
                               if let Some(udp) = transport.udp() {
                                   if udp.destination_port == 3075 || udp.destination_port == 30005 {
                                       continue;
                                   }

                                   if get_sot_ports(sot_pid).contains(&udp.source_port) {
                                       let ip = ipv4.destination.map(|c| c.to_string()).join(".");
                                       println!("You are connected to: {}:{}", ip, udp.destination_port);

                                       let url = format!("https://sot.insane.software/api/data?ip={}&port={}&secret={}&name={}", ip, udp.destination_port, secret, name);
                                       match reqwest::get(&url).await {
                                           Ok(_response) => {
                                               println!("Server info sended to https://sot.insane.software?secret={}", secret );
                                           }
                                           Err(e) => {
                                               eprintln!("Request failed: {}", e);
                                           }
                                       }

                                       println!("\nPress Enter to check again.");

                                       std::io::stdin().read_line(&mut String::new()).unwrap();
                                       continue;
                                   }
                               }
                           }
                       }
                   }
               }
           }
       });
   }