use std::{net::IpAddr, process::Command};
use etherparse::{IpHeader, PacketHeaders};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, RefreshKind, System, SystemExt};
use reqwest;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use tokio::runtime::Runtime;
use tokio::time::Duration;
use get_if_addrs::{get_if_addrs};

#[derive(Serialize, Deserialize)]
struct Config {
    discord_webhook_url: String,
    name: String,
}

impl Config {
    fn new() -> Self {
        Config {
            discord_webhook_url: "https://discord.com/api/webhooks/your/webhook/url".to_string(),
            name: "ChangeMe".to_string(),
        }
    }

    fn load_or_create() -> Self {
        let config_path = "config.json";
        if Path::new(config_path).exists() {
            let config_str = fs::read_to_string(config_path)
                .expect("Failed to read config.json");
            serde_json::from_str(&config_str).expect("Failed to parse config.json")
        } else {
            let config = Config::new();
            let config_str = serde_json::to_string_pretty(&config)
                .expect("Failed to serialize config");
            fs::write(config_path, config_str)
                .expect("Failed to write default config.json");
            config
        }
    }
}

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
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    rt.block_on(async {
        println!("Insane Sea Of Thieves Server ip Gatherer\n");

        let mut config = Config::load_or_create(); // Declare `config` as mutable
        let mut insane_vpn_interface_name = None;
        let devices = pcap::Device::list().unwrap();

        // Check if the name is still the default value
        if config.name == "ChangeMe" {
            println!("It seems like you're using the default name. Please enter your correct name/identifier:");
            let mut new_name = String::new();
            std::io::stdin().read_line(&mut new_name).expect("Failed to read line");
            let new_name = new_name.trim().to_string();
            config.name = new_name;

            // Save the updated name back to the config file
            let config_str = serde_json::to_string_pretty(&config).expect("Failed to serialize config");
            fs::write("config.json", config_str).expect("Failed to write updated config.json");
        }


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

        println!("Awesome! Npcap requirement found.\n");

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

        // Check for VPN connections
        match get_if_addrs() {
            Ok(ifaces) => {
                for iface in ifaces {

                    // Directly use the ip() method
                    let ip_addr = iface.addr.ip();
                    if ip_addr.to_string().contains("25.168") {
                        insane_vpn_interface_name = Some(iface.name); // Store the VPN interface name
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to get network interfaces: {}", e);
            }
        }


        let auto_found_dev = devices.iter().find(|d| {
            if insane_vpn_interface_name.is_some() {
                false
            } else {
                d.addresses.iter().any(|addr| {
                    if let IpAddr::V4(addr) = addr.addr {
                        addr.octets()[0] == 192 && addr.octets()[1] == 168
                    } else {
                        false
                    }
                })
            }
        });

        let dev = match auto_found_dev {
            Some(d) => {
                println!("Using auto-found network adapter: {:?} \n", d.desc);
                d.clone()
            }
            None => {
                if insane_vpn_interface_name.is_some() {
                    let mut n = 0;
                    println!("Connected to an Insane Spike VPN!");

                    let mut i = 1;
                    for device in devices.clone() {
                        if device.desc.clone().unwrap().contains("Miniport (IP)") {
                            println!("Auto selecting network adapter: {}", device.desc.clone().unwrap());
                            n = i;
                            break;
                        };
                        i += 1;
                    }

                    if n == 0 {
                        println!("Couldn't guess which VPN adapter to use. Please select one manually. (mostly its called VPN, Miniport etc)3");

                        println!("Network adapters attached to your PC: ");

                        let devices = pcap::Device::list().expect("device lookup failed");
                        let mut i = 1;

                        for device in devices.clone() {
                            println!(
                                "    {i}. {:?}",
                                device.desc.clone().unwrap_or_else(|| device.name.clone())
                            );

                            i += 1;
                        }


                        // prompt user for their device
                        println!(
                            "Please select your WiFi or Ethernet card, or if you're on a VPN, select the VPN: "
                        );
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).unwrap();
                        n = input.trim().parse::<usize>().unwrap() - 1;
                    }

                    (&devices[n]).clone()
                } else {
                    println!("Couldn't guess which network adapter to use. Please select one manually.");

                    println!("Network adapters attached to your PC: ");

                    let devices = pcap::Device::list().expect("device lookup failed");
                    let mut i = 1;

                    for device in devices.clone() {
                        println!(
                            "    {i}. {:?}",
                            device.desc.clone().unwrap_or_else(|| device.name.clone())
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
            }
        };

        let mut cap = pcap::Capture::from_device(dev)
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap();

        println!("Waiting for you to connect to a game in Sea of Thieves...\n");

        let webhook_url = &config.discord_webhook_url;
        let mut last_server = String::new();
        let mut connection_count = 0;
        let mut ignore_local_port: u16 = 0;

        // Iterate udp packets
        loop {
            if let Ok(raw_packet) = cap.next_packet() {
                if let Ok(packet) = PacketHeaders::from_ethernet_slice(raw_packet.data) {
                    if let Some(IpHeader::Version4(ipv4, _)) = packet.ip {
                        if let Some(transport) = packet.transport {
                            if let Some(udp) = transport.udp() {
                                if udp.destination_port == 3075 || udp.destination_port == 30005 || udp.source_port == ignore_local_port {
                                    continue;
                                }
                                if get_sot_ports(sot_pid).contains(&udp.source_port) {
                                    let ip = ipv4.destination.map(|c| c.to_string()).join(".");
                                    let server_info = format!("{}:{}", ip, udp.destination_port);
                                    if server_info != last_server {
                                        connection_count += 1;

                                        if connection_count == 2 {
                                            ignore_local_port = udp.source_port;
                                            println!("Ignoring Local port: {}", udp.source_port);
                                            continue;
                                        }

                                        // Use the reference to webhook_url here
                                        let json_payload = serde_json::json!({
                                                "content": format!("Server: IP: {}:{}, Name: {}", ip, udp.destination_port, config.name)
                                        }).to_string();

                                        println!("You are connected to: {}:{}", ip, udp.destination_port);
                                        last_server = server_info;

                                        let client = reqwest::Client::new();
                                        let res = client.post(webhook_url) // No need to clone, as we're using a reference
                                            .header("Content-Type", "application/json")
                                            .body(json_payload)
                                            .send()
                                            .await;

                                        match res {
                                            Ok(_response) => {
                                                println!("Server info sent to Discord webhook.");
                                            }
                                            Err(e) => {
                                                eprintln!("Request failed: {}", e);
                                            }
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_secs(1)).await; // Add a 1-second delay
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