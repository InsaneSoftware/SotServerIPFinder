## Building
This works only on Windows.

Install rust language: https://www.rust-lang.org/tools/install

Install Npccap: https://npcap.com/dist/npcap-1.72.exe

1. Download and run [the Npcap installer](https://npcap.com/dist/npcap-1.72.exe). Select WinPCap compatibility mode. 
2. Run `cargo build --release`.

The [build script](build.rs) will automatically download [the Npcap SDK version 1.13](https://npcap.com/dist/npcap-sdk-1.13.zip) and place it in the `libs` directory.
