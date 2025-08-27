#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use ipscan_rs::{
    Feeder, FetcherRegistry, RangeFeeder, ResultType, ScannerConfig, ScanningResult,
    ScanningSubject,
};
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

#[derive(Clone)]
struct ScanResult {
    address: String,
    hostname: String,
    ping: String,
    ports: String,
    mac: String,
    status: ResultType,
}

#[allow(dead_code)]
enum ScanState {
    Idle,
    Scanning {
        start_time: Instant,
        progress: f32,
        current: usize,
        total: usize,
    },
    Completed {
        duration: std::time::Duration,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum SortColumn {
    IpAddress,
}

#[derive(Clone, Copy, PartialEq)]
enum SortOrder {
    Ascending,
    Descending,
}

struct IpScanApp {
    start_ip: String,
    end_ip: String,
    port_string: String,
    threads: usize,
    ping_timeout: u64,
    scan_dead: bool,

    results: Arc<Mutex<Vec<ScanResult>>>,
    scan_state: Arc<Mutex<ScanState>>,
    status_message: Arc<Mutex<String>>,

    runtime: Arc<Runtime>,
    filter_text: String,
    show_dead: bool,

    total_hosts: usize,
    alive_hosts: usize,
    hosts_with_ports: usize,

    show_settings: bool,
    settings_temp: Settings,

    _selected_host: Option<ScanResult>,
    _show_context_menu: bool,
    _context_menu_pos: egui::Pos2,

    use_cidr: bool,
    cidr_input: String,
    selected_mask: String,

    sort_column: Option<SortColumn>,
    sort_order: SortOrder,
}

#[derive(Clone)]
struct Settings {
    threads: usize,
    ping_timeout: u64,
    ping_count: u8,
    port_timeout: u64,
    min_port_timeout: u64,
    adapt_port_timeout: bool,
    scan_dead: bool,
    auto_save_results: bool,
    theme: Theme,
}

#[derive(Clone, PartialEq)]
enum Theme {
    Light,
    Dark,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            threads: 100,
            ping_timeout: 2000,
            ping_count: 3,
            port_timeout: 500,
            min_port_timeout: 100,
            adapt_port_timeout: true,
            scan_dead: false,
            auto_save_results: false,
            theme: Theme::Dark,
        }
    }
}

impl Default for IpScanApp {
    fn default() -> Self {
        let settings = Settings::default();
        Self {
            start_ip: "192.168.0.1".to_string(),
            end_ip: "192.168.0.254".to_string(),
            port_string: "21-23,25,80,110,139,443,445,3389,8080".to_string(),
            threads: settings.threads,
            ping_timeout: settings.ping_timeout,
            scan_dead: settings.scan_dead,

            results: Arc::new(Mutex::new(Vec::new())),
            scan_state: Arc::new(Mutex::new(ScanState::Idle)),
            status_message: Arc::new(Mutex::new("Ready".to_string())),

            runtime: Arc::new(Runtime::new().unwrap()),
            filter_text: String::new(),
            show_dead: false,

            total_hosts: 0,
            alive_hosts: 0,
            hosts_with_ports: 0,

            show_settings: false,
            settings_temp: settings,

            _selected_host: None,
            _show_context_menu: false,
            _context_menu_pos: egui::Pos2::new(0.0, 0.0),

            use_cidr: false,
            cidr_input: "192.168.1.0/24".to_string(),
            selected_mask: "/24".to_string(),

            sort_column: None,
            sort_order: SortOrder::Ascending,
        }
    }
}

impl IpScanApp {
    fn execute_terminal_command(&self, command: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("cmd")
                .arg("/c")
                .arg("start")
                .arg("cmd")
                .arg("/k")
                .arg(command)
                .spawn();
        }

        #[cfg(target_os = "linux")]
        {
            // Try different terminal emulators in order of preference
            let terminals = [
                ("gnome-terminal", vec!["--", "bash", "-c"]),
                ("konsole", vec!["-e", "bash", "-c"]),
                ("xfce4-terminal", vec!["-x", "bash", "-c"]),
                ("terminator", vec!["-x", "bash", "-c"]),
                ("xterm", vec!["-e", "bash", "-c"]),
            ];

            let full_command = format!("{} ; echo 'Press Enter to close'; read", command);

            for (terminal, args) in terminals.iter() {
                if Command::new("which")
                    .arg(terminal)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    let mut cmd = Command::new(terminal);
                    for arg in args {
                        cmd.arg(arg);
                    }
                    cmd.arg(&full_command);
                    if cmd.spawn().is_ok() {
                        return;
                    }
                }
            }

            // Fallback to x-terminal-emulator if available
            let _ = Command::new("x-terminal-emulator")
                .arg("-e")
                .arg("bash")
                .arg("-c")
                .arg(&full_command)
                .spawn();
        }

        #[cfg(target_os = "macos")]
        {
            let script = format!(r#"tell application "Terminal" to do script "{}""#, command);
            let _ = Command::new("osascript").arg("-e").arg(script).spawn();
        }
    }

    fn open_url(&self, url: &str) {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("cmd").arg("/c").arg("start").arg(url).spawn();
        }

        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("xdg-open").arg(url).spawn();
        }

        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("open").arg(url).spawn();
        }
    }

    fn update_cidr_mask(&mut self, mask: &str) {
        if let Some(base) = self.cidr_input.split('/').next() {
            self.cidr_input = format!("{}{}", base, mask);
        }
    }

    fn calculate_cidr_range(&self) -> Option<(String, String, usize)> {
        let parts: Vec<&str> = self.cidr_input.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let base_ip = parts[0];
        let mask_bits: u32 = parts[1].parse().ok()?;

        let octets: Vec<u8> = base_ip.split('.').filter_map(|s| s.parse().ok()).collect();

        if octets.len() != 4 || mask_bits > 32 {
            return None;
        }

        let ip_num = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);

        let network_mask = if mask_bits == 0 {
            0
        } else {
            !0u32 << (32 - mask_bits)
        };
        let network_addr = ip_num & network_mask;

        let broadcast_addr = network_addr | !network_mask;

        let first_addr = if mask_bits < 31 {
            network_addr + 1
        } else {
            network_addr
        };
        let last_addr = if mask_bits < 31 {
            broadcast_addr - 1
        } else {
            broadcast_addr
        };

        let total_hosts = (last_addr - first_addr + 1) as usize;

        let first_ip = format!(
            "{}.{}.{}.{}",
            (first_addr >> 24) & 0xFF,
            (first_addr >> 16) & 0xFF,
            (first_addr >> 8) & 0xFF,
            first_addr & 0xFF
        );

        let last_ip = format!(
            "{}.{}.{}.{}",
            (last_addr >> 24) & 0xFF,
            (last_addr >> 16) & 0xFF,
            (last_addr >> 8) & 0xFF,
            last_addr & 0xFF
        );

        Some((first_ip, last_ip, total_hosts))
    }

    fn parse_ip_for_sorting(ip_str: &str) -> Option<IpAddr> {
        ip_str.parse().ok()
    }

    fn sort_results(&mut self) {
        if self.sort_column.is_some() {
            let mut results = self.results.lock().unwrap();

            results.sort_by(|a, b| {
                let cmp = match (
                    Self::parse_ip_for_sorting(&a.address),
                    Self::parse_ip_for_sorting(&b.address),
                ) {
                    (Some(ip_a), Some(ip_b)) => ip_a.cmp(&ip_b),
                    _ => a.address.cmp(&b.address),
                };

                match self.sort_order {
                    SortOrder::Ascending => cmp,
                    SortOrder::Descending => cmp.reverse(),
                }
            });
        }
    }

    fn start_scan(&mut self) {
        if self.use_cidr {
            if let Some((start, end, total)) = self.calculate_cidr_range() {
                self.start_ip = start.clone();
                self.end_ip = end.clone();
                *self.status_message.lock().unwrap() =
                    format!("Scanning CIDR {} ({} hosts)", self.cidr_input, total);
            } else {
                *self.status_message.lock().unwrap() = "Invalid CIDR notation".to_string();
                return;
            }
        }

        let start_ip: IpAddr = match self.start_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                *self.status_message.lock().unwrap() = "Invalid start IP".to_string();
                return;
            }
        };

        let end_ip: IpAddr = match self.end_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                *self.status_message.lock().unwrap() = "Invalid end IP".to_string();
                return;
            }
        };

        self.results.lock().unwrap().clear();
        self.total_hosts = 0;
        self.alive_hosts = 0;
        self.hosts_with_ports = 0;

        *self.scan_state.lock().unwrap() = ScanState::Scanning {
            start_time: Instant::now(),
            progress: 0.0,
            current: 0,
            total: 0,
        };
        *self.status_message.lock().unwrap() = format!("Scanning {} to {}", start_ip, end_ip);

        let config = Arc::new(ScannerConfig {
            max_threads: self.threads,
            ping_timeout_ms: self.ping_timeout,
            scan_dead_hosts: self.scan_dead,
            port_string: self.port_string.clone(),
            use_requested_ports: true,
            ping_count: self.settings_temp.ping_count,
            port_timeout_ms: self.settings_temp.port_timeout,
            min_port_timeout_ms: self.settings_temp.min_port_timeout,
            adapt_port_timeout: self.settings_temp.adapt_port_timeout,
        });

        let results = self.results.clone();
        let scan_state = self.scan_state.clone();
        let status_message = self.status_message.clone();

        self.runtime.spawn(async move {
            let fetcher_registry = Arc::new(RwLock::new(FetcherRegistry::new()));
            fetcher_registry
                .write()
                .await
                .register_default_fetchers(config.clone());

            match RangeFeeder::new(start_ip, end_ip) {
                Ok(mut feeder) => {
                    let total = feeder.total_addresses();
                    let start_time = Instant::now();
                    let scanned = Arc::new(Mutex::new(0));

                    // Update initial state with total count
                    *scan_state.lock().unwrap() = ScanState::Scanning {
                        start_time,
                        progress: 0.0,
                        current: 0,
                        total,
                    };

                    let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_threads));
                    let mut tasks = tokio::task::JoinSet::new();

                    while let Some(address) = feeder.next_address().await {
                        let permit = semaphore.clone().acquire_owned().await.unwrap();
                        let fetcher_registry = fetcher_registry.clone();
                        let config = config.clone();
                        let results = results.clone();
                        let scan_state = scan_state.clone();
                        let status_message = status_message.clone();
                        let scanned = scanned.clone();

                        tasks.spawn(async move {
                            let _permit = permit; // Hold permit until task completes

                            let mut subject = ScanningSubject::new(address, config.clone());
                            let mut result = ScanningResult::new(address);

                            let registry = fetcher_registry.read().await;
                            for fetcher in registry.get_selected_fetchers() {
                                if let Ok(value) = fetcher.scan(&mut subject).await {
                                    result.add_value(fetcher.id(), value);
                                }

                                if subject.is_aborted() && !config.scan_dead_hosts {
                                    break;
                                }
                            }

                            result.set_type(subject.result_type());

                            let current_scanned = {
                                let mut sc = scanned.lock().unwrap();
                                *sc += 1;
                                *sc
                            };

                            let progress = current_scanned as f32 / total as f32;
                            *scan_state.lock().unwrap() = ScanState::Scanning {
                                start_time,
                                progress,
                                current: current_scanned,
                                total,
                            };

                            *status_message.lock().unwrap() = format!(
                                "Scanning... ({}/{} - {:.0}%)",
                                current_scanned,
                                total,
                                progress * 100.0
                            );

                            // Add result immediately if not dead (or if scan_dead is enabled)
                            if result.result_type() != ResultType::Dead || config.scan_dead_hosts {
                                let gui_result = ScanResult {
                                    address: result.address().to_string(),
                                    hostname: result
                                        .get_value("hostname")
                                        .unwrap_or(&"[n/a]".to_string())
                                        .clone(),
                                    ping: result
                                        .get_value("ping")
                                        .unwrap_or(&"[n/a]".to_string())
                                        .clone(),
                                    ports: result
                                        .get_value("ports")
                                        .unwrap_or(&"[n/a]".to_string())
                                        .clone(),
                                    mac: result
                                        .get_value("mac")
                                        .unwrap_or(&"[n/a]".to_string())
                                        .clone(),
                                    status: result.result_type(),
                                };

                                results.lock().unwrap().push(gui_result);
                            }
                        });
                    }

                    // Wait for all tasks to complete
                    while tasks.join_next().await.is_some() {
                        // Tasks complete one by one, results are added in real-time
                    }

                    let duration = start_time.elapsed();
                    let final_results = results.lock().unwrap();
                    let alive = final_results
                        .iter()
                        .filter(|r| r.status != ResultType::Dead)
                        .count();
                    let with_ports = final_results
                        .iter()
                        .filter(|r| r.status == ResultType::WithPorts)
                        .count();

                    *scan_state.lock().unwrap() = ScanState::Completed { duration };
                    *status_message.lock().unwrap() = format!(
                        "Scan completed: {} hosts scanned, {} alive, {} with open ports in {:.2}s",
                        total,
                        alive,
                        with_ports,
                        duration.as_secs_f32()
                    );
                }
                Err(e) => {
                    *scan_state.lock().unwrap() = ScanState::Idle;
                    *status_message.lock().unwrap() = format!("Invalid IP range: {}", e);
                }
            }
        });
    }

    fn stop_scan(&mut self) {
        *self.scan_state.lock().unwrap() = ScanState::Idle;
        *self.status_message.lock().unwrap() = "Scan stopped".to_string();
    }

    fn export_results(&self, format: &str) {
        let results = self.results.lock().unwrap();

        let content = match format {
            "csv" => {
                let mut csv =
                    String::from("IP Address,Hostname,Ping,MAC Address,Open Ports,Status\n");
                for r in results.iter() {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{:?}\n",
                        r.address, r.hostname, r.ping, r.mac, r.ports, r.status
                    ));
                }
                csv
            }
            "json" => serde_json::to_string_pretty(
                &results
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "address": r.address,
                            "hostname": r.hostname,
                            "ping": r.ping,
                            "mac": r.mac,
                            "ports": r.ports,
                            "status": format!("{:?}", r.status)
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            _ => {
                let mut text = String::new();
                text.push_str("IP Address\tHostname\tPing\tMAC Address\tOpen Ports\tStatus\n");
                text.push_str(
                    "------------------------------------------------------------------------\n",
                );
                for r in results.iter() {
                    text.push_str(&format!(
                        "{}\t{}\t{}\t{}\t{}\t{:?}\n",
                        r.address, r.hostname, r.ping, r.mac, r.ports, r.status
                    ));
                }
                text
            }
        };

        let extension = match format {
            "csv" => "csv",
            "json" => "json",
            _ => "txt",
        };

        if let Some(path) = rfd::FileDialog::new()
            .set_title(format!("Save scan results as {}", format.to_uppercase()))
            .set_file_name(format!(
                "scan_results_{}.{}",
                chrono::Local::now().format("%Y%m%d_%H%M%S"),
                extension
            ))
            .add_filter(format!("{} files", format.to_uppercase()), &[extension])
            .add_filter("All files", &["*"])
            .save_file()
        {
            match std::fs::write(&path, content) {
                Ok(_) => {
                    *self.status_message.lock().unwrap() =
                        format!("Results exported to: {}", path.display());
                }
                Err(e) => {
                    *self.status_message.lock().unwrap() = format!("Failed to save file: {}", e);
                }
            }
        } else {
            *self.status_message.lock().unwrap() = "Export cancelled".to_string();
        }
    }
}

impl eframe::App for IpScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let visuals = match self.settings_temp.theme {
            Theme::Dark => egui::Visuals::dark(),
            Theme::Light => egui::Visuals::light(),
        };
        ctx.set_visuals(visuals);

        if self.show_settings {
            egui::Window::new("⚙ Settings")
                .collapsible(false)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Scanning Configuration");
                    ui.separator();

                    egui::Grid::new("settings_grid")
                        .num_columns(2)
                        .spacing([40.0, 10.0])
                        .show(ui, |ui| {
                            ui.label("Number of threads:");
                            ui.add(egui::Slider::new(&mut self.settings_temp.threads, 1..=500)
                                .text("threads"));
                            ui.end_row();

                            ui.label("Ping timeout (ms):");
                            ui.add(egui::Slider::new(&mut self.settings_temp.ping_timeout, 100..=10000)
                                .text("ms"));
                            ui.end_row();

                            ui.label("Ping count:");
                            ui.add(egui::Slider::new(&mut self.settings_temp.ping_count, 1..=10)
                                .text("packets"));
                            ui.end_row();

                            ui.label("Port timeout (ms):");
                            ui.add(egui::Slider::new(&mut self.settings_temp.port_timeout, 50..=5000)
                                .text("ms"));
                            ui.end_row();

                            ui.label("Min port timeout (ms):");
                            ui.add(egui::Slider::new(&mut self.settings_temp.min_port_timeout, 10..=1000)
                                .text("ms"));
                            ui.end_row();
                        });

                    ui.separator();
                    ui.heading("Options");

                    ui.checkbox(&mut self.settings_temp.adapt_port_timeout,
                        "Adapt port timeout to ping RTT");
                    ui.checkbox(&mut self.settings_temp.scan_dead,
                        "Continue scanning dead hosts");
                    ui.checkbox(&mut self.settings_temp.auto_save_results,
                        "Auto-save results after scan");

                    ui.separator();
                    ui.heading("Appearance");

                    ui.horizontal(|ui| {
                        ui.label("Theme:");
                        ui.selectable_value(&mut self.settings_temp.theme, Theme::Light, "☀ Light");
                        ui.selectable_value(&mut self.settings_temp.theme, Theme::Dark, "🌙 Dark");
                    });

                    ui.separator();
                    ui.heading("Common Port Presets");

                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Web").clicked() {
                            self.port_string = "80,443,8080,8443".to_string();
                        }
                        if ui.button("Mail").clicked() {
                            self.port_string = "25,110,143,465,587,993,995".to_string();
                        }
                        if ui.button("File Transfer").clicked() {
                            self.port_string = "20,21,22,69,115,139,445,3389".to_string();
                        }
                        if ui.button("Database").clicked() {
                            self.port_string = "1433,1521,3306,5432,5984,6379,7000,7001,8086,9042,27017".to_string();
                        }
                        if ui.button("Top 100").clicked() {
                            self.port_string = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157".to_string();
                        }
                        if ui.button("All (1-1000)").clicked() {
                            self.port_string = "1-1000".to_string();
                        }
                    });

                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("Apply").clicked() {
                            self.threads = self.settings_temp.threads;
                            self.ping_timeout = self.settings_temp.ping_timeout;
                            self.scan_dead = self.settings_temp.scan_dead;
                            self.show_settings = false;
                            *self.status_message.lock().unwrap() = "Settings applied".to_string();
                        }
                        if ui.button("Cancel").clicked() {
                            self.settings_temp.threads = self.threads;
                            self.settings_temp.ping_timeout = self.ping_timeout;
                            self.settings_temp.scan_dead = self.scan_dead;
                            self.show_settings = false;
                        }
                        if ui.button("Reset to Defaults").clicked() {
                            self.settings_temp = Settings::default();
                        }
                    });
                });
        }

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.use_cidr, false, "IP Range");
                ui.selectable_value(&mut self.use_cidr, true, "CIDR");

                ui.separator();

                if self.use_cidr {
                    ui.label("Network:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.cidr_input)
                            .desired_width(150.0)
                            .hint_text("192.168.1.0/24"),
                    );

                    ui.label("Mask:");
                    egui::ComboBox::from_label("")
                        .selected_text(&self.selected_mask)
                        .show_ui(ui, |ui| {
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/32".to_string(),
                                    "/32 - 1 host",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/32");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/31".to_string(),
                                    "/31 - 2 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/31");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/30".to_string(),
                                    "/30 - 4 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/30");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/29".to_string(),
                                    "/29 - 8 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/29");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/28".to_string(),
                                    "/28 - 16 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/28");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/27".to_string(),
                                    "/27 - 32 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/27");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/26".to_string(),
                                    "/26 - 64 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/26");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/25".to_string(),
                                    "/25 - 128 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/25");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/24".to_string(),
                                    "/24 - 256 hosts (Class C)",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/24");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/23".to_string(),
                                    "/23 - 512 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/23");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/22".to_string(),
                                    "/22 - 1024 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/22");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/21".to_string(),
                                    "/21 - 2048 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/21");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/20".to_string(),
                                    "/20 - 4096 hosts",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/20");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/16".to_string(),
                                    "/16 - 65536 hosts (Class B)",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/16");
                            }
                            if ui
                                .selectable_value(
                                    &mut self.selected_mask,
                                    "/8".to_string(),
                                    "/8 - 16M hosts (Class A)",
                                )
                                .clicked()
                            {
                                self.update_cidr_mask("/8");
                            }
                        });
                } else {
                    ui.label("IP Range:");
                    ui.add(egui::TextEdit::singleline(&mut self.start_ip).desired_width(120.0));
                    ui.label("to");
                    ui.add(egui::TextEdit::singleline(&mut self.end_ip).desired_width(120.0));
                }

                ui.separator();

                let is_scanning =
                    matches!(*self.scan_state.lock().unwrap(), ScanState::Scanning { .. });

                if is_scanning {
                    if ui.button("⏹ Stop").clicked() {
                        self.stop_scan();
                    }
                } else if ui.button("▶ Start").clicked() {
                    self.start_scan();
                }

                ui.separator();

                if ui.button("⚙ Settings").clicked() {
                    self.show_settings = true;
                }

                ui.separator();

                ui.menu_button("📥 Export", |ui| {
                    if ui.button("CSV").clicked() {
                        self.export_results("csv");
                        ui.close();
                    }
                    if ui.button("JSON").clicked() {
                        self.export_results("json");
                        ui.close();
                    }
                    if ui.button("Text").clicked() {
                        self.export_results("text");
                        ui.close();
                    }
                });
            });

            ui.add_space(5.0);

            ui.horizontal(|ui| {
                ui.label("Ports:");
                ui.add(egui::TextEdit::singleline(&mut self.port_string).desired_width(200.0));

                ui.separator();

                ui.label("Threads:");
                ui.add(egui::Slider::new(&mut self.threads, 1..=500));

                ui.separator();

                ui.label("Timeout (ms):");
                ui.add(egui::Slider::new(&mut self.ping_timeout, 100..=5000));

                ui.separator();

                ui.checkbox(&mut self.scan_dead, "Scan dead hosts");
                ui.checkbox(&mut self.show_dead, "Show dead hosts");
            });

            ui.add_space(5.0);
        });

        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.add_space(5.0);

            ui.horizontal(|ui| {
                let status = self.status_message.lock().unwrap().clone();
                ui.label(status);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let results = self.results.lock().unwrap();
                    let alive = results
                        .iter()
                        .filter(|r| r.status != ResultType::Dead)
                        .count();
                    let with_ports = results
                        .iter()
                        .filter(|r| r.status == ResultType::WithPorts)
                        .count();

                    ui.label(format!("Hosts with ports: {}", with_ports));
                    ui.separator();
                    ui.label(format!("Alive hosts: {}", alive));
                    ui.separator();
                    ui.label(format!("Total scanned: {}", results.len()));
                });
            });

            if let ScanState::Scanning {
                progress,
                current,
                total,
                ..
            } = *self.scan_state.lock().unwrap()
            {
                ui.add(
                    egui::ProgressBar::new(progress)
                        .show_percentage()
                        .text(format!("{}/{} hosts", current, total)),
                );
            }

            ui.add_space(5.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("🔍 Filter:");
                ui.text_edit_singleline(&mut self.filter_text);
                if ui.button("Clear").clicked() {
                    self.filter_text.clear();
                }
            });

            ui.separator();

            let filtered_results: Vec<_> = {
                let results = self.results.lock().unwrap();
                results
                    .iter()
                    .filter(|r| {
                        (self.show_dead || r.status != ResultType::Dead)
                            && (self.filter_text.is_empty()
                                || r.address.contains(&self.filter_text)
                                || r.hostname.contains(&self.filter_text)
                                || r.ports.contains(&self.filter_text))
                    })
                    .cloned()
                    .collect()
            };

            let table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(120.0).at_least(100.0)) // IP
                .column(Column::initial(80.0).at_least(60.0)) // Ping
                .column(Column::initial(200.0).at_least(150.0)) // Hostname
                .column(Column::initial(150.0).at_least(120.0)) // MAC
                .column(Column::remainder()) // Ports
                .header(25.0, |mut header| {
                    header.col(|ui| {
                        let response = ui.add(
                            egui::Label::new(egui::RichText::new("IP Address").strong())
                                .sense(egui::Sense::click()),
                        );

                        if response.hovered() {
                            ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        }

                        if response.clicked() {
                            if self.sort_column == Some(SortColumn::IpAddress) {
                                self.sort_order = match self.sort_order {
                                    SortOrder::Ascending => SortOrder::Descending,
                                    SortOrder::Descending => SortOrder::Ascending,
                                };
                            } else {
                                self.sort_column = Some(SortColumn::IpAddress);
                                self.sort_order = SortOrder::Ascending;
                            }
                            self.sort_results();
                        }
                    });
                    header.col(|ui| {
                        ui.strong("Ping");
                    });
                    header.col(|ui| {
                        ui.strong("Hostname");
                    });
                    header.col(|ui| {
                        ui.strong("MAC Address");
                    });
                    header.col(|ui| {
                        ui.strong("Ports [3+]");
                    });
                });

            table.body(|body| {
                body.rows(22.0, filtered_results.len(), |mut row| {
                    let row_index = row.index();
                    if let Some(result) = filtered_results.get(row_index) {
                        let result = result.clone();

                        let _row_color = match result.status {
                            ResultType::Dead => egui::Color32::from_gray(60),
                            ResultType::Alive => egui::Color32::from_rgb(0, 100, 0),
                            ResultType::WithPorts => egui::Color32::from_rgb(0, 80, 120),
                            ResultType::Unknown => egui::Color32::from_gray(80),
                        };

                        row.col(|ui| {
                            let response = ui.add(
                                egui::Label::new(egui::RichText::new(&result.address).color(
                                    if result.status == ResultType::Dead {
                                        egui::Color32::from_gray(128)
                                    } else {
                                        egui::Color32::from_gray(220)
                                    },
                                ))
                                .sense(egui::Sense::click()),
                            );

                            response.context_menu(|ui| {
                                ui.label(format!("🖥 {}", result.address));
                                ui.separator();

                                if result.ports != "[n/a]" && result.ports != "[n/s]" {
                                    let has_http = result.ports.contains("80")
                                        || result.ports.contains("8080");
                                    let has_https = result.ports.contains("443")
                                        || result.ports.contains("8443");

                                    if (has_http || has_https)
                                        && ui.button("🌐 Open in Browser").clicked()
                                    {
                                        let protocol = if has_https { "https" } else { "http" };
                                        let port = if has_https {
                                            if result.ports.contains("443") {
                                                ""
                                            } else {
                                                ":8443"
                                            }
                                        } else if result.ports.contains("80") {
                                            ""
                                        } else {
                                            ":8080"
                                        };
                                        let url =
                                            format!("{}://{}{}", protocol, result.address, port);
                                        self.open_url(&url);
                                        ui.close();
                                    }

                                    if result.ports.contains("22")
                                        && ui.button("🔐 SSH Connect").clicked()
                                    {
                                        self.execute_terminal_command(&format!(
                                            "ssh {}",
                                            result.address
                                        ));
                                        ui.close();
                                    }

                                    if result.ports.contains("3389")
                                        && ui.button("🖥 RDP Connect").clicked()
                                    {
                                        #[cfg(target_os = "windows")]
                                        {
                                            let _ = Command::new("mstsc")
                                                .arg("/v")
                                                .arg(&result.address)
                                                .spawn();
                                        }
                                        #[cfg(target_os = "linux")]
                                        {
                                            if Command::new("which")
                                                .arg("remmina")
                                                .output()
                                                .map(|o| o.status.success())
                                                .unwrap_or(false)
                                            {
                                                let _ = Command::new("remmina")
                                                    .arg("-c")
                                                    .arg(format!("rdp://{}", result.address))
                                                    .spawn();
                                            } else if Command::new("which")
                                                .arg("xfreerdp")
                                                .output()
                                                .map(|o| o.status.success())
                                                .unwrap_or(false)
                                            {
                                                self.execute_terminal_command(&format!(
                                                    "xfreerdp /v:{}",
                                                    result.address
                                                ));
                                            }
                                        }
                                        #[cfg(target_os = "macos")]
                                        {
                                            let _ = Command::new("open")
                                                .arg(format!(
                                                    "rdp://full%20address=s:{}",
                                                    result.address
                                                ))
                                                .spawn();
                                        }
                                        ui.close();
                                    }

                                    if (result.ports.contains("445")
                                        || result.ports.contains("139"))
                                        && ui.button("📁 SMB Browse").clicked()
                                    {
                                        #[cfg(target_os = "windows")]
                                        {
                                            let _ = Command::new("explorer")
                                                .arg(format!("\\\\{}", result.address))
                                                .spawn();
                                        }
                                        #[cfg(not(target_os = "windows"))]
                                        {
                                            self.open_url(&format!("smb://{}", result.address));
                                        }
                                        ui.close();
                                    }

                                    ui.separator();
                                }

                                if ui.button("📋 Copy IP").clicked() {
                                    ui.ctx().copy_text(result.address.clone());
                                    ui.close();
                                }

                                if ui.button("📋 Copy Hostname").clicked() {
                                    ui.ctx().copy_text(result.hostname.clone());
                                    ui.close();
                                }

                                if result.mac != "[n/a]" && ui.button("📋 Copy MAC").clicked() {
                                    ui.ctx().copy_text(result.mac.clone());
                                    ui.close();
                                }

                                if result.ports != "[n/a]"
                                    && result.ports != "[n/s]"
                                    && ui.button("📋 Copy Ports").clicked()
                                {
                                    ui.ctx().copy_text(result.ports.clone());
                                    ui.close();
                                }

                                ui.separator();

                                if ui.button("🔍 Ping").clicked() {
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.execute_terminal_command(&format!(
                                            "ping -t {}",
                                            result.address
                                        ));
                                    }
                                    #[cfg(not(target_os = "windows"))]
                                    {
                                        self.execute_terminal_command(&format!(
                                            "ping {}",
                                            result.address
                                        ));
                                    }
                                    ui.close();
                                }

                                if ui.button("🛤 Traceroute").clicked() {
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.execute_terminal_command(&format!(
                                            "tracert {}",
                                            result.address
                                        ));
                                    }
                                    #[cfg(target_os = "linux")]
                                    {
                                        if Command::new("which")
                                            .arg("traceroute")
                                            .output()
                                            .map(|o| o.status.success())
                                            .unwrap_or(false)
                                        {
                                            self.execute_terminal_command(&format!(
                                                "traceroute {}",
                                                result.address
                                            ));
                                        } else {
                                            self.execute_terminal_command(&format!(
                                                "tracepath {}",
                                                result.address
                                            ));
                                        }
                                    }
                                    #[cfg(target_os = "macos")]
                                    {
                                        self.execute_terminal_command(&format!(
                                            "traceroute {}",
                                            result.address
                                        ));
                                    }
                                    ui.close();
                                }

                                if ui.button("🔍 Nmap Scan").clicked() {
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.execute_terminal_command(&format!(
                                            "nmap -A {}",
                                            result.address
                                        ));
                                    }
                                    #[cfg(not(target_os = "windows"))]
                                    {
                                        if Command::new("which")
                                            .arg("nmap")
                                            .output()
                                            .map(|o| o.status.success())
                                            .unwrap_or(false)
                                        {
                                            self.execute_terminal_command(&format!(
                                                "nmap -A {}",
                                                result.address
                                            ));
                                        } else {
                                            *self.status_message.lock().unwrap() =
                                                "Nmap is not installed".to_string();
                                        }
                                    }
                                    ui.close();
                                }

                                if ui.button("ℹ Whois").clicked() {
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.open_url(&format!(
                                            "https://www.whois.com/whois/{}",
                                            result.address
                                        ));
                                    }
                                    #[cfg(not(target_os = "windows"))]
                                    {
                                        if Command::new("which")
                                            .arg("whois")
                                            .output()
                                            .map(|o| o.status.success())
                                            .unwrap_or(false)
                                        {
                                            self.execute_terminal_command(&format!(
                                                "whois {}",
                                                result.address
                                            ));
                                        } else {
                                            self.open_url(&format!(
                                                "https://www.whois.com/whois/{}",
                                                result.address
                                            ));
                                        }
                                    }
                                    ui.close();
                                }
                            });
                        });

                        // Ping column with color coding
                        row.col(|ui| {
                            let ping_text = &result.ping;
                            let color = if ping_text == "[n/a]" {
                                egui::Color32::from_gray(128)
                            } else if let Ok(ms) = ping_text.trim_end_matches(" ms").parse::<u32>()
                            {
                                if ms < 50 {
                                    egui::Color32::from_rgb(0, 200, 0) // Green for fast
                                } else if ms < 200 {
                                    egui::Color32::from_rgb(200, 200, 0) // Yellow for medium
                                } else {
                                    egui::Color32::from_rgb(200, 0, 0) // Red for slow
                                }
                            } else {
                                egui::Color32::from_gray(180)
                            };

                            ui.label(egui::RichText::new(ping_text).color(color));
                        });

                        // Hostname column
                        row.col(|ui| {
                            ui.label(egui::RichText::new(&result.hostname).color(
                                if result.hostname == "[n/a]" {
                                    egui::Color32::from_gray(128)
                                } else {
                                    egui::Color32::from_gray(200)
                                },
                            ));
                        });

                        // MAC column
                        row.col(|ui| {
                            ui.label(egui::RichText::new(&result.mac).color(
                                if result.mac == "[n/a]" {
                                    egui::Color32::from_gray(128)
                                } else {
                                    egui::Color32::from_rgb(100, 200, 100) // Green for valid MAC
                                },
                            ));
                        });

                        row.col(|ui| {
                            let ports_text = &result.ports;
                            let color = if ports_text == "[n/a]" || ports_text == "[n/s]" {
                                egui::Color32::from_gray(128)
                            } else {
                                let port_count = ports_text.split(',').count();
                                if port_count >= 3 {
                                    egui::Color32::from_rgb(255, 100, 0) // Orange for many ports
                                } else {
                                    egui::Color32::from_rgb(0, 150, 200) // Blue for few ports
                                }
                            };

                            ui.label(egui::RichText::new(ports_text).color(color));
                        });
                    }
                });
            });
        });

        if matches!(*self.scan_state.lock().unwrap(), ScanState::Scanning { .. }) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    let icon_bytes = include_bytes!("assets/icon.png");
    let icon = eframe::icon_data::from_png_bytes(icon_bytes).expect("Failed to load icon");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("IPScan - Network Scanner")
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        "IPScan",
        options,
        Box::new(|_cc| Ok(Box::new(IpScanApp::default()))),
    )
}
