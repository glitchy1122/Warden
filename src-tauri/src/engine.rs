use crate::bloom::{BloomFilter, EMBEDDED_BLOOM};
use crate::db::{CustomDomain, Db};
use crate::dns::{BlockEvent, DnsProxy};
use crate::ip_block;
use crate::lookup::{LookupEngine, LookupResult};
use crate::vpn_guard::VpnGuard;
use crate::wfp::{self, WfpGuard};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::sync::Arc;
use tauri::AppHandle;
use tauri::Manager;

pub struct AppState {
    pub db: Arc<Db>,
    pub engine: Arc<LookupEngine>,
    pub dns: Arc<DnsProxy>,
    pub wfp: Mutex<WfpGuard>,
    pub vpn_guard: VpnGuard,
    pub protection_enabled: RwLock<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub protection_enabled: bool,
    pub wfp_active: bool,
    pub dns_proxy_active: bool,
    pub bloom_domains: u64,
    pub custom_domains: u64,
    pub blocked_total: u64,
    pub allowed_total: u64,
    pub recent_blocks: Vec<BlockEvent>,
    pub admin_required_hint: String,
}

impl AppState {
    pub fn initialize(app: &AppHandle) -> Result<Self, String> {
        let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
        let db_path = data_dir.join("warden.sqlite3");

        let db = Arc::new(Db::open(&db_path)?);
        let bloom = BloomFilter::from_embedded(EMBEDDED_BLOOM)?;
        let engine = Arc::new(LookupEngine::new(db.clone(), bloom));
        let dns = Arc::new(DnsProxy::new());
        let wfp = Mutex::new(WfpGuard::new());

        Ok(Self {
            db,
            engine,
            dns,
            wfp,
            vpn_guard: VpnGuard::new(),
            protection_enabled: RwLock::new(false),
        })
    }

    fn sync_custom_ip_firewall(&self) {
        let Ok(list) = self.db.list_custom() else {
            return;
        };
        let ips: Vec<String> = list
            .into_iter()
            .map(|e| e.domain)
            .filter(|d| ip_block::is_ipv4(d))
            .collect();
        ip_block::sync_ip_blocks(&ips);
    }

    pub fn status(&self) -> Result<EngineStatus, String> {
        let custom_domains = self.db.custom_count()?;
        Ok(EngineStatus {
            protection_enabled: *self.protection_enabled.read(),
            wfp_active: false,
            dns_proxy_active: self.dns.is_running(),
            bloom_domains: self.engine.bloom_domain_count(),
            custom_domains,
            blocked_total: self.dns.blocked_total(),
            allowed_total: self.dns.allowed_total(),
            recent_blocks: self.dns.recent_blocks(),
            admin_required_hint: "Domains block via DNS. Raw IPs (e.g. https://1.2.3.4/) block via Windows Firewall — DNS cannot see IP URLs."
                .into(),
        })
    }

    pub fn enable_protection(&self) -> Result<EngineStatus, String> {
        self.wfp.lock().stop();

        if let Err(error) = self.dns.start(self.engine.clone()) {
            return Err(error);
        }

        if let Err(error) = self.dns.smoke_test_upstream() {
            self.dns.stop();
            return Err(format!(
                "Cannot reach 1.1.1.1 / 8.8.8.8 from Warden ({error}). NIC DNS was not changed."
            ));
        }

        match wfp::apply_local_dns() {
            Ok(backup) => {
                let _ = self.db.set_setting("dns_backup", &backup);
            }
            Err(error) => {
                self.dns.stop();
                *self.protection_enabled.write() = false;
                return Err(format!("Could not switch adapter DNS to Warden: {error}"));
            }
        }

        // Custom IPv4 entries → firewall (browsers never DNS-query raw IPs).
        self.sync_custom_ip_firewall();

        if let Err(error) = self.vpn_guard.start() {
            eprintln!("Warden VPN guard start warning: {error}");
        }

        *self.protection_enabled.write() = true;
        let _ = self.db.set_setting("protection_enabled", "1");
        self.status()
    }

    pub fn disable_protection(&self) -> Result<EngineStatus, String> {
        self.vpn_guard.stop();
        ip_block::clear_all_ip_blocks();
        if let Ok(Some(backup)) = self.db.get_setting("dns_backup") {
            let _ = wfp::restore_dns(&backup);
        }
        self.wfp.lock().stop();
        self.dns.stop();
        *self.protection_enabled.write() = false;
        let _ = self.db.set_setting("protection_enabled", "0");
        self.status()
    }
}

#[tauri::command]
pub fn get_status(state: tauri::State<'_, AppState>) -> Result<EngineStatus, String> {
    state.status()
}

#[tauri::command]
pub fn set_protection(
    enabled: bool,
    state: tauri::State<'_, AppState>,
) -> Result<EngineStatus, String> {
    if enabled {
        state.enable_protection()
    } else {
        state.disable_protection()
    }
}

#[tauri::command]
pub fn list_custom_domains(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<CustomDomain>, String> {
    state.db.list_custom()
}

#[tauri::command]
pub fn add_custom_domain(
    domain: String,
    state: tauri::State<'_, AppState>,
) -> Result<CustomDomain, String> {
    let normalized = LookupEngine::normalize_input(&domain)?;
    let entry = state.db.add_custom(&normalized)?;
    if *state.protection_enabled.read() && ip_block::is_ipv4(&normalized) {
        let _ = ip_block::block_ipv4(&normalized);
    }
    Ok(entry)
}

#[tauri::command]
pub fn remove_custom_domain(id: i64, state: tauri::State<'_, AppState>) -> Result<(), String> {
    // Need domain before delete for firewall cleanup.
    let list = state.db.list_custom()?;
    let domain = list
        .into_iter()
        .find(|e| e.id == id)
        .map(|e| e.domain);
    state.db.remove_custom(id)?;
    if let Some(d) = domain {
        if ip_block::is_ipv4(&d) {
            let _ = ip_block::unblock_ipv4(&d);
        }
    }
    Ok(())
}

#[tauri::command]
pub fn check_domain(
    domain: String,
    state: tauri::State<'_, AppState>,
) -> Result<LookupResult, String> {
    Ok(state.engine.lookup(&domain))
}
