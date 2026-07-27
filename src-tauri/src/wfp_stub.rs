//! Non-Windows stub.



#![cfg(not(windows))]



pub const DOH_HOSTS: &[&str] = &[];



pub struct WfpGuard;



impl WfpGuard {

    pub fn new() -> Self {

        Self

    }



    pub fn is_active(&self) -> bool {

        false

    }



    pub fn start(&mut self) -> Result<(), String> {

        Err("Warden Phase 2 WFP blocking is Windows-only".into())

    }



    pub fn stop(&mut self) {}

}



pub fn apply_local_dns() -> Result<String, String> {

    Err("Windows only".into())

}



pub fn restore_dns(_backup_json: &str) -> Result<(), String> {

    Ok(())

}


