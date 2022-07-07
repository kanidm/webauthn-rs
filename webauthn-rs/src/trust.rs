struct CaPolicy {
    /// None means allow all. Some means only allow this list.
    dev_list: Option<Vec<DeviceIdentity>>,
}

pub struct AttestationPolicy {
    cas: Vec<AttestationCa>,
    pol_map: BTreeMap<CaIdentity, CaPolicy>,
}

pub struct AttestationPolicyBuilder {}

impl AttestationPolicyBuilder {
    pub fn new() -> Self {}

    pub fn finish(self) -> AttestationPolicy {}

    pub fn trust_ca_all_devices(self) -> Self {}

    pub fn trust_ca_device_list(self, devices: Vec<DeviceIdentity>) -> Self {}
}
