use crate::errors::*;
use caps::{CapSet, Capability};

pub fn init() -> Result<()> {
    debug!("Permanently clearing capability sets");

    for set in [CapSet::Effective, CapSet::Permitted] {
        let mut caps = caps::read(None, set)
            .with_context(|| anyhow!("Failed to read capability set ({set:?})"))?;
        caps.remove(&Capability::CAP_DAC_READ_SEARCH);
        caps::set(None, set, &caps)
            .with_context(|| anyhow!("Failed to apply capability set ({set:?})"))?;
    }

    debug!("Sandbox has been setup successfully");

    Ok(())
}
