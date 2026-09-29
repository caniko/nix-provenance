use age::{NoCallbacks, Recipient, plugin, ssh, x25519};
use anyhow::{Context, Result, bail, ensure};
use std::io::Write;

fn recipients(values: &[String]) -> Result<Vec<Box<dyn Recipient + Send>>> {
    // age's plugin protocol trace includes the file key, which would make a
    // logged checkpoint decryptable. Reject an inherited debug setting.
    ensure!(
        std::env::var_os("AGEDEBUG").as_deref() != Some(std::ffi::OsStr::new("plugin")),
        "AGEDEBUG=plugin is not supported for OAuth credentials"
    );
    ensure!(
        !values.is_empty(),
        "at least one recovery age recipient is required"
    );
    values
        .iter()
        .map(|value| {
            if let Ok(recipient) = value.parse::<x25519::Recipient>() {
                return Ok(Box::new(recipient) as Box<dyn Recipient + Send>);
            }
            if let Ok(recipient) = value.parse::<ssh::Recipient>() {
                return Ok(Box::new(recipient) as Box<dyn Recipient + Send>);
            }
            if let Ok(recipient) = value.parse::<plugin::Recipient>() {
                let encryptor = plugin::RecipientPluginV1::new(
                    recipient.plugin(),
                    std::slice::from_ref(&recipient),
                    &[],
                    NoCallbacks,
                )
                .context(
                    "recovery age plugin unavailable; install the declared recovery plugin package",
                )?;
                return Ok(Box::new(encryptor) as Box<dyn Recipient + Send>);
            }
            bail!("unsupported recovery recipient; use an age X25519, SSH or plugin public key")
        })
        .collect()
}

pub fn validate_recipients(values: &[String]) -> Result<()> {
    recipients(values).map(|_| ())
}

pub fn encrypt(plaintext: &[u8], values: &[String]) -> Result<Vec<u8>> {
    let recipients = recipients(values)?;
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn Recipient))
            .context("cannot create recovery encryptor")?;
    let mut output = Vec::new();
    let mut writer = encryptor.wrap_output(&mut output)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(output)
}
