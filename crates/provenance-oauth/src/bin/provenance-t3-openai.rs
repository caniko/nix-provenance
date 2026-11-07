//! T3 executes this inside the session owner's runner, never the shared server.
use std::{os::unix::process::CommandExt, path::PathBuf, process::Command};

fn main() {
    if std::env::var_os("T3CODE_OPENAI_OAUTH_COMMAND").is_none()
        && std::env::var_os("T3CODE_OPENAI_OAUTH_CONFIG_FILE").is_none()
    {
        // No enrollment leaves the owner's existing native Codex login alone.
        println!("null");
        return;
    }
    let path = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let (Some(command), Some(config)) = (
        path("T3CODE_OPENAI_OAUTH_COMMAND"),
        path("T3CODE_OPENAI_OAUTH_CONFIG_FILE"),
    ) else {
        eprintln!("provenance-t3-openai: this runner has no explicit OpenAI credential binding");
        std::process::exit(1);
    };
    let _error = Command::new(command)
        .arg("--config")
        .arg(config)
        .arg("access")
        .exec();
    eprintln!("provenance-t3-openai: could not start the bound OAuth helper");
    std::process::exit(1);
}
