//! Establish protection before any credential is read, prompted for, or decoded.
use super::{Failure, Result};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
use std::time::Duration;

pub(super) struct Protection {
    // logind keeps sleep/hibernation blocked until this descriptor is closed.
    _sleep: dbus::arg::OwnedFd,
}

impl Protection {
    pub(super) fn acquire() -> Result<Self> {
        // Linux makes procfs control files root-owned after PR_SET_DUMPABLE=0.
        // Set the inheritable filter before disabling dumpability.
        std::fs::write("/proc/self/coredump_filter", "0\n").map_err(|_| {
            Failure::permanent("Cannot exclude credential-helper memory from dumps")
        })?;
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: prctl takes integer arguments and setrlimit reads this valid
        // stack rlimit. Neither call retains a pointer.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        {
            return Err(Failure::permanent(
                "Cannot protect credential-process dumps",
            ));
        }
        let connection = Connection::new_system().map_err(|_| {
            Failure::permanent("Cannot contact logind for credential sleep protection")
        })?;
        let manager = connection.with_proxy(
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            Duration::from_secs(3),
        );
        let (sleep,): (dbus::arg::OwnedFd,) = manager
            .method_call(
                "org.freedesktop.login1.Manager",
                "Inhibit",
                (
                    "sleep",
                    "proton-vpn-auth",
                    "Protect transient account credentials",
                    "block",
                ),
            )
            .map_err(|_| Failure::permanent("Cannot inhibit sleep while handling credentials"))?;
        if manager
            .get::<bool>("org.freedesktop.login1.Manager", "PreparingForSleep")
            .map_err(|_| Failure::permanent("Cannot check the credential sleep transition"))?
        {
            return Err(Failure::permanent(
                "Cannot handle credentials during a sleep transition",
            ));
        }
        // Protect writable mappings (heap, stack, TLS and parser/crypto scratch)
        // and all future allocations. Immutable executable/library pages cannot
        // contain runtime secrets and need not consume the memlock allowance.
        // Locks disappear across exec: no plaintext is handed to a decryptor
        // subprocess. Production supplies the normal bounded 8 MiB memlock limit.
        // SAFETY: mlockall accepts only flags and retains no caller pointer.
        if unsafe { libc::mlockall(libc::MCL_FUTURE | libc::MCL_ONFAULT) } != 0 {
            return Err(Failure::permanent(
                "Cannot lock credential memory; increase the process memlock limit before retrying",
            ));
        }
        let maps = std::fs::read_to_string("/proc/self/maps")
            .map_err(|_| Failure::permanent("Cannot inspect credential memory mappings"))?;
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let range = fields.next().unwrap_or_default();
            if !fields.next().unwrap_or_default().contains('w') {
                continue;
            }
            let (start, end) = range
                .split_once('-')
                .ok_or_else(|| Failure::permanent("Invalid credential memory mapping"))?;
            let start = usize::from_str_radix(start, 16)
                .map_err(|_| Failure::permanent("Invalid credential memory mapping"))?;
            let end = usize::from_str_radix(end, 16)
                .map_err(|_| Failure::permanent("Invalid credential memory mapping"))?;
            let length = end
                .checked_sub(start)
                .ok_or_else(|| Failure::permanent("Invalid credential memory mapping"))?;
            // SAFETY: this range is an existing writable mapping reported by
            // the kernel. Startup is single-threaded; mlock retains no pointer.
            if unsafe { libc::mlock(start as *const libc::c_void, length) } != 0 {
                return Err(Failure::permanent(
                    "Cannot lock credential memory; increase the process memlock limit before retrying",
                ));
            }
        }
        Ok(Self { _sleep: sleep })
    }
}
