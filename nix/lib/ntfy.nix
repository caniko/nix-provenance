{lib}: let
  tokenPattern = "^tk_[A-Za-z0-9]{29}$";
in {
  inherit tokenPattern;

  # Shell that reads plaintext from runtime files and writes ntfy's
  # NTFY_AUTH_USERS / NTFY_AUTH_TOKENS env file to `out`. Nothing here sees a
  # secret at eval time. users: [{name, role, file}]; tokens: [{user, file, label}].
  # ponytail: hashes are recomputed (fresh salt) on every start; fine for a
  # handful of users, cache by password digest if that ever grows.
  mkEnvScript = {
    ntfy,
    out,
    users,
    tokens,
  }: let
    q = lib.escapeShellArg;
  in ''
    set -eu
    umask 077
    hash() {
      printf '%s\n%s\n' "$1" "$1" | ${q "${ntfy}/bin/ntfy"} user hash | tr -d '\r' \
        | grep -o '\$2[aby]\$[^[:space:]]*' | tail -n1
    }
    users="" tokens=""
    ${lib.concatMapStrings (u: ''
        pw="$(tr -d '\n' < ${q u.file})"
        [ -n "$pw" ] || { echo ${q "ntfy: empty password file for ${u.name}"} >&2; exit 1; }
        h="$(hash "$pw")"
        [ -n "$h" ] || { echo ${q "ntfy: could not hash password for ${u.name}"} >&2; exit 1; }
        users="$users''${users:+,}"${q "${u.name}:"}"$h"${q ":${u.role}"}
      '')
      users}
    ${lib.concatMapStrings (t: ''
        tk="$(tr -d '\n' < ${q t.file})"
        [ -n "$tk" ] || { echo ${q "ntfy: empty token file for ${t.user}"} >&2; exit 1; }
        printf '%s' "$tk" | grep -Eq ${q tokenPattern} \
          || { echo ${q "ntfy: token for ${t.user} must match ${tokenPattern}"} >&2; exit 1; }
        tokens="$tokens''${tokens:+,}"${q "${t.user}:"}"$tk"${lib.optionalString (t.label != null) (q ":${t.label}")}
      '')
      tokens}
    {
      printf 'NTFY_AUTH_USERS=%s\n' "$users"
      printf 'NTFY_AUTH_TOKENS=%s\n' "$tokens"
      # an operator environmentFile must not reopen anonymous access
      printf 'NTFY_AUTH_DEFAULT_ACCESS=deny-all\n'
    } > ${q out}.tmp
    mv ${q out}.tmp ${q out}
  '';
}
