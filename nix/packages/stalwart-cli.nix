{
  lib,
  rustPlatform,
  fetchFromGitHub,
  openssl,
  pkg-config,
  versionCheckHook,
  nix-update-script,
}:
rustPlatform.buildRustPackage {
  pname = "stalwart-cli";
  version = "1.0.8";

  src = fetchFromGitHub {
    owner = "stalwartlabs";
    repo = "cli";
    tag = "v1.0.8";
    hash = "sha256-teQB+6ZPEH3RXxG8WX4L67ckLCTYfMF4xaiz3S074b0=";
  };

  cargoHash = "sha256-yMfWFTXV1gXPqo2OOAN/Fkym9UiHjXDX0tAJOCF2p4U=";

  nativeBuildInputs = [pkg-config];
  buildInputs = [openssl];

  env.OPENSSL_NO_VENDOR = true;

  # These snapshot tests build a reqwest HTTPS client and fail inside the Nix
  # sandbox with "No CA certificates were loaded from the system" because there
  # is no system trust store. They are environmental failures, not regressions.
  checkFlags = [
    "--skip=commands::snapshot::tests::emit_create_flushes_sink_around_reporter_calls"
    "--skip=commands::snapshot::tests::emit_create_flushes_sink_on_empty_shard"
    "--skip=commands::snapshot::tests::emit_create_omits_deferred_field_and_emits_followup_update"
    "--skip=commands::snapshot::tests::snapshot_emits_marker_only_variant_as_type_only_record"
  ];

  doInstallCheck = true;
  nativeInstallCheckInputs = [versionCheckHook];

  passthru.updateScript = nix-update-script {};

  meta = {
    description = "Stalwart Mail Server CLI";
    homepage = "https://github.com/stalwartlabs/cli";
    changelog = "https://github.com/stalwartlabs/cli/blob/main/CHANGELOG.md";
    license = lib.licenses.agpl3Only;
    mainProgram = "stalwart-cli";
    maintainers = with lib.maintainers; [giomf];
  };
}
