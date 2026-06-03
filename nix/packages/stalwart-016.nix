{
  lib,
  rustPlatform,
  fetchFromGitHub,
  pkg-config,
  protobuf,
  bzip2,
  openssl,
  sqlite,
  foundationdb,
  zstd,
  stdenv,
  nix-update-script,
  nixosTests,
  rocksdb,
  withFoundationdb ? false,
  stalwartEnterprise ? false,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "stalwart" + (lib.optionalString stalwartEnterprise "-enterprise");
  version = "0.16.7";

  src = fetchFromGitHub {
    owner = "stalwartlabs";
    repo = "stalwart";
    tag = "v${finalAttrs.version}";
    hash = "sha256-wL6cWEv3pc5v833OXbMjZrlbqXcvrCWA4NI1n897CxU=";
  };

  cargoHash = "sha256-2auureALi04NWfa3PhK/7F4yKlTASYCZtPXRDMjuAq0=";

  patches = [];

  depsBuildBuild = [
    pkg-config
    zstd
  ];

  nativeBuildInputs = [
    protobuf
    rustPlatform.bindgenHook
  ];

  buildInputs =
    [
      bzip2
      openssl
      sqlite
      zstd
    ]
    ++ lib.optionals (stdenv.hostPlatform.isLinux && withFoundationdb) [foundationdb];

  nativeCheckInputs = [openssl];

  # Keep feature parity with the nixpkgs 0.16.0 packaging attempt.
  buildNoDefaultFeatures = true;
  buildFeatures =
    [
      "sqlite"
      "postgres"
      "mysql"
      "rocks"
      "s3"
      "redis"
      "azure"
      "nats"
    ]
    ++ lib.optionals withFoundationdb ["foundationdb"]
    ++ lib.optionals stalwartEnterprise ["enterprise"];

  env =
    {
      OPENSSL_NO_VENDOR = true;
      ZSTD_SYS_USE_PKG_CONFIG = true;
      ROCKSDB_INCLUDE_DIR = "${rocksdb}/include";
      ROCKSDB_LIB_DIR = "${rocksdb}/lib";
    }
    // lib.optionalAttrs
    (stdenv.hostPlatform.isLinux && (stdenv.hostPlatform.isAarch64 || stdenv.hostPlatform.isArmv7))
    {
      JEMALLOC_SYS_WITH_LG_PAGE = 16;
    };

  postInstall = ''
    mkdir -p $out/etc/stalwart
    mkdir -p $out/lib/systemd/system
    substitute resources/systemd/stalwart-mail.service $out/lib/systemd/system/stalwart.service \
      --replace-fail "__PATH__" "$out"
  '';

  checkFlags = lib.forEach [
    "directory::imap::imap_directory"
    "directory::internal::internal_directory"
    "directory::ldap::ldap_directory"
    "directory::sql::sql_directory"
    "directory::oidc::oidc_directory"
    "store::blob::blob_tests"
    "store::lookup::lookup_tests"
    "smtp::lookup::sql::lookup_sql"
    "directory::smtp::lmtp_directory"
    "imap::imap_tests"
    "jmap::jmap_tests"
    "smtp::inbound::data::data"
    "smtp::inbound::scripts::sieve_scripts"
    "smtp::outbound::lmtp::lmtp_delivery"
    "smtp::outbound::extensions::extensions"
    "smtp::outbound::smtp::smtp_delivery"
    "smtp::outbound::lmtp::lmtp_delivery"
    "smtp::queue::retry::queue_retry"
    "smtp::queue::virtualq::virtual_queue"
    "store::store_tests"
    "cluster::cluster_tests"
    "webdav::webdav_tests"
    "config::parser::tests::toml_parse"
    "backend::sqlite::pool::SqliteConnectionManager::with_init"
    "smtp::reporting::analyze::report_analyze"
    "smtp::inbound::dmarc::dmarc"
    "smtp::queue::concurrent::concurrent_queue"
    "smtp::inbound::auth::auth"
    "smtp::inbound::antispam::antispam"
    "smtp::inbound::vrfy::vrfy_expn"
    "smtp::management::queue::manage_queue"
    "responses::tests::parse_responses"
    "store::search_tests"
    "automation::automation_tests"
    "cluster::broadcast::cluster_tests"
    "cluster::stress::stress_tests"
    "directory::directory_tests"
    "smtp::inbound::basic::basic_commands"
    "smtp::inbound::ehlo::ehlo"
    "smtp::inbound::limits::limits"
    "smtp::inbound::mail::mail"
    "smtp::inbound::milter::milter_session"
    "smtp::inbound::milter::mta_hook_session"
    "smtp::inbound::rcpt::rcpt"
    "smtp::inbound::rewrite::address_rewrite"
    "smtp::inbound::sign::sign_and_seal"
    "smtp::inbound::throttle::throttle_inbound"
    "smtp::lookup::expressions::expressions"
    "smtp::lookup::utils::strategies"
    "smtp::management::report::manage_reports"
    "smtp::outbound::dane::dane_test"
    "smtp::outbound::dane::dane_verify"
    "smtp::outbound::fallback_relay::fallback_relay"
    "smtp::outbound::ip_lookup::ip_lookup_strategy"
    "smtp::outbound::mta_sts::mta_sts_verify"
    "smtp::outbound::throttle::throttle_outbound"
    "smtp::outbound::tls::starttls_optional"
    "smtp::queue::dsn::generate_dsn"
    "smtp::queue::manager::queue_due"
    "smtp::reporting::dmarc::report_dmarc"
    "smtp::reporting::scheduler::report_scheduler"
    "smtp::reporting::tls::report_tls"
    "system::system_tests"
    "telemetry::telemetry_tests"
  ] (test: "--skip=${test}");

  doCheck = false;
  __darwinAllowLocalNetworking = true;

  passthru = {
    inherit rocksdb;
    updateScript = nix-update-script {};
    tests.stalwart = nixosTests.stalwart;
  };

  meta = {
    description = "Secure, modern, all-in-one mail and collaboration server";
    longDescription = ''
      Secure, scalable and fluent in every protocol (IMAP, JMAP, SMTP, CalDAV, CardDAV, WebDAV).
    '';
    homepage = "https://github.com/stalwartlabs/stalwart";
    changelog = "https://github.com/stalwartlabs/stalwart/blob/main/CHANGELOG.md";
    license =
      [lib.licenses.agpl3Only]
      ++ lib.optionals stalwartEnterprise [
        {
          fullName = "Stalwart Enterprise License 1.0 (SELv1) Agreement";
          url = "https://github.com/stalwartlabs/stalwart/blob/main/LICENSES/LicenseRef-SEL.txt";
          free = false;
          redistributable = false;
        }
      ];
    mainProgram = "stalwart";
    maintainers = with lib.maintainers; [
      happysalada
      onny
      oddlama
      pandapip1
      norpol
    ];
  };
})
