{
  pkgs,
  self,
  ...
}: let
  inherit (pkgs) lib;
  ports = [25 587 993];
  listenerNames = ["smtp" "submission" "imaps"];
  withTrust = value: lib.genAttrs listenerNames (_: {proxyTrustedNetworks = lib.mkForce value;});
  common = address: {
    virtualisation = {
      memorySize = 768;
      interfaces.eth1.vlan = 1;
    };
    networking = {
      useDHCP = false;
      dhcpcd.enable = false;
      networkmanager = {
        enable = true;
        settings.main.no-auto-default = "*";
        ensureProfiles.profiles.fixture = {
          connection = {
            id = "fixture";
            type = "ethernet";
            interface-name = "eth1";
          };
          ipv4 = {
            method = "manual";
            address1 = "${address}/24";
          };
          ipv6.method = "disabled";
        };
      };
      hosts."192.0.2.2" = ["mail.example.test"];
      firewall.allowedTCPPorts = ports;
    };
    environment.systemPackages = [pkgs.python3];
  };
  cred = name: {
    "@type" = "File";
    filePath = "/run/credentials/stalwart.service/${name}";
  };
  migration = pkgs.writeText "stalwart-proxy-fixture.ndjson" (lib.concatMapStrings (op: builtins.toJSON op + "\n") [
    {
      "@type" = "create";
      object = "Domain";
      value.fixture-domain.name = "example.test";
    }
    {
      "@type" = "create";
      object = "Certificate";
      value.fixture = {
        certificate = cred "certificate";
        privateKey = cred "private_key";
      };
    }
    {
      "@type" = "update";
      object = "SystemSettings";
      value = {
        defaultHostname = "mail.example.test";
        defaultDomainId = "#fixture-domain";
        defaultCertificateId = "#fixture";
      };
    }
  ]);
in
  pkgs.testers.nixosTest {
    name = "stalwart016-proxy";
    globalTimeout = 600;
    nodes = {
      mail = {
        virtualisation.memorySize = lib.mkForce 1536;
        services.stalwart016 = {
          enable = true;
          hostname = "mail.example.test";
          datastore.postgresql.passwordFile = "/run/stalwart-proxy-fixture/pg-password";
          recoveryAdmin.passwordFile = "/run/stalwart-proxy-fixture/admin-password";
          credentials = {
            certificate = "/run/stalwart-proxy-fixture/cert.pem";
            private_key = "/run/stalwart-proxy-fixture/key.pem";
          };
          listeners = {
            smtp = {
              bind = ["192.0.2.1:25"];
              protocol = "smtp";
              useTls = true;
            };
            submission = {
              bind = ["192.0.2.1:587"];
              protocol = "smtp";
              useTls = true;
            };
            imaps = {
              bind = ["192.0.2.1:993"];
              protocol = "imap";
              useTls = true;
              tlsImplicit = true;
            };
            https-admin = {
              bind = ["127.0.0.1:8580"];
              protocol = "http";
            };
          };
          provision = {
            migrationApplyFiles = [migration];
            queryObjects = ["NetworkListener"];
            registryConfig = [
              {
                "@type" = "update";
                object = "SystemSettings";
                value.proxyTrustedNetworks = {};
              }
              # Expose the session's parsed client identity in the test greeting.
              {
                "@type" = "update";
                object = "MtaStageConnect";
                value.smtpGreeting."else" = "'mail.example.test fixture-client=' + remote_ip";
              }
              # This fixture is offline; DNS-based sender checks are independent
              # of PROXY parsing and recipient relay authorization.
              {
                "@type" = "update";
                object = "SenderAuth";
                value = lib.genAttrs ["spfEhloVerify" "spfFromVerify" "reverseIpVerify"] (_: {"else" = "disable";});
              }
            ];
          };
        };
        # Kept separate from the listener definitions to exercise module merging.
        imports = [
          self.nixosModules.stalwart016
          (common "192.0.2.1")
          {
            services.stalwart016.listeners = lib.genAttrs listenerNames (_: {proxyTrustedNetworks = ["192.0.2.2/32"];});
          }
        ];
        specialisation = {
          unmanaged.configuration.services.stalwart016.listeners = withTrust null;
          replaced.configuration.services.stalwart016.listeners = withTrust ["192.0.2.3/32"];
          cleared.configuration.services.stalwart016.listeners = withTrust [];
        };
        systemd.services = {
          fixture-secrets = {
            wantedBy = ["multi-user.target"];
            before = ["postgresql-setup.service" "stalwart.service"];
            path = [pkgs.openssl pkgs.coreutils];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
            };
            script = ''
              umask 077
              install -d -m 0750 -g postgres /run/stalwart-proxy-fixture
              openssl rand -hex 32 > /run/stalwart-proxy-fixture/admin-password
              openssl rand -hex 32 > /run/stalwart-proxy-fixture/pg-password
              chown postgres:postgres /run/stalwart-proxy-fixture/pg-password
              openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
                -keyout /run/stalwart-proxy-fixture/ca.key -out /run/stalwart-proxy-fixture/ca.pem \
                -days 1 -subj '/CN=Mail fixture CA' -addext 'basicConstraints=critical,CA:TRUE' \
                -addext 'keyUsage=critical,keyCertSign,cRLSign'
              openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
                -keyout /run/stalwart-proxy-fixture/key.pem -out /run/stalwart-proxy-fixture/request.pem \
                -subj '/CN=mail.example.test' -addext 'subjectAltName=DNS:mail.example.test' \
                -addext 'basicConstraints=critical,CA:FALSE' -addext 'keyUsage=critical,digitalSignature' \
                -addext 'extendedKeyUsage=serverAuth'
              openssl x509 -req -in /run/stalwart-proxy-fixture/request.pem \
                -CA /run/stalwart-proxy-fixture/ca.pem -CAkey /run/stalwart-proxy-fixture/ca.key \
                -CAcreateserial -out /run/stalwart-proxy-fixture/cert.pem -days 1 -copy_extensions copy
            '';
          };
          postgresql-setup = {
            requires = ["fixture-secrets.service"];
            after = ["fixture-secrets.service"];
          };
          stalwart = {
            requires = ["fixture-secrets.service"];
            wants = ["network-online.target"];
            after = ["fixture-secrets.service" "network-online.target"];
          };
        };
      };
      proxy = {
        imports = [(common "192.0.2.2")];
        services.haproxy = {
          enable = true;
          config = ''
            defaults
              mode tcp
              timeout connect 5s
              timeout client 30s
              timeout server 30s
            ${lib.concatMapStringsSep "\n" (port: ''
                listen fixture_${toString port}
                  bind 192.0.2.2:${toString port}
                  server mail 192.0.2.1:${toString port} send-proxy
              '')
              ports}
          '';
        };
        systemd.services.haproxy = {
          wants = ["network-online.target"];
          after = ["network-online.target"];
        };
      };
      client.imports = [(common "192.0.2.3")];
    };
    testScript = ''
      import shlex

      start_all()
      for host in [mail, proxy, client]:
          host.wait_for_unit("multi-user.target", timeout=180)
          host.wait_until_succeeds("ip -o -4 addr show dev eth1 | grep -q '192.0.2.'", timeout=30)
      mail.wait_for_unit("stalwart.service")
      proxy.wait_for_unit("haproxy.service")
      for port in [25, 587, 993]:
          mail.wait_for_open_port(port, timeout=30)
          proxy.wait_for_open_port(port, timeout=30)
      cert = mail.succeed("cat /run/stalwart-proxy-fixture/ca.pem")
      client.succeed("printf %s " + shlex.quote(cert) + " > /run/mail-fixture.pem")
      probe = "python ${./stalwart016-proxy-client.py}"
      client.succeed(probe + " forwarded")
      proxy.succeed(probe + " trusted")
      proxy.succeed(probe + " missing")
      proxy.succeed(probe + " malformed")
      client.succeed(probe + " untrusted")

      base = mail.succeed("readlink -f /run/current-system").strip()
      def activate(name):
          mail.succeed(f"{base}/specialisation/{name}/bin/switch-to-configuration test")
          mail.wait_for_unit("stalwart.service")
          # Type=simple reaches active before Stalwart reopens its listeners.
          # Keep each trust assertion single-shot after bounded readiness.
          for port in [25, 587, 993]:
              mail.wait_for_open_port(port, timeout=30)

      # Null preserves existing registry trust; it must not silently clear it.
      activate("unmanaged")
      client.succeed(probe + " forwarded")
      proxy.succeed(probe + " trusted")
      # Replacing trust removes the previous source, rather than unioning sets.
      activate("replaced")
      proxy.succeed(probe + " untrusted --peer 192.0.2.2")
      client.succeed(probe + " trusted")
      # Empty override inherits the explicitly empty system trust.
      activate("cleared")
      client.succeed(probe + " untrusted")
      proxy.succeed(probe + " untrusted --peer 192.0.2.2")
    '';
  }
