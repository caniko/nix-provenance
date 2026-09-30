{
  pkgs,
  self,
}: let
  evaluate = extra:
    import "${pkgs.path}/nixos/lib/eval-config.nix" {
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = {inherit self;};
      modules = [./stalwart016-eval.nix extra];
    };
  unmanaged = evaluate {};
  withTrust = proxyTrustedNetworks:
    evaluate {
      services.stalwart016.listeners =
        unmanaged.config.services.stalwart016.listeners
        // {
          smtp = unmanaged.config.services.stalwart016.listeners.smtp // {inherit proxyTrustedNetworks;};
        };
    };
  trusted = withTrust ["10.77.0.1/32" "2001:db8::1/128"];
  cleared = withTrust [];
  plan = evaluation: evaluation.config.environment.etc."stalwart016/apply.ndjson".source;
  invalid = value: let
    evaluation = withTrust [value];
  in
    !(builtins.tryEval (builtins.deepSeq evaluation.config.services.stalwart016.listeners.smtp.proxyTrustedNetworks true)).success;
in
  assert builtins.all invalid ["999.1.1.1/32" "10.77.0.1/33" "2001:::1" "2001:db8::1/129" "proxy.example.test" "10.0.0.1/24/1"];
    pkgs.runCommand "stalwart016-proxy-eval" {nativeBuildInputs = [pkgs.jq];} ''
      jq -e 'select(.object == "NetworkListener") | .value.smtp | has("overrideProxyTrustedNetworks") | not' ${plan unmanaged}
      jq -e 'select(.object == "NetworkListener") | .value.smtp.overrideProxyTrustedNetworks == {"10.77.0.1/32":true,"2001:db8::1/128":true}' ${plan trusted}
      jq -e 'select(.object == "NetworkListener") | .value.smtp | has("overrideProxyTrustedNetworks") and .overrideProxyTrustedNetworks == {}' ${plan cleared}
      # Configuring one listener must not broaden trust on another listener.
      jq -e 'select(.object == "NetworkListener") | .value.imaps | has("overrideProxyTrustedNetworks") | not' ${plan trusted}
      touch "$out"
    ''
