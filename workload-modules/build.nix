{ nixpkgs }:
{ system ? "x86_64-linux", definition, modules ? [ ], specialArgs ? { } }:
let
  pkgs = import nixpkgs { inherit system; };
  inherit (definition) workloadId;
in
  if definition.architecture != system then
    throw "workload architecture does not match requested system"
  else if definition.runtimeVersion != "nspawn-v1" then
    throw "unsupported workload runtimeVersion"
  else if definition.category == "archive" then
    throw "archive definitions are not executable workloads"
  else if builtins.match "[a-z][a-z0-9-]{0,62}" workloadId == null then
    throw "invalid workloadId"
  else if definition ? revisionDigest then
    throw "draft must not carry revisionDigest"
  else if builtins.any (artifact: (artifact.id or null) == definition.runtimeArtifactId) definition.artifacts then
    throw "runtime artifact already declared in draft"
  else
    let
      workloadSystem = nixpkgs.lib.nixosSystem {
        inherit system specialArgs;
        modules = [
          ./base.nix
          { networking.hostName = workloadId; }
        ] ++ modules;
      };
      bundle = pkgs.stdenvNoCC.mkDerivation {
        name = "nexus-workload-${workloadId}";
        __structuredAttrs = true;
        exportReferencesGraph.closure = [ workloadSystem.config.system.build.toplevel ];
        nativeBuildInputs = [ pkgs.python3 ];
        buildCommand = ''
          mkdir "''${outputs[out]}"
          ${pkgs.python3}/bin/python ${../console}/artifacts.py build \
            --graph "$NIX_ATTRS_JSON_FILE" \
            --root ${workloadSystem.config.system.build.toplevel} \
            --architecture ${system} \
            --definition ${pkgs.writeText "workload-draft.json" (builtins.toJSON definition)} \
            --output "''${outputs[out]}"
        '';
      };
      resolved = workloadSystem.config;
      invariants = [
        [ resolved.boot.isNspawnContainer "resolved profile must remain an nspawn container" ]
        [ (!resolved.nix.enable) "resolved profile must keep nix disabled" ]
        [ (!resolved.networking.useDHCP) "resolved profile must keep DHCP disabled" ]
        [ (!resolved.networking.useHostResolvConf) "resolved profile must keep host resolv.conf disabled" ]
        [ (resolved.networking.hostName == workloadId) "resolved hostname must equal workloadId" ]
        [ (workloadSystem.pkgs.stdenv.hostPlatform.system == system) "resolved system platform mismatch" ]
      ];
    in
      assert builtins.all (check: pkgs.lib.assertMsg (builtins.head check) (builtins.elemAt check 1)) invariants;
      {
        system = workloadSystem;
        inherit bundle;
      }
