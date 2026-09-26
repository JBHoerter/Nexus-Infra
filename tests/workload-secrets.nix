{ nixpkgs }:
let
  secretsNode = { pkgs, ... }: {
    imports = [ ../host-modules/workload-secrets.nix ];
    virtualisation.memorySize = 768;
    virtualisation.cores = 1;
    # The escrow needs no network path between the hosts: the blob
    # plus envelope transfer below is plain bytes carried by the
    # test driver.
    virtualisation.restrictNetwork = true;
    services.nexus-workload-secrets = {
      enable = true;
      configurationFile = "/run/secrets-config.json";
    };
  };
in { pkgs, lib, ... }: {
  name = "nexus-workload-secrets";
  nodes = {
    sealhost = secretsNode;
    provisionhost = { pkgs, ... }: {
      imports = [ secretsNode ];
      # age-keygen for the runtime identity; nexus-secrets itself
      # already carries pkgs.age in its wrapper inputs.
      environment.systemPackages = [ pkgs.age ];
    };
  };
  testScript = ''
    import base64
    import hashlib
    import json
    import shlex

    PRIVATE = "/root/secrets-private"
    CONFIG = "/run/secrets-config.json"
    SOURCE = "/root/secret-source"
    REF = "canary-secrets"
    MARKER = "nexus-secrets-vm-marker-0a7c1e"

    def cli(node, request):
        # The CLI verb argument is required; dispatch itself is on
        # the request's action field.
        rc, out = node.execute(
            "printf %s " + shlex.quote(json.dumps(request))
            + " | nexus-secrets " + request["action"])
        assert out.strip(), "empty nexus-secrets response"
        return rc, json.loads(out)

    def expect_blocked(node, request, code):
        rc, resp = cli(node, request)
        assert resp["status"] == "blocked", resp
        assert resp["error"] == code, resp
        return resp

    start_all()
    for node in (sealhost, provisionhost):
        node.wait_for_unit("multi-user.target")

    with subtest("the identity exists only on the provisioning host"):
        provisionhost.succeed("install -d -m 0700 " + PRIVATE)
        provisionhost.succeed(
            "age-keygen -o " + PRIVATE + "/identity")
        provisionhost.succeed("chmod 600 " + PRIVATE + "/identity")
        recipient = provisionhost.succeed(
            "age-keygen -y " + PRIVATE + "/identity").strip()
        assert recipient.startswith("age1"), recipient
        provisionhost.succeed(
            "printf %s " + shlex.quote(json.dumps(
                {"schemaVersion": 1,
                 "keyFile": PRIVATE + "/identity"}))
            + " > " + CONFIG)

    with subtest("the sealing host holds only the public recipient"):
        sealhost.succeed("install -d -m 0700 " + PRIVATE)
        sealhost.succeed(
            "printf '%s\\n' " + shlex.quote(recipient)
            + " > " + PRIVATE + "/recipients")
        sealhost.succeed("chmod 600 " + PRIVATE + "/recipients")
        sealhost.succeed(
            "printf %s " + shlex.quote(json.dumps(
                {"schemaVersion": 1,
                 "keyFile": PRIVATE + "/recipients"}))
            + " > " + CONFIG)

    with subtest("host A seals a private secret directory"):
        sealhost.succeed("install -d -m 0700 " + SOURCE)
        names = ["api-token", "db-password", ".env", "marker"]
        src_hash = {}
        for name in names[:-1]:
            sealhost.succeed(
                "head -c 200 /dev/urandom > " + SOURCE + "/" + name
                + " && chmod 600 " + SOURCE + "/" + name)
            src_hash[name] = sealhost.succeed(
                "sha256sum " + SOURCE + "/" + name).split()[0]
        # One deterministic entry lets the driver prove the sealed
        # blob carries no plaintext without ever printing secrets.
        sealhost.succeed(
            "printf %s " + shlex.quote(MARKER)
            + " > " + SOURCE + "/marker"
            + " && chmod 600 " + SOURCE + "/marker")
        src_hash["marker"] = sealhost.succeed(
            "sha256sum " + SOURCE + "/marker").split()[0]
        rc, resp = cli(sealhost, {
            "schemaVersion": 1, "action": "seal",
            "secretSetRef": REF, "sourceDir": SOURCE,
            "bundleFile": PRIVATE + "/bundle.age"})
        assert resp["status"] == "completed", resp
        envelope = resp["envelope"]
        assert envelope["sealingScheme"] == "age-x25519-v1", envelope
        binding = {key: envelope[key] for key in
                   ("secretSetRef", "versionDigest", "bundleDigest")}
        blob_b64 = sealhost.succeed(
            "base64 -w0 " + PRIVATE + "/bundle.age").strip()
        blob = base64.b64decode(blob_b64)
        assert b"BEGIN AGE ENCRYPTED FILE" in blob, "not an age blob"
        assert MARKER.encode() not in blob, "plaintext leaked"

    with subtest("the sealing host alone can never open the bundle"):
        expect_blocked(sealhost, {
            "schemaVersion": 1, "action": "provision",
            "envelope": envelope,
            "bundleFile": PRIVATE + "/bundle.age",
            "targetDir": "/root/never", "binding": binding},
            "unseal-failed")
        sealhost.fail("test -e /root/never")

    with subtest("host B verifies and provisions the transferred bundle"):
        provisionhost.succeed(
            "printf %s " + shlex.quote(blob_b64)
            + " | base64 -d > " + PRIVATE + "/bundle.age")
        rc, resp = cli(provisionhost, {
            "schemaVersion": 1, "action": "verify",
            "envelope": envelope,
            "bundleFile": PRIVATE + "/bundle.age"})
        assert resp["status"] == "completed", resp
        # A mismatched manifest binding refuses before decryption.
        bad_binding = dict(binding)
        bad_binding["versionDigest"] = "sha256:" + "0" * 64
        expect_blocked(provisionhost, {
            "schemaVersion": 1, "action": "provision",
            "envelope": envelope,
            "bundleFile": PRIVATE + "/bundle.age",
            "targetDir": "/root/bad-binding",
            "binding": bad_binding},
            "bundle-binding-mismatch")
        provisionhost.fail("test -e /root/bad-binding")
        rc, resp = cli(provisionhost, {
            "schemaVersion": 1, "action": "provision",
            "envelope": envelope,
            "bundleFile": PRIVATE + "/bundle.age",
            "targetDir": "/root/provisioned", "binding": binding})
        assert resp["status"] == "completed", resp
        assert resp["fileCount"] == len(names), resp
        assert provisionhost.succeed(
            "stat -c %a /root/provisioned").strip() == "700"
        for name in names:
            digest = provisionhost.succeed(
                "sha256sum /root/provisioned/" + name).split()[0]
            assert digest == src_hash[name], \
                "content mismatch for " + name
            assert provisionhost.succeed(
                "stat -c %a /root/provisioned/" + name
                ).strip() == "600"

    with subtest("tampered and foreign envelopes fail closed"):
        tampered = bytearray(blob)
        tampered[len(tampered) // 2] ^= 0x01
        provisionhost.succeed(
            "printf %s " + shlex.quote(
                base64.b64encode(bytes(tampered)).decode())
            + " | base64 -d > " + PRIVATE + "/tampered.age")
        # Rebind the envelope digest so the AEAD open itself must
        # be the gate that rejects the tampered bytes.
        forged = dict(envelope)
        forged["bundleDigest"] = "sha256:" + hashlib.sha256(
            bytes(tampered)).hexdigest()
        expect_blocked(provisionhost, {
            "schemaVersion": 1, "action": "provision",
            "envelope": forged,
            "bundleFile": PRIVATE + "/tampered.age",
            "targetDir": "/root/tampered-target", "binding": None},
            "unseal-failed")
        provisionhost.fail("test -e /root/tampered-target")
        # A foreign scheme token never reaches the cipher.
        foreign = dict(envelope)
        foreign["sealingScheme"] = "test-only-v1"
        expect_blocked(provisionhost, {
            "schemaVersion": 1, "action": "provision",
            "envelope": foreign,
            "bundleFile": PRIVATE + "/bundle.age",
            "targetDir": "/root/foreign-target", "binding": None},
            "sealing-scheme-unknown")
        provisionhost.fail("test -e /root/foreign-target")
  '';
}
