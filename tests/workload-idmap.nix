{ nixpkgs }:
let
  canary = import ./workload-canary.nix { inherit nixpkgs; };
  host = import ./workload-worker-host.nix {
    inherit canary;
    hostId = "host-idmap";
    uuid = "11111111-2222-3333-4444-555555555555";
    slots = [{ id="first"; uidBase=262144;
               hostAddress="192.168.150.1"; localAddress="192.168.150.2"; }];
  };
in { pkgs, ... }: let
  verifyScript = pkgs.writeText "verify-idmap.py" ''
import json, os, stat, struct
from pathlib import Path
raw=Path('/srv/workloads/raw/data'); view=Path('/srv/workloads/view/data'); out=Path('/srv/workloads/translated/data')
def caproot(path):
    value=os.getxattr(path,'security.capability')
    assert len(value)==24, ('unexpected-cap-format',len(value))
    return struct.unpack('<6I',value)[-1]
report={'rawCapRoot':caproot(raw/'cap'),'viewCapRoot':caproot(view/'cap'),'copiedCapRoot':caproot(out/'cap')}
print(json.dumps(report),flush=True)
assert report == {'rawCapRoot':65536,'viewCapRoot':262144,'copiedCapRoot':262144}, report
for wrapper in ('/srv/workloads/raw','/srv/workloads/view','/srv/workloads/translated'):
    w=os.stat(wrapper)
    assert (w.st_uid,w.st_gid)==(0,0), wrapper
    assert stat.S_IMODE(w.st_mode)==0o700, wrapper
for name in ('value','hardlink','cap','suid','new'):
    a=os.stat(raw/name); b=os.stat(view/name); c=os.stat(out/name)
    assert (a.st_uid,a.st_gid)==(65536,65536), name
    assert (b.st_uid,b.st_gid)==(262144,262144), name
    assert (c.st_uid,c.st_gid)==(262144,262144), name
    assert stat.S_IMODE(a.st_mode)==stat.S_IMODE(b.st_mode)==stat.S_IMODE(c.st_mode), name
    assert a.st_mtime_ns==b.st_mtime_ns==c.st_mtime_ns, name
    assert (raw/name).read_bytes()==(out/name).read_bytes(), name
assert os.stat(out/'suid').st_mode & stat.S_ISUID
assert os.stat(out/'value').st_ino==os.stat(out/'hardlink').st_ino
assert os.readlink(out/'link')=='value'
assert (os.lstat(raw/'link').st_uid,os.lstat(raw/'link').st_gid)==(65536,65536)
assert (os.lstat(out/'link').st_uid,os.lstat(out/'link').st_gid)==(262144,262144)
assert os.getxattr(view/'value','system.posix_acl_access')==os.getxattr(out/'value','system.posix_acl_access')
assert os.getxattr(raw/'value','system.posix_acl_access')!=os.getxattr(out/'value','system.posix_acl_access')
assert (out/'value').read_bytes()==b'idmap-content'
assert (out/'new').read_bytes()==b'mapped-write'
  '';
in {
  name = "nexus-workload-idmap";
  globalTimeout = 10 * 60;
  nodes.machine = {
    imports = [ host ];
    virtualisation.restrictNetwork = true;
    environment.systemPackages = [ pkgs.acl pkgs.libcap pkgs.python3 ];
  };
  testScript = ''
    import json
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("mkfs.ext4 -q -U 11111111-2222-3333-4444-555555555555 /dev/vdc")
    machine.succeed("mkdir -p /srv/workloads && mount /dev/vdc /srv/workloads")
    machine.succeed("mkdir /srv/workloads/raw /srv/workloads/view /srv/workloads/translated")
    machine.succeed("mkdir /srv/workloads/raw/data")
    machine.succeed("printf '%s' idmap-content > /srv/workloads/raw/data/value")
    machine.succeed("cp ${pkgs.coreutils}/bin/true /srv/workloads/raw/data/cap")
    machine.succeed("cp ${pkgs.coreutils}/bin/true /srv/workloads/raw/data/suid")
    machine.succeed("ln /srv/workloads/raw/data/value /srv/workloads/raw/data/hardlink && ln -s value /srv/workloads/raw/data/link")
    machine.succeed("chmod 0700 /srv/workloads/raw /srv/workloads/raw/data && chown -R 65536:65536 /srv/workloads/raw/data && chmod 04755 /srv/workloads/raw/data/suid")
    machine.succeed("setfacl -m u:65543:r-- /srv/workloads/raw/data/value")
    machine.succeed("setcap -n 65536 cap_net_bind_service=ep /srv/workloads/raw/data/cap")
    for index, mapping in enumerate(("b:262144:65536:65536", "b:65536:262144:65536")):
        mount_rc = machine.execute("mount --bind -o 'X-mount.idmap={}' /srv/workloads/raw/data /srv/workloads/view".format(mapping))[0]
        if mount_rc != 0:
            print(json.dumps({"mapping": mapping, "mountRc": mount_rc}), flush=True)
            continue
        root_rc, root_stat = machine.execute("stat -c '%u:%g' /srv/workloads/view")
        file_rc, file_stat = machine.execute("stat -c '%u:%g' /srv/workloads/view/value")
        print(json.dumps({"mapping": mapping, "mountRc": mount_rc, "rootRc": root_rc, "rootStat": root_stat.strip(), "fileRc": file_rc, "fileStat": file_stat.strip()}), flush=True)
        if index == 1:
            assert file_rc == 0, file_stat
            assert file_stat.strip() == "262144:262144", file_stat
            machine.succeed("setpriv --reuid=262144 --regid=262144 --clear-groups sh -c 'printf mapped-write > /srv/workloads/view/new'")
            assert machine.succeed("stat -c '%u:%g' /srv/workloads/raw/data/new").strip() == "65536:65536"
        machine.succeed("umount /srv/workloads/view")
    machine.succeed("mount --bind -o 'X-mount.idmap=b:0:0:1 b:65536:262144:65536' /srv/workloads/raw /srv/workloads/view")
    assert machine.succeed("stat -c '%u:%g' /srv/workloads/view").strip() == "0:0"
    assert machine.succeed("stat -c '%u:%g' /srv/workloads/view/data").strip() == "262144:262144"
    machine.succeed("mount -o remount,bind,ro /srv/workloads/view")
    machine.fail("touch /srv/workloads/view/data/must-not-write")
    machine.succeed("cp --archive --reflink=auto --no-target-directory /srv/workloads/view /srv/workloads/translated")
    machine.succeed("sync -f /srv/workloads/translated")
    # Run exact verifier below via pkgs.writeText or stdin;
    # script emits only synthetic metadata then raises on anyloss.
    machine.succeed("python3 ${verifyScript}")
    facl = machine.succeed("getfacl -cn /srv/workloads/translated/data/value")
    assert "user:262151:r--" in facl, facl
    raw_acl = machine.succeed("getfacl -cn /srv/workloads/raw/data/value")
    assert "user:65543:r--" in raw_acl, raw_acl
    machine.succeed("umount /srv/workloads/view")
    assert machine.succeed("stat -c '%u:%g' /srv/workloads/raw/data/value").strip() == "65536:65536"
  '';
}
