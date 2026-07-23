{ identityJson }:
let
  nixpkgsPath = <nixpkgs>;
  buildSystem = (
    configuration: import (nixpkgsPath + /nixos/lib/eval-config.nix) { modules = [ configuration ]; }
  );
  fsLabel = "rootfs";
in
buildSystem (
  { config, ... }:
  {
    imports = [
      (nixpkgsPath + /nixos/modules/profiles/all-hardware.nix)
      ../software/volumesetup/source/module.nix
      (
        { pkgs, lib, ... }:
        {
          config = {
            nixpkgs.config.allowUnfree = true;

            # Linux
            nixpkgs.localSystem.system = "x86_64-linux";
            boot.kernelParams = [
              "nomodeset"
              "console=tty0"
              "console=ttyS0,38400n8d"
            ];
            boot.kernel.sysctl = {
              "net.ipv6.bindv6only" = true;
            };
            boot.consoleLogLevel = lib.mkDefault 7;
            systemd.targets.getty = {
              enable = false;
            };
            services.logind = {
              extraConfig = lib.strings.concatStringsSep "\n" [
                "NAutoVTs=0"
                "ReserveVT=0"
              ];
            };
            services.journald = {
              console = "/dev/console";
              extraConfig = lib.strings.concatStringsSep "\n" [
                "Storage=volatile"
                "RuntimeMaxSize=100M"
              ];
            };
            users = {
              users = {
                root = {
                  hashedPassword = "!";
                };
              };
            };

            # Boot, filesystems
            boot.loader.grub.device = "/dev/vda";
            fileSystems = lib.mkForce {
              "/" = {
                fsType = "tmpfs";
                options = [
                  "rw"
                  "inode64"
                ];
                neededForBoot = true;
              };
              "/image" = {
                device = "/dev/disk/by-label/${fsLabel}";
                fsType = "ext4";
                options = [ "ro" ];
                neededForBoot = true;
              };
              "/nix" = {
                device = "/image/nix";
                fsType = "bind";
                options = [ "bind" ];
                neededForBoot = true;
              };
            };
            systemd.targets.local-fs = {
              unitConfig = {
                OnFailure = "";
              };
            };

            # Network
            networking.hostName = "nixcloudvm";
            networking.firewall.enable = false;

            # Format persistent
            volumesetup.enable = true;

            # Spagh
            systemd.services.spagh = {
              description = "spagh";
              wantedBy = [ "multi-user.target" ];
              requires = [ "volumesetup.service" ];
              after = [ "volumesetup.service" ];
              serviceConfig.Type = "simple";
              startLimitIntervalSec = 0;
              serviceConfig.Restart = "always";
              serviceConfig.RestartSec = "60";
              serviceConfig.ExecStart =
                let
                  identity = pkgs.writeText "identity" identityJson;
                  code = (import ../../package.nix) { pkgs = pkgs; };
                  persistent_dir = "${config.volumesetup.mountpoint}";
                  data_dir = "${persistent_dir}/data";
                  cache_dir = "${persistent_dir}/cache";
                  self_ip_lookup = "https://3takozni27cd7mpmql5qlfkcze0zillb.lambda-url.us-east-1.on.aws/";
                  spagh_config = pkgs.writeTextFile {
                    name = "spagh-config";
                    text = builtins.toJSON {
                      persistent_dir = data_dir;
                      cache_dir = cache_dir;
                      node = {
                        bind_addr = "[::]:48390";
                        bootstrap = [ ];
                      };
                      api = {
                        bind_addrs = [
                          "[::]:443"
                          "0:443"
                        ];
                      };
                      identity = {
                        local = identity;
                      };
                      global_addrs = [
                        {
                          lookup = {
                            lookup = self_ip_lookup;
                            contact_ip_ver = "v6";
                          };
                        }
                        {
                          lookup = {
                            lookup = self_ip_lookup;
                            contact_ip_ver = "v4";
                          };
                        }
                      ];
                      enable_resolver_rest = true;
                    };
                    checkPhase = ''
                      ${code}/bin/spagh demon --config $out --validate
                    '';
                  };
                in
                pkgs.writeShellScript "start" ''
                  set -xeu -o pipefail
                  ${pkgs.coreutils}/bin/ls /mnt/persistent
                  ${pkgs.coreutils}/bin/cat ${spagh_config}
                  # Temp, wipe persisted data
                  #rm -f ${config.volumesetup.mountpoint}/node.sqlite3
                  #rm -f ${config.volumesetup.mountpoint}/self_tls.sqlite3
                  #rm -f ${config.volumesetup.mountpoint}/resolver.sqlite3
                  exec ${code}/bin/spagh demon --config ${spagh_config} --debug node
                '';
            };

            /*
              systemd.timers.dbg = {
                wantedBy = [ "timers.target" ];
                timerConfig = {
                  OnBootSec = "5m";
                  OnUnitActiveSec = "5m";
                  Unit = "dbg.service";
                };
              };
              systemd.services.dbg = {
                script = ''
                  set -eux
                  ${pkgs.iproute2}/bin/ss --listening --tcp --numeric
                '';
                serviceConfig = {
                  Type = "oneshot";
                };
              };
            */
          };
        }
      )
      (
        {
          config,
          pkgs,
          lib,
          ...
        }:
        {
          config.system.build.gcpimage = (
            import (nixpkgsPath + /nixos/lib/make-disk-image.nix) {
              pkgs = pkgs;
              lib = lib;
              config = config;
              additionalSpace = "0M";
              partitionTableType = "legacy";
              installBootLoader = true;
              fsType = "ext4";
              label = fsLabel;
              format = "raw";
              copyChannel = false;
              postVM = ''
                set -xeu
                mv $diskImage disk.raw
                ${pkgs.gnutar}/bin/tar --format=oldgnu -Sczf $out/compressed-image.tar.gz disk.raw
                rm disk.raw
              '';
            }
          );
        }
      )
    ];
  }
)
