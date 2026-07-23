{ config, pkgs, lib, ... }:
{
  options = {
    volumesetup = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable the volumesetup service to run at boot. See volumesetup documentation for default values for various parameters.";
      };
      debug = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable debug logging.";
      };
      uuid = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Override the default UUID.";
      };
      mountpoint = lib.mkOption {
        type = lib.types.str;
        default = "/mnt/persistent";
        description = "Where to mount the volume";
      };

      encryption = lib.mkOption {
        type = lib.types.enum [ "none" "shared-image" "private-image" ];
        default = "none";
        description = "What mode to use to encrypt the volume. See the command arguments for more details.";
      };

      # Shared image encryption
      encryptionSharedImageMode = lib.mkOption {
        type = lib.types.enum [ "password" ];
        default = "password";
        description = "How to obtain the disk key for shared image encryption.";
      };

      # Private image
      encryptionPrivateImageKeyfile = lib.mkOption {
        type = lib.types.str;
        description = "Path to encrypted key file for private-image encryption";
      };
      encryptionPrivateImageMode = lib.mkOption {
        type = lib.types.enum [ "smartcard" ];
        default = "smartcard";
      };
      encryptionPrivateImageSmartcardPinMode = lib.mkOption {
        type = lib.types.enum [ "factory-default" "text" "numpad" ];
        description = "How to get the PIN for the smartcard.";
      };
      encryptionPrivateImageDecrypt = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Optionally, a file encrypted with `age` encryption (using the keyfile key as the passphrase) to decrypt to `/run/volumesetup-decrypted`.";
      };

      # Post-mount
      ensureDirs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "A list of paths of directories to create after mounting. These may be absolute or relative to the mountpoint.";
      };
    };
  };
  config =
    let
      cfg = config.volumesetup;
    in
    {
      systemd.services = lib.mkIf cfg.enable {
        volumesetup = {
          wantedBy = [ "local-fs.target" ];
          after = [
            "local-fs.target"
            # For pcscd
            "sockets.target"
          ];
          serviceConfig.Type = "oneshot";
          serviceConfig.RemainAfterExit = "yes";
          startLimitIntervalSec = 0;
          serviceConfig.Restart = "on-failure";
          serviceConfig.RestartSec = 60;
          script =
            let
              pkg = (import ./package.nix) { pkgs = pkgs; };
              cmdline = lib.concatStringsSep " "
                (
                  [ ]
                  ++ [ "${pkg}/bin/volumesetup" ]
                  ++ (lib.lists.optionals cfg.debug [ "--debug" ])
                  ++ (lib.lists.optionals (cfg.uuid != "") [ "--uuid ${cfg.uuid}" ])
                  ++ [ "--mountpoint ${cfg.mountpoint}" ]
                  ++ {
                    "none" = [ ];
                    "shared-image" = [ "--encryption" "shared-image" ] ++ {
                      "password" = [ "--key-mode" "password" ];
                    }.${cfg.encryptionSharedImageMode};
                    "private-image" = [ "--encryption" "private-image" "--key" cfg.encryptionPrivateImageKeyfile ] ++ {
                      "smartcard" = [ "--key-mode" "smartcard" cfg.encryptionSmartcardPinMode ];
                    }.${cfg.encryptionPrivateImageMode};
                  }.${cfg.encryption}
                  ++ (lib.lists.optionals (cfg.ensureDirs != [ ]) [ "--ensure-dirs" ] ++ cfg.ensureDirs)
                );
            in
            ''
              set -xeu
              exec ${cmdline}
            '';
        };
      };
    };
}
