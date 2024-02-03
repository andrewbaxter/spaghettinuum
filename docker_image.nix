{}:
let
  nixpkgsPath = <nixpkgs>;
  buildSystem = (configuration: import
    (nixpkgsPath + /nixos/lib/eval-config.nix)
    { modules = [ configuration ]; });
in
buildSystem
  ({ pkgs, ... }:
  {
    config.system.build.docker_image = pkgs.dockerTools.buildLayeredImage
      {
        name = "docker_image";
        config = {
          WorkingDir =
            let
              spagh = pkgs.callPackage
                ({ lib
                 , rustPlatform
                 , pkg-config
                 , nettle
                 , cargo
                 , rustc
                 , capnproto
                 , pcsclite
                 , sqlite
                 }:
                  rustPlatform.buildRustPackage {
                    pname = "spaghettinuum";
                    version = "0.0.0";
                    src = ./spaghettinuum;
                    # Based on final path element of src
                    sourceRoot = "spaghettinuum";
                    # For build.rs:
                    # Source is copied over with all the files read only for some reason.
                    # Make a new tree as the build user and make the files writable.
                    preConfigure = ''
                      cd ../
                      mv spaghettinuum ro
                      cp -r ro rw
                      chmod -R u+w rw
                      cd rw
                    '';
                    cargoLock = {
                      lockFile = ./spaghettinuum/Cargo.lock;
                    };
                    buildFeatures = [
                      "card"
                    ];
                    buildInputs = [
                      nettle
                      pcsclite
                      sqlite
                    ];
                    nativeBuildInputs = [
                      pkg-config
                      cargo
                      rustc
                      rustPlatform.bindgenHook
                      capnproto
                    ];
                    meta = {
                      description = "x";
                      homepage = "https://x/";
                      license = [ lib.licenses.isc ];
                    };
                  })
                { };
            in
            "${spagh}/bin"
          ;
        };
      };
  })
