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
    config = {
      system.build.docker_image = pkgs.dockerTools.buildLayeredImage
        {
          name = "docker_image";
          contents = [
            (pkgs.cacert.override {
              extraCertificateFiles = [
                (pkgs.fetchurl {
                  url = "https://storage.googleapis.com/zlr7wmbe6/spaghettinuum_s.crt";
                  hash = "sha256-cg0EIXX05OrZDeZcgCkmMxfyJhBdEdBplYOJr3ET9fk=";
                })
              ];
            })
            (pkgs.buildEnv
              {
                name = "spaghettinuum";
                paths = [ (import ./package.nix) ];
                pathsToLink = [ "/bin" ];
              })
          ];
        };
    };
  })
