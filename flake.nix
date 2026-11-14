# ffp: FFP-AegisScan-SCANNER-FLAKE declarative nix
{
  description = "AegisScan v2.1.0 — Tier-2 Standalone 8-Domain Polyglot Security & AI Prompt-Safety Enclave";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    tianxia-core = {
      url = "github:Tianxia-Core/TianxiaOS";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, tianxia-core, ... }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in {
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [ go python3 ];
          };
        }
      );
    };
}
