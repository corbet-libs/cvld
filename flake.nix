{
  description = "Native libraries for the door's CI checks";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { nixpkgs, ... }: {
    devShells = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; }; in {
        ci = pkgs.mkShell {
          packages = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };
      });
  };
}
