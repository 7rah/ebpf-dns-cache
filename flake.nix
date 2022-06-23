{
  inputs = {
    nixpkgs.url = "nixpkgs"; 
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self,utils ,nixpkgs, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      rec {
        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            pkgconfig
            llvm_13
            clang_13
            rustup
            rust-analyzer
            cargo-watch
            glibc
            git
           ];
          buildInputs = with pkgs; [
            openssl
            zlib
            libxml2
            libelf
            llvm_13.dev
            clang_13
            glibc
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages_13.libclang.lib}/lib";
        };
      });
}
