{
  description = "ragemanifest dev shell -- wasm build, extension build, smoke and Playwright Tier-2";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        nativeDeps = [
          pkgs.pcsclite
          pkgs.dbus
          pkgs.udev
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.lld
            pkgs.pkg-config
            pkgs.wasm-pack
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
            pkgs.nodejs_26
            pkgs.pnpm_12
            pkgs.web-ext
            pkgs.firefox
            pkgs.playwright-driver
            pkgs.vaultwarden
            pkgs.zip
            pkgs.util-linux
          ]
          ++ nativeDeps;

          buildInputs = nativeDeps;

          shellHook = ''
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
            export RAGEWARDEN_VAULTWARDEN_BIN="${pkgs.vaultwarden}/bin/vaultwarden"
            mkdir -p node_modules/.bin
            ln -sfn ${pkgs.web-ext}/bin/web-ext node_modules/.bin/web-ext
          '';
        };
      }
    );
}
