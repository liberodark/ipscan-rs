{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    rustfmt
    clippy
    rust-analyzer
    pkg-config
    xorg.libX11
    xorg.libXcursor
    xorg.libXrandr
    xorg.libXi
    xorg.libXinerama
    xorg.libxcb
    xorg.libXext
    xorg.libXfixes
    xorg.libXrender
    xorg.libXtst
    libxkbcommon
    libGL
    libGLU
    wayland
  ];

  shellHook = ''
    rustfmt --edition 2024 src/*.rs
    rm -f "$HOME/.cargo/advisory-db..lock"
    cargo audit
    export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
      pkgs.xorg.libX11
      pkgs.xorg.libXcursor
      pkgs.xorg.libXrandr
      pkgs.xorg.libXi
      pkgs.xorg.libxcb
      pkgs.libxkbcommon
      pkgs.libGL
      pkgs.wayland
    ]}:$LD_LIBRARY_PATH"
  '';

  RUST_BACKTRACE = 1;
}
