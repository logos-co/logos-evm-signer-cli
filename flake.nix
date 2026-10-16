{
  description = "evm_signer_cli — the headless approver for signer_manager_module, driven over logosctl.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Pinned to the manager's first branch until it reaches main.
    signer_manager_module = {
      url = "github:logos-co/logos-signer-manager-module/308b151c7460cff2300cbc8cc338f04cd7442a6a";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    # OPTIONAL. Named so the generated client exists; never loaded on its account, and
    # absent is a normal state — the interpretation it feeds is a feature, not a
    # precondition, and this signer must come up on a device that has no token list.
    token_list_module = {
      url = "github:logos-co/logos-evm-token-list-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    # OPTIONAL too. Section 1 names who asked as the user's installed package does, never as the
    # requester says. Only its contract is read here, so its library input is cut.
    package_manager = {
      url = "github:logos-co/logos-package-manager-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
      inputs.logos-package-manager.follows = "";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross PSEUDO-SYSTEM the builder understands; a target, never a
      # host nixpkgs is evaluated for natively, so it only ever belongs in `packages`.
      targets = systems ++ [ "x86_64-windows" ];
    in
    {
      packages = nixpkgs.lib.genAttrs targets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
