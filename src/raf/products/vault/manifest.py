from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="vault",
    display_name="Vault",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Secret hygiene: find exposed credentials in files (redacted, fingerprinted, allowlistable)",
    category="analysis",
    commands=["vault"],
    cli="raf.products.vault.cli:app",
    api="raf.products.vault.api:router",
    docs="docs/products/vault.md",
    ui={"route": "/findings", "nav": None},
)
