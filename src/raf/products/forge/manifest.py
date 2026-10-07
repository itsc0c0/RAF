from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="forge",
    display_name="Forge",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Synthetic security telemetry (auth, DNS, web, process, file, identity, cloud) and modeled scenarios",
    category="synthetic",
    commands=["forge"],
    cli="raf.products.forge.cli:app",
    api="raf.products.forge.api:router",
    docs="docs/products/forge.md",
    ui={"route": "/ranges", "nav": "Ranges"},
)
