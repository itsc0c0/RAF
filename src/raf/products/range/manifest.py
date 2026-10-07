from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="range",
    display_name="Range",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Synthetic organizations with deterministic seeds and simulated routine activity",
    category="synthetic",
    commands=["range"],
    cli="raf.products.range.cli:app",
    api="raf.products.range.api:router",
    docs="docs/products/range.md",
    ui={"route": "/ranges", "nav": "Ranges"},
)
