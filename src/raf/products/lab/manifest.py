from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="lab",
    display_name="Lab",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Isolated container labs for security experiments (no network, no capabilities, read-only by default)",
    category="synthetic",
    commands=["lab"],
    cli="raf.products.lab.cli:app",
    api="raf.products.lab.api:router",
    docs="docs/products/lab.md",
    ui={"route": "/lab", "nav": "Lab"},
)
