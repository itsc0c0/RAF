from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="lens",
    display_name="Lens",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Security data workbench: filter, group and pivot any scope of events, objects and findings",
    category="analysis",
    depends_on=["timeline"],
    commands=["lens"],
    cli="raf.products.lens.cli:app",
    api="raf.products.lens.api:router",
    docs="docs/products/lens.md",
    ui={"route": "/investigate", "nav": "Investigate"},
)
