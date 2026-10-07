from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="trace",
    display_name="Trace",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Causal chains around an object: observed links vs. labeled correlations",
    category="investigation",
    commands=["trace"],
    cli="raf.products.trace.cli:app",
    api="raf.products.trace.api:router",
    docs="docs/products/trace.md",
    ui={"route": "/investigate", "nav": None},
)
