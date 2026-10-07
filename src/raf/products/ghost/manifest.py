from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="ghost",
    display_name="Ghost",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Security digital twins: what-if models, simulated exposure and comparisons (no real systems)",
    category="synthetic",
    commands=["ghost"],
    cli="raf.products.ghost.cli:app",
    api="raf.products.ghost.api:router",
    docs="docs/products/ghost.md",
    ui={"route": "/ghost", "nav": "Ghost"},
)
