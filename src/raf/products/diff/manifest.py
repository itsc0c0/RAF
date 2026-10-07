from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="diff",
    display_name="Diff",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Compare security states (snapshots, current, Ghost models) with explained importance",
    category="investigation",
    commands=["diff"],
    cli="raf.products.diff.cli:app",
    api="raf.products.diff.api:router",
    docs="docs/products/diff.md",
    ui={"route": "/investigate", "nav": None},
)
