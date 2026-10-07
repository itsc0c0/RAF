from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="timeline",
    display_name="Timeline",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Unified event timelines with filters, grouping and JSON/CSV/R$F export",
    category="investigation",
    commands=["timeline"],
    cli="raf.products.timeline.cli:app",
    api="raf.products.timeline.api:router",
    docs="docs/products/timeline.md",
    ui={"route": "/timeline", "nav": "Timeline"},
)
