from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="evidence",
    display_name="Evidence",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="DFIR cases: SHA-256 hashed read-only evidence, chain of custody, verification",
    category="analysis",
    commands=["evidence"],
    cli="raf.products.evidence.cli:app",
    api="raf.products.evidence.api:router",
    docs="docs/products/evidence.md",
    ui={"route": "/evidence", "nav": "Evidence"},
)
