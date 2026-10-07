from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="blast",
    display_name="Blast",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Blast radius of a hypothetical compromise with explainable paths and risk",
    category="exposure",
    commands=["blast"],
    cli="raf.products.blast.cli:app",
    api="raf.products.blast.api:router",
    docs="docs/products/blast.md",
    ui={"route": "/exposure", "nav": "Exposure"},
)
