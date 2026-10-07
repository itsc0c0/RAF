from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="exposure",
    display_name="Exposure",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Contextual, explainable exposure of every asset (criticality, reachability, vulns, control paths)",
    category="exposure",
    commands=["exposure"],
    cli="raf.products.exposure.cli:app",
    api="raf.products.exposure.api:router",
    docs="docs/products/exposure.md",
    ui={"route": "/exposure", "nav": "Exposure"},
)
