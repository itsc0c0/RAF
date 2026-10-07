from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="graph",
    display_name="Graph",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Security relationship graph: neighborhoods, paths, temporal views, export",
    category="investigation",
    commands=["graph"],
    cli="raf.products.graph.cli:app",
    api="raf.products.graph.api:router",
    docs="docs/products/graph.md",
    ui={"route": "/graph", "nav": "Graph"},
)
