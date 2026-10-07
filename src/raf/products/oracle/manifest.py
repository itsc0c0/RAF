from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="oracle",
    display_name="Oracle",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Grounded answers about the workspace with citations to R$F objects (builtin reasoner or a model)",
    category="ai",
    commands=["oracle"],
    cli="raf.products.oracle.cli:app",
    api="raf.products.oracle.api:router",
    docs="docs/products/oracle.md",
    ui={"route": "/oracle", "nav": "Oracle"},
)
