from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="policy",
    display_name="Policy",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Normalize and analyze network and access policies; evaluate flows with the decision chain",
    category="exposure",
    commands=["policy"],
    cli="raf.products.policy.cli:app",
    api="raf.products.policy.api:router",
    parsers=["raf.products.policy.parser:PolicyFileParser"],
    docs="docs/products/policy.md",
    ui={"route": "/exposure", "nav": "Exposure"},
)
