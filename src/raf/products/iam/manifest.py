from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="iam",
    display_name="IAM",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Identity and access analysis: effective access, privilege paths, risky identities",
    category="exposure",
    commands=["iam"],
    cli="raf.products.iam.cli:app",
    api="raf.products.iam.api:router",
    docs="docs/products/iam.md",
    ui={"route": "/exposure", "nav": "Exposure"},
)
