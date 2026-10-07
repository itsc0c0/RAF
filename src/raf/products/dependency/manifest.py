from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="dependency",
    display_name="Dependency",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Dependency inventory from manifests and lockfiles, SBOM import/export, offline OSV advisory checks",
    category="analysis",
    commands=["dependency"],
    cli="raf.products.dependency.cli:app",
    api="raf.products.dependency.api:router",
    docs="docs/products/dependency.md",
    ui={"route": "/findings", "nav": None},
)
