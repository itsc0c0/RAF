from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="surface",
    display_name="Surface",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Authorized external attack surface from imported inventories: scope, ownership, DNS, "
    "certificates, exposed services and cloud storage (no scanning)",
    category="exposure",
    commands=["surface"],
    cli="raf.products.surface.cli:app",
    api="raf.products.surface.api:router",
    parsers=["raf.products.surface.parser:SurfaceInventoryParser"],
    docs="docs/products/surface.md",
    ui={"route": "/surface", "nav": "Surface"},
)
