from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="replay",
    display_name="Replay",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Deterministic temporal incident reconstruction (state at T, windows, playback)",
    category="investigation",
    commands=["replay"],
    cli="raf.products.replay.cli:app",
    api="raf.products.replay.api:router",
    docs="docs/products/replay.md",
    ui={"route": "/replay", "nav": "Replay"},
)
