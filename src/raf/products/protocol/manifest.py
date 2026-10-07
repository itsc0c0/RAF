from raf.core.plugins.manifest import ProductManifest, ProductStatus
from raf.version import RAF_VERSION

MANIFEST = ProductManifest(
    name="protocol",
    display_name="Protocol",
    version=RAF_VERSION,
    status=ProductStatus.BETA,
    description="Packet captures (pcap/pcapng): explained protocol fields, flows, DNS/HTTP/TLS metadata",
    category="analysis",
    commands=["protocol"],
    cli="raf.products.protocol.cli:app",
    api="raf.products.protocol.api:router",
    parsers=["raf.products.protocol.parser:PcapParser"],
    docs="docs/products/protocol.md",
    ui={"route": "/protocol", "nav": "Protocol"},
)
