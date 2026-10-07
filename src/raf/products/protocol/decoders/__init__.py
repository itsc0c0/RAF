"""Protocol decoders (link, network, transport and application layers).

Every decoder works on immutable ``bytes``, reads through a bounds-checked
:class:`~raf.products.protocol.decoders.base.Cursor` and reports problems by
marking its layer ``malformed`` instead of raising.
"""
