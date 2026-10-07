"""R$F Surface: an organization's authorized external attack surface, from imported inventories.

Surface never touches the network: no DNS resolution, no port scanning, no HTTP or certificate
retrieval. Everything it knows comes from imported inventories and the authorized scope the
operator declares (``raf surface scope add``).
"""
