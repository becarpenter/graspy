"""Dummy ACP module"""

def status():
    """Dummy ACP status() for testing purposes"""
    return True  #pretend ACP is available

#Note - we might want a similar mechanism to show that the
#security bootstrap succeeded. But if there's no ACP,
#and TLS fails, we know we have no trust in place.

#We might also need to know on which interfaces the ACP
#is up. At the moment we assume it is up for all.
