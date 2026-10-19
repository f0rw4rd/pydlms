"""pydlms - a DLMS/COSEM client library for Python (IEC 62056).

Packet definitions are expressed with the ``construct`` declarative library;
higher layers (association, client, transports) orchestrate them.

Until 1.0 the surface is unstable. The names below are the supported entry
points; everything else is importable from its subpackage.
"""

__version__ = "0.1.0"

from pydlms.association import AssociationSettings
from pydlms.client import (
    AccessAction,
    AccessGet,
    AccessOutcome,
    AccessSet,
    DlmsClient,
    RegisterValue,
)
from pydlms.cosem.data import DlmsData, decode_data, encode_data
from pydlms.cosem.time import CosemDateTime
from pydlms.debug import enable_debug
from pydlms.exceptions import (
    AssociationError,
    AuthenticationError,
    CryptoProviderError,
    DlmsError,
    LinkLostError,
    ReplayError,
    ServiceError,
)
from pydlms.explain import explain
from pydlms.image import ImageTransferResult, transfer_image
from pydlms.obis import ObisCode
from pydlms.objects import CosemObject
from pydlms.push import PushDecoder, PushMessage
from pydlms.security.context import SecurityContext
from pydlms.security.general import GeneralAad, SigningForm
from pydlms.security.hls import Mechanism
from pydlms.security.provider import CryptoProvider, SoftwareProvider
from pydlms.security.thirdparty import ThirdParty

__all__ = [
    "AccessAction",
    "AccessGet",
    "AccessOutcome",
    "AccessSet",
    "AssociationError",
    "AssociationSettings",
    "AuthenticationError",
    "CosemDateTime",
    "CosemObject",
    "CryptoProvider",
    "CryptoProviderError",
    "DlmsClient",
    "DlmsData",
    "DlmsError",
    "GeneralAad",
    "ImageTransferResult",
    "LinkLostError",
    "Mechanism",
    "ObisCode",
    "PushDecoder",
    "PushMessage",
    "RegisterValue",
    "ReplayError",
    "SecurityContext",
    "ServiceError",
    "SigningForm",
    "SoftwareProvider",
    "ThirdParty",
    "__version__",
    "decode_data",
    "enable_debug",
    "encode_data",
    "explain",
    "transfer_image",
]
