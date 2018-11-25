__author__ = 'r2h2'

class PVZDuserexception(Exception):
    pass


class JSONdecodeError(PVZDuserexception):
    pass


class HashChainError(PVZDuserexception):
    pass



class InputFormatOrValueError(PVZDuserexception):
    pass


class InputValueError(InputFormatOrValueError):
    pass


class InputFormatError(InputFormatOrValueError):
    pass


class SecurityLayerUnavailableError(PVZDuserexception):
    """ Security Layer (MOCCA etc.) is inactive (local port 3495 not open) """
    pass


class SecurityLayerCancelledError(PVZDuserexception):
    """ Security Layer (MOCCA etc.) interaction was cancelled by user """
    pass


class InvalidArgumentValueError(PVZDuserexception):
    pass


class EmptySamlEDError(PVZDuserexception):
    """ SAML metadata file is empty or does not exist """
    pass


class EmptyAODSError(PVZDuserexception):
    """ Policy Journal file is empty and will not be saved"""
    pass


class InvalidSamlXmlSchemaError(PVZDuserexception):
    """ Invalid XML schmea for SAML metadata """
    pass


class MultipleEntitiesNotAllowed(PVZDuserexception):
    """ More than 1 EntitiyDescriptor is not allowed in a request """
    pass

class ValidationError(PVZDuserexception):
    """ application-level validation failure """
    pass


class EntityRoleNotSupportedError(ValidationError):
    """ Only IDP and SP roles are implemented """
    pass


class CertExpiredError(ValidationError):
    """ certificate has a notValidAfter date in the pas """
    pass


class CertInvalidError(ValidationError):
    """ certificate was not issued by a accredited CA """
    pass


class EdHostnameNotMatchingCertSubject(ValidationError):
    """ Hostname in EntityID does not match CN in certificate subject """
    pass


class InvalidFQDNinEntityID(ValidationError):
    """ The entitID's FQDN is not in the allowed namespaces """
    pass


class InvalidFQDNInEndpoint(ValidationError):
    """ The FQDN of a location URL is not in the allowed namespaces """
    pass


class MissingRootElemError(ValidationError):
    """ Expected XML root element not found """
    pass


class UnauthorizedSignerError(ValidationError):
    """ Signer certificate not found not found in policy directory """
    pass


class UnauthorizedAODSSignerError(ValidationError):
    """ Signer certificate of policy journal not found not found in policy directory """
    pass


class SignatureVerificationError(ValidationError):
    """ Signature verification failed """
    pass


class PMPInputRecNoDictError(ValidationError):
    """ PMP input record is not a non-empty list of dict """
    pass

class MissingArgumentError(ValidationError):
    """ required argument missing """
    pass

