__author__ = 'r2h2'

class JSONdecodeError(Exception):
    pass


class HashChainError(Exception):
    pass



class InputFormatOrValueError(Exception):
    pass


class InputValueError(InputFormatOrValueError):
    pass


class InputFormatError(InputFormatOrValueError):
    pass


class SecurityLayerUnavailableError(Exception):
    """ Security Layer (MOCCA etc.) is inactive (local port 3495 not open) """
    pass


class SecurityLayerCancelledError(Exception):
    """ Security Layer (MOCCA etc.) interaction was cancelled by user """
    pass


class InvalidArgumentValueError(Exception):
    pass


class EmptySamlEDError(Exception):
    """ SAML metadata file is empty or does not exist """
    pass


class EmptyAODSError(Exception):
    """ Policy Journal file is empty and will not be saved"""
    pass


class InvalidSamlXmlSchemaError(Exception):
    """ Invalid XML schmea for SAML metadata """
    pass


class ValidationError(Exception):
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


class InvalidFQDNError(ValidationError):
    """ The FQDN is not in the allowed domains """
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

