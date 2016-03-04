"""

This file contains the exception hierarchy for repy. This allows repy modules
to import a single file to have access to all the defined exceptions.

"""

# This list maintains the exceptions that are exported to the user
# If the exception is not listed here, the user cannot explicitly
# catch that error.
_EXPORTED_EXCEPTIONS = ["RepyException",
                        "RepyArgumentError",
                        "CodeUnsafeError",
                        "ContextUnsafeError",
                        "ResourceUsageError",
                        "ResourceExhaustedError",
                        "ResourceForbiddenError",
                        "FileError",
                        "FileNotFoundError",
                        "FileInUseError",
                        "SeekPastEndOfFileError",
                        "FileClosedError",
                        "LockDoubleReleaseError",
                        "NetworkError",
                        "NetworkAddressError",
                        "AlreadyListeningError",
                        "DuplicateTupleError",
                        "CleanupInProgressError",
                        "InternetConnectivityError",
                        "AddressBindingError",
                        "ConnectionRefusedError",
                        "LocalIPChanged",
                        "SocketClosedLocal",
                        "SocketClosedRemote",
                        "SocketWouldBlockError",
                        "TCPServerSocketInvalidError",
                        "TimeoutError",
                       ]



##### High-level, generic exceptions

class InternalRepyError (Exception):
  """
  All Fatal Repy Exceptions derive from this exception.
  This error should never make it to the user-code.
  """
  pass

class RepyException (Exception):
  """All Repy Exceptions derive from this exception."""
  def __init__(self, *value):
    self.value = value
  def __str__(self):
    return str(self.value)
  def __repr__(self):
    # Using `type` on a Repy exception returns
    # "<class 'exception_hierarchy." and the Repy exception class name, 
    # followed by a closing "'>". We are interested only in the actual 
    # exception class name.
    # (The `value` parameter on the other hand is a plain tuple.)
    my_type_as_string = str(type(self))
    name_prefix = "<class 'exception_hierarchy."
    exception_name = my_type_as_string[len(name_prefix):-2]
    return exception_name + str(self.value)

class RepyArgumentError (RepyException):
  """
  This Exception indicates that an argument was provided
  to a repy API as an in-appropriate type or value.
  """
  pass

class TimeoutError (RepyException):
  """
  This generic error indicates that a timeout has
  occurred.
  """
  pass


##### Code Safety Exceptions

class CodeUnsafeError (RepyException):
  """
  This indicates that the static code analysis failed due to
  unsafe constructions or a syntax error.
  """
  pass

class ContextUnsafeError (RepyException):
  """
  This indicates that the context provided to evaluate() was
  unsafe, and could not be converted into a SafeDict.
  """
  pass


##### Resource Related Exceptions

class ResourceUsageError (RepyException):
  """
  All Resource Usage Exceptions derive from this exception.
  """
  pass

class ResourceExhaustedError (ResourceUsageError):
  """
  This Exception indicates that a resource has been
  Exhausted, and that the operation has failed for that
  reason.
  """
  pass

class ResourceForbiddenError (ResourceUsageError):
  """
  This Exception indicates that a specified resource
  is forbidden, and cannot be used.
  """
  pass


##### File Related Exceptions

class FileError (RepyException):
  """All File-Related Exceptions derive from this exception."""
  pass

class FileNotFoundError (FileError):
  """
  This Exception indicates that a file which does not exist was
  used as an argument to a function expecting a real file.
  """
  pass

class FileInUseError (FileError):
  """
  This Exception indicates that a file which is in use was
  used as an argument to a function expecting the file to
  be un-used.
  """
  pass

class SeekPastEndOfFileError (FileError):
  """
  This Exception indicates that an attempt was made to
  seek past the end of a file.
  """
  pass

class FileClosedError (FileError):
  """
  This Exception indicates that the file is closed,
  and that the operation is therfor invalid.
  """
  pass


##### Safety exceptions from safe.py

class SafeException(RepyException):
    """Base class for Safe Exceptions"""
    pass

class CheckNodeException(SafeException):
    """AST Node class is not in the whitelist."""
    pass

class CheckStrException(SafeException):
    """A string in the AST looks insecure."""
    pass

class RunBuiltinException(SafeException):
    """During the run a non-whitelisted builtin was called."""
    pass


##### Lock related exceptions

class LockDoubleReleaseError(RepyException):
  """
  This exception indicates that an attempt was made to
  release a lock that was not acquired.
  """
  pass


##### Network exceptions

class NetworkError (RepyException):
  """
  This exception parent-classes all of the networking exceptions.
  """
  pass

class NetworkAddressError (NetworkError):
  """
  This exception is raised when a DNS lookup fails.
  """
  pass

class AlreadyListeningError (NetworkError):
  """
  This exception indicates that there is an existing
  listen on the local IP / Port pair that are specified.
  """
  pass

class DuplicateTupleError (NetworkError):
  """
  This exception indicates that there is another socket
  which has a duplicate tuple (local ip, local port, remote ip, remote port)
  """
  pass

class CleanupInProgressError (NetworkError):
  """
  This exception indicates that the socket is still
  being cleaned up by the operating system, and that
  it is unavailable.
  """
  pass

class InternetConnectivityError (NetworkError):
  """
  This exception is raised when there is no route to an IP passed to
  sendmessage or openconnection.
  """
  pass

class AddressBindingError (NetworkError):
  """
  This exception is raised when binding to an ip and port fails.
  """
  pass

class ConnectionRefusedError (NetworkError):
  """
  This exception is raised when a TCP connection request is refused.
  """
  pass

class LocalIPChanged (NetworkError):
  """
  This exception indicates that the local IP has changed.
  """
  pass

class SocketClosedLocal (NetworkError):
  """
  This indicates that the socket was closed locally.
  """
  pass

class SocketClosedRemote (NetworkError):
  """
  This indicates that the socket was closed on the remote end.
  """
  pass

class SocketWouldBlockError (NetworkError):
  """
  This indicates that the socket operation would have blocked.
  """
  pass

class TCPServerSocketInvalidError(NetworkError):
  """
  This indicates that the TCP server socket has become invalid, e.g. 
  because the local IP address changed.
  """
