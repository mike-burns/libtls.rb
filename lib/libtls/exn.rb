module LibTLS
##
# An unknown error occured in the libtls library
#
# This exception is raised when a non-TLS issue occurs in the libtls library.
# If possible, it might be useful to inspect +errno+ when you rescue this
# exception.
class UnknownCError < RuntimeError
  ##
  # A description of the error
  #
  # This description contains the C function name.
  def to_s
    "#{super.to_s} failed"
  end
end

##
# A known error occured in the libtls library
class CError < RuntimeError
end
end
