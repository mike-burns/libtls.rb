module LibTLS
class UnknownCError < RuntimeError
  def to_s
    "#{super.to_s} failed"
  end
end

class CError < RuntimeError
end
end
