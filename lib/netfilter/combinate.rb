
class Array
  def combinate(arr = nil, stack = [], results = [])
    arr = self if arr.nil?
    if arr.empty?
      results << stack.dup
    else
      arr.first.each do |e|
        stack << e
        combinate(arr[1..-1], stack, results)
        stack.pop
      end
      results
    end
  end
end

class Hash
  def combinate(arr = nil, stack = [], results = [])
    arr = self.keys if arr.nil?
    if arr.empty?
      results << stack.inject({}) { |e,h| h.merge(e) }
    else
      [self[arr.first]].flatten.each do |k|
        stack << { arr.first => k }
        combinate(arr[1..-1], stack, results)
        stack.pop
      end
      results
    end
  end
end

