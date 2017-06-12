package route

import (
	"github.com/golang/protobuf/proto"
)

// DecodeHops decodes the encoded hops array.
func (r *Route) DecodeHops() ([]*Route_Hop, error) {
	result := make([]*Route_Hop, len(r.Hop))

	for i, bin := range r.Hop {
		h := &Route_Hop{}
		if err := proto.Unmarshal(bin, h); err != nil {
			return nil, err
		}
		result[i] = h
	}

	return result, nil
}
