package network

import (
	"hash/fnv"
	"net"
)

// InterfaceList is the list of network interfaces
type InterfaceList []*NetworkInterface

// FindByIdentifier tries to find an interface that matches the id.
func (i InterfaceList) FindByIdentifier(id uint32) *NetworkInterface {
	for _, inter := range i {
		if inter.Identifier() == id {
			return inter
		}
	}
	return nil
}

// NetworkInterface is information collected about a interface.
type NetworkInterface struct {
	*net.Interface
}

// Identifier returns the uint32 id of the interface.
func (ni *NetworkInterface) Identifier() uint32 {
	h := fnv.New32a()
	h.Write([]byte(ni.Name))
	return h.Sum32()
}

// BroadcastAddr returns the IPV4 broadcast address, if any.
func (ni *NetworkInterface) BroadcastAddr() *net.IPNet {
	if ni.Flags&net.FlagBroadcast == 0 {
		return nil
	}

	addrs, err := ni.Addrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		ipa, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ones, bits := ipa.Mask.Size()
		if ones == bits || bits != 32 {
			continue
		}
		return ipa
	}

	return nil
}

// ListNetworkInterfaces builds the list of applicable network interfaces.
func ListNetworkInterfaces() ([]*NetworkInterface, error) {
	netInters, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var result []*NetworkInterface
	for _, ni := range netInters {
		func(ni net.Interface) {
			result = append(result, &NetworkInterface{Interface: &ni})
		}(ni)
	}

	return result, nil
}

// FromAddr attempts to determine which interface an address belongs to.
func FromAddr(addr net.IP) (*NetworkInterface, error) {
	netInters, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, inter := range netInters {
		addrs, err := inter.Addrs()
		if err != nil {
			continue
		}
		for _, iaddr := range addrs {
			ipn, ok := iaddr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipn.Contains(addr) {
				return func(ni net.Interface) *NetworkInterface {
					return &NetworkInterface{Interface: &ni}
				}(inter), nil
			}
		}
	}

	return nil, nil
}
