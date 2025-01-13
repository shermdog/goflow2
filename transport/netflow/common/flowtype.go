package common

type FlowType int

const (
	TypeUnknown FlowType = iota
	TypeSFlow5
	TypeNetFlow5
	TypeNetFlow9
	TypeIPFIX
)

func (ft FlowType) String() string {
	switch ft {
	case TypeSFlow5:
		return "sflow5"
	case TypeNetFlow5:
		return "netflow5"
	case TypeNetFlow9:
		return "netflow9"
	case TypeIPFIX:
		return "ipfix"
	default:
		return "unknown"
	}
}
