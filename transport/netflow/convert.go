package netflow

import (
	"encoding/json"
	"fmt"
	"net"

	flowmessage "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/transport/netflow/common"
)

func ConvertJSONToFlowMessage(data []byte) (*flowmessage.FlowMessage, error) {
	fmt.Printf("Incoming JSON data: %s\n", string(data))

	var jsonMap map[string]interface{}
	err := json.Unmarshal(data, &jsonMap)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON: %v", err)
	}

	msg := &flowmessage.FlowMessage{}

	for key, value := range jsonMap {
		applyField(msg, key, value)
	}

	return msg, nil
}

func applyField(msg *flowmessage.FlowMessage, key string, value interface{}) {
	switch key {
	case "type":
		if v, ok := value.(string); ok {
			flowType := flowmessage.FlowMessage_FlowType(flowmessage.FlowMessage_FlowType_value[v])
			msg.Type = flowmessage.FlowMessage_FlowType(convertFlowType(flowType))
		}
	case "time_flow_start_ns":
		setInt(&msg.TimeFlowStartNs, value)
	case "time_flow_end_ns":
		setInt(&msg.TimeFlowEndNs, value)
	case "bytes":
		setInt(&msg.Bytes, value)
	case "packets":
		setInt(&msg.Packets, value)
	case "src_addr":
		setIP(&msg.SrcAddr, value)
	case "dst_addr":
		setIP(&msg.DstAddr, value)
	case "src_port":
		setInt(&msg.SrcPort, value)
	case "dst_port":
		setInt(&msg.DstPort, value)
	case "proto":
		setProto(&msg.Proto, value)
	case "tcp_flags":
		setInt(&msg.TcpFlags, value)
	case "etype":
		setEtype(&msg.Etype, value)
	case "in_if":
		setInt(&msg.InIf, value)
	case "out_if":
		setInt(&msg.OutIf, value)
	case "src_mac":
		setMac(&msg.SrcMac, value)
	case "dst_mac":
		setMac(&msg.DstMac, value)
	case "src_vlan":
		setInt(&msg.SrcVlan, value)
	case "dst_vlan":
		setInt(&msg.DstVlan, value)
	case "vlan_id":
		setInt(&msg.VlanId, value)
	case "ip_tos":
		setInt(&msg.IpTos, value)
	case "sampler_address":
		setIP(&msg.SamplerAddress, value)
	case "sampling_rate":
		setInt(&msg.SamplingRate, value)
	case "time_received_ns":
		setInt(&msg.TimeReceivedNs, value)
	case "sequence_num":
		setInt(&msg.SequenceNum, value)
	case "forwarding_status":
		setInt(&msg.ForwardingStatus, value)
	case "ip_ttl":
		setInt(&msg.IpTtl, value)
	case "ip_flags":
		setInt(&msg.IpFlags, value)
	case "icmp_type":
		setInt(&msg.IcmpType, value)
	case "icmp_code":
		setInt(&msg.IcmpCode, value)
	case "ipv6_flow_label":
		setInt(&msg.Ipv6FlowLabel, value)
	case "ipv6_routing_header_seg_left":
		setInt(&msg.Ipv6RoutingHeaderSegLeft, value)
	case "fragment_id":
		setInt(&msg.FragmentId, value)
	case "fragment_offset":
		setInt(&msg.FragmentOffset, value)
	case "src_as":
		setInt(&msg.SrcAs, value)
	case "dst_as":
		setInt(&msg.DstAs, value)
	case "next_hop":
		setIP(&msg.NextHop, value)
	case "next_hop_as":
		setInt(&msg.NextHopAs, value)
	case "src_net":
		setNet(&msg.SrcNet, value)
	case "dst_net":
		setNet(&msg.DstNet, value)
	case "bgp_next_hop":
		setIP(&msg.BgpNextHop, value)
	case "bgp_communities":
		setBgpCommunities(&msg.BgpCommunities, value)
	case "as_path":
		setAsPath(&msg.AsPath, value)
	case "mpls_ttl":
		setMplsTtl(&msg.MplsTtl, value)
	case "mpls_label":
		setMplsLabel(&msg.MplsLabel, value)
	case "mpls_ip":
		setMplsIp(&msg.MplsIp, value)
	case "observation_domain_id":
		setInt(&msg.ObservationDomainId, value)
	case "observation_point_id":
		setInt(&msg.ObservationPointId, value)
	case "layer_size":
		setUint32Slice(&msg.LayerSize, value)
	case "layer_stack":
		setLayerStack(&msg.LayerStack, value)
	case "ipv6_routing_header_addresses":
		setIPv6RoutingHeaderAddresses(&msg.Ipv6RoutingHeaderAddresses, value)
	default:
		fmt.Printf("Unhandled field: %s\n", key)
	}
}

// Add these new helper functions:

func setProto(field *uint32, value interface{}) {
	if v, ok := value.(string); ok {
		*field = uint32(getProtoNumber(v))
	}
}

func setEtype(field *uint32, value interface{}) {
	if v, ok := value.(string); ok {
		*field = uint32(getEtypeNumber(v))
	}
}

func setMac(field *uint64, value interface{}) {
	if v, ok := value.(string); ok {
		mac, err := net.ParseMAC(v)
		if err == nil {
			*field = macToUint64(mac)
		}
	}
}

func setNet(field *uint32, value interface{}) {
	if v, ok := value.(string); ok {
		_, ipnet, err := net.ParseCIDR(v)
		if err == nil {
			*field = ipNetToUint32(ipnet)
		}
	}
}

func ipNetToUint32(ipnet *net.IPNet) uint32 {
	ones, _ := ipnet.Mask.Size()
	return uint32(ones)
}

func setBgpCommunities(field *[]uint32, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]uint32, len(v))
		for i, comm := range v {
			if c, ok := comm.(float64); ok {
				(*field)[i] = uint32(c)
			}
		}
	}
}

func setAsPath(field *[]uint32, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]uint32, len(v))
		for i, as := range v {
			if a, ok := as.(float64); ok {
				(*field)[i] = uint32(a)
			}
		}
	}
}

func setMplsTtl(field *[]uint32, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]uint32, len(v))
		for i, ttl := range v {
			if t, ok := ttl.(float64); ok {
				(*field)[i] = uint32(t)
			}
		}
	}
}

func setMplsLabel(field *[]uint32, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]uint32, len(v))
		for i, label := range v {
			if l, ok := label.(float64); ok {
				(*field)[i] = uint32(l)
			}
		}
	}
}

func setMplsIp(field *[][]byte, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([][]byte, len(v))
		for i, ip := range v {
			if ipStr, ok := ip.(string); ok {
				parsedIP := net.ParseIP(ipStr)
				if parsedIP != nil {
					(*field)[i] = parsedIP
				}
			}
		}
	}
}

func getProtoNumber(protoName string) int {
	switch protoName {
	case "TCP":
		return 6
	case "UDP":
		return 17
	// Add more protocol mappings as needed
	default:
		return 0
	}
}

func getEtypeNumber(etypeName string) int {
	switch etypeName {
	case "IPv4":
		return 0x0800
	case "IPv6":
		return 0x86DD
	// Add more ethertype mappings as needed
	default:
		return 0
	}
}

func macToUint64(mac net.HardwareAddr) uint64 {
	var macInt uint64
	for i, b := range mac {
		macInt |= uint64(b) << ((5 - i) * 8)
	}
	return macInt
}

func convertFlowType(flowType flowmessage.FlowMessage_FlowType) common.FlowType {
	switch flowType {
	case flowmessage.FlowMessage_SFLOW_5:
		return common.TypeSFlow5
	case flowmessage.FlowMessage_NETFLOW_V5:
		return common.TypeNetFlow5
	case flowmessage.FlowMessage_NETFLOW_V9:
		return common.TypeNetFlow9
	case flowmessage.FlowMessage_IPFIX:
		return common.TypeIPFIX
	default:
		return common.TypeUnknown
	}
}

func setInt[T uint64 | uint32 | int32 | int64](field *T, value interface{}) {
	if v, ok := value.(float64); ok {
		*field = T(v)
	}
}

func setIP(field *[]byte, value interface{}) {
	if v, ok := value.(string); ok {
		ip := net.ParseIP(v)
		if ip != nil {
			*field = ip.To4()
			if *field == nil {
				*field = ip.To16()
			}
		}
	}
}

func setUint32Slice(field *[]uint32, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]uint32, len(v))
		for i, item := range v {
			if num, ok := item.(float64); ok {
				(*field)[i] = uint32(num)
			}
		}
	}
}

func setLayerStack(field *[]flowmessage.FlowMessage_LayerStack, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([]flowmessage.FlowMessage_LayerStack, len(v))
		for i, item := range v {
			if num, ok := item.(float64); ok {
				(*field)[i] = flowmessage.FlowMessage_LayerStack(uint32(num))
			}
		}
	}
}

func setIPv6RoutingHeaderAddresses(field *[][]byte, value interface{}) {
	if v, ok := value.([]interface{}); ok {
		*field = make([][]byte, len(v))
		for i, item := range v {
			if ipStr, ok := item.(string); ok {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					(*field)[i] = ip.To16()
				}
			}
		}
	}
}
