package netflow

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"sync"
	"time"

	flowmessage "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/transport"
	"google.golang.org/protobuf/proto"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

const (
	netflowV9Version      = 9
	templateIDIPv4        = 256
	templateIDIPv6        = 257
	templateFlowsetID     = 0
	maxPacketSize         = 1464 // Maximum size of a NetFlow packet (typical MTU minus IP and UDP headers)
	maxFlowsetSize        = 1444 // Maximum size of a flowset (maxPacketSize minus NetFlow header)
	flowRecordSize        = 52   // Size of a single flow record (sum of all field lengths)
	dataFlowsetHeaderSize = 4    // Size of the data flowset header (FlowsetID + Length)
)

type NetFlowDriver struct {
	destinationAddr string
	conn            net.Conn
	templateCache   map[uint32]time.Time
	sequenceNum     uint32
	packetCount     uint32
	templateRefresh uint64
	flowBuffer      []*flowmessage.FlowMessage
	bufferSize      int
}

func (d *NetFlowDriver) Prepare() error {
	flag.StringVar(&d.destinationAddr, "netflow.destination", "127.0.0.1:2056", "NetFlow destination address")
	flag.Uint64Var(&d.templateRefresh, "netflow.template.refresh", 20, "Number of packets between template refreshes")
	return nil
}

func (d *NetFlowDriver) Init() error {
	var err error
	d.conn, err = net.Dial("udp", d.destinationAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to NetFlow destination: %w", err)
	}
	d.templateCache = make(map[uint32]time.Time)
	d.packetCount = 0
	return nil
}

func (d *NetFlowDriver) Send(key, data []byte) error {
	var flowMessage *flowmessage.FlowMessage
	var err error

	// Try to unmarshal as protobuf first
	flowMessage = &flowmessage.FlowMessage{}
	if err = proto.Unmarshal(data, flowMessage); err != nil {
		// If protobuf fails, try JSON
		flowMessage, err = ConvertJSONToFlowMessage(data)
		if err != nil {
			return fmt.Errorf("failed to unmarshal flow message: %v", err)
		}
	}

	// Add the flow to the buffer
	d.flowBuffer = append(d.flowBuffer, flowMessage)
	d.bufferSize += flowRecordSize

	// Check if we need to send a packet
	if d.bufferSize >= maxFlowsetSize-dataFlowsetHeaderSize || len(d.flowBuffer) == 30 {
		if err := d.sendBatch(); err != nil {
			return fmt.Errorf("failed to send batch: %w", err)
		}
	}

	return nil
}

func (d *NetFlowDriver) sendBatch() error {
	if len(d.flowBuffer) == 0 {
		return nil
	}

	// Determine if we need to send a template
	sendTemplate := d.packetCount == 0 || uint64(d.packetCount)%d.templateRefresh == 0

	// Format the NetFlow v9 packet
	packet, err := d.formatNetflowV9Batch(d.flowBuffer, sendTemplate)
	if err != nil {
		return fmt.Errorf("failed to format NetFlow v9 packet: %w", err)
	}

	// Send the packet
	_, err = d.conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send data to NetFlow destination: %w", err)
	}

	d.packetCount++
	d.flowBuffer = d.flowBuffer[:0] // Clear the buffer
	d.bufferSize = 0

	return nil
}

func (d *NetFlowDriver) formatNetflowV9Batch(flows []*flowmessage.FlowMessage, sendTemplate bool) ([]byte, error) {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	// Write header
	flowsetCount := uint16(1)
	if sendTemplate {
		flowsetCount++
	}
	if err := d.writeHeader(buf, flows[0], flowsetCount); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	// Write template flowset if needed
	if sendTemplate {
		if err := d.writeBothTemplates(buf); err != nil {
			return nil, fmt.Errorf("failed to write template: %w", err)
		}
	}

	// Write data flowset
	if err := d.writeDataFlowsetBatch(buf, flows); err != nil {
		return nil, fmt.Errorf("failed to write data flowset: %w", err)
	}

	// Create a copy of the buffer's bytes to return
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())

	return result, nil
}

func (d *NetFlowDriver) writeHeader(buf *bytes.Buffer, fm *flowmessage.FlowMessage, flowsetCount uint16) error {
	header := struct {
		Version        uint16
		Count          uint16
		SysUptime      uint32
		UnixSecs       uint32
		SequenceNumber uint32
		SourceID       uint32
	}{
		Version:        netflowV9Version,
		Count:          flowsetCount,
		SysUptime:      uint32(fm.TimeFlowEndNs / 1000000), // Convert to milliseconds
		UnixSecs:       uint32(fm.TimeReceivedNs / 1000000000),
		SequenceNumber: d.sequenceNum,
		SourceID:       0,
	}
	d.sequenceNum++

	return binary.Write(buf, binary.BigEndian, header)
}

func (d *NetFlowDriver) writeBothTemplates(buf *bytes.Buffer) error {
	// Template FlowSet Header
	templateHeader := struct {
		FlowsetID uint16
		Length    uint16
	}{
		FlowsetID: templateFlowsetID,
		Length:    0, // We'll update this later
	}

	templateHeaderPos := buf.Len()
	if err := binary.Write(buf, binary.BigEndian, templateHeader); err != nil {
		return fmt.Errorf("failed to write template header: %w", err)
	}

	// IPv4 Template
	if err := d.writeIPv4Template(buf); err != nil {
		return fmt.Errorf("failed to write IPv4 template: %w", err)
	}

	// IPv6 Template
	if err := d.writeIPv6Template(buf); err != nil {
		return fmt.Errorf("failed to write IPv6 template: %w", err)
	}

	// Update template length
	templateLength := uint16(buf.Len() - templateHeaderPos)
	binary.BigEndian.PutUint16(buf.Bytes()[templateHeaderPos+2:], templateLength)

	return nil
}

func (d *NetFlowDriver) writeIPv4Template(buf *bytes.Buffer) error {
	templateIPv4 := struct {
		TemplateID uint16
		FieldCount uint16
		Fields     [17]struct{ Type, Length uint16 }
	}{
		TemplateID: templateIDIPv4,
		FieldCount: 17,
		Fields: [17]struct{ Type, Length uint16 }{
			{Type: 1, Length: 4},  // IN_BYTES
			{Type: 2, Length: 4},  // IN_PKTS
			{Type: 4, Length: 1},  // PROTOCOL
			{Type: 6, Length: 1},  // TCP_FLAGS
			{Type: 7, Length: 2},  // L4_SRC_PORT
			{Type: 11, Length: 2}, // L4_DST_PORT
			{Type: 10, Length: 2}, // INPUT_SNMP
			{Type: 14, Length: 2}, // OUTPUT_SNMP
			{Type: 21, Length: 4}, // LAST_SWITCHED
			{Type: 22, Length: 4}, // FIRST_SWITCHED
			{Type: 23, Length: 4}, // OUT_BYTES
			{Type: 24, Length: 4}, // OUT_PKTS
			{Type: 8, Length: 4},  // IPV4_SRC_ADDR
			{Type: 9, Length: 1},  // SRC_NET
			{Type: 12, Length: 4}, // IPV4_DST_ADDR
			{Type: 13, Length: 1}, // DST_NET
			{Type: 15, Length: 4}, // IPV4_NEXT_HOP
		},
	}

	return binary.Write(buf, binary.BigEndian, templateIPv4)
}

func (d *NetFlowDriver) writeIPv6Template(buf *bytes.Buffer) error {
	templateIPv6 := struct {
		TemplateID uint16
		FieldCount uint16
		Fields     [17]struct{ Type, Length uint16 }
	}{
		TemplateID: templateIDIPv6,
		FieldCount: 17,
		Fields: [17]struct{ Type, Length uint16 }{
			{Type: 1, Length: 4},   // IN_BYTES
			{Type: 2, Length: 4},   // IN_PKTS
			{Type: 4, Length: 1},   // PROTOCOL
			{Type: 6, Length: 1},   // TCP_FLAGS
			{Type: 7, Length: 2},   // L4_SRC_PORT
			{Type: 11, Length: 2},  // L4_DST_PORT
			{Type: 10, Length: 2},  // INPUT_SNMP
			{Type: 14, Length: 2},  // OUTPUT_SNMP
			{Type: 21, Length: 4},  // LAST_SWITCHED
			{Type: 22, Length: 4},  // FIRST_SWITCHED
			{Type: 23, Length: 4},  // OUT_BYTES
			{Type: 24, Length: 4},  // OUT_PKTS
			{Type: 27, Length: 16}, // IPV6_SRC_ADDR
			{Type: 29, Length: 1},  // IPV6_SRC_MASK
			{Type: 28, Length: 16}, // IPV6_DST_ADDR
			{Type: 30, Length: 1},  // IPV6_DST_MASK
			{Type: 62, Length: 16}, // IPV6_NEXT_HOP
		},
	}

	return binary.Write(buf, binary.BigEndian, templateIPv6)
}

func (d *NetFlowDriver) writeIPv4FlowData(buf *bytes.Buffer, flow *flowmessage.FlowMessage) error {
	fields := []interface{}{
		uint32(flow.Bytes),
		uint32(flow.Packets),
		uint8(flow.Proto),
		uint8(flow.TcpFlags),
		uint16(flow.SrcPort),
		uint16(flow.DstPort),
		uint16(flow.InIf),
		uint16(flow.OutIf),
		uint32(flow.TimeFlowEndNs / 1000000),   // Convert ns to ms
		uint32(flow.TimeFlowStartNs / 1000000), // Convert ns to ms
		uint32(flow.Bytes),                     // OUT_BYTES (using Bytes as a placeholder)
		uint32(flow.Packets),                   // OUT_PKTS (using Packets as a placeholder)
		flow.SrcAddr[:4],                       // Full IPv4 source address
		uint8(flow.SrcNet),
		flow.DstAddr[:4], // Full IPv4 destination address
		uint8(flow.DstNet),
		flow.NextHop[:4], // Full IPv4 next hop
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return fmt.Errorf("failed to write IPv4 field: %w", err)
		}
	}

	return nil
}

func (d *NetFlowDriver) writeIPv6FlowData(buf *bytes.Buffer, flow *flowmessage.FlowMessage) error {
	fields := []interface{}{
		uint32(flow.Bytes),
		uint32(flow.Packets),
		uint8(flow.Proto),
		uint8(flow.TcpFlags),
		uint16(flow.SrcPort),
		uint16(flow.DstPort),
		uint16(flow.InIf),
		uint16(flow.OutIf),
		uint32(flow.TimeFlowEndNs / 1000000),   // Convert ns to ms
		uint32(flow.TimeFlowStartNs / 1000000), // Convert ns to ms
		uint32(flow.Bytes),                     // OUT_BYTES (using Bytes as a placeholder)
		uint32(flow.Packets),                   // OUT_PKTS (using Packets as a placeholder)
		flow.SrcAddr[:16],                      // IPv6 source address (16 bytes)
		uint8(flow.SrcNet),
		flow.DstAddr[:16], // IPv6 destination address (16 bytes)
		uint8(flow.DstNet),
		flow.NextHop[:16], // IPv6 next hop (16 bytes)
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return fmt.Errorf("failed to write IPv6 field: %w", err)
		}
	}
	return nil
}

func (d *NetFlowDriver) writeFlowData(buf *bytes.Buffer, flow *flowmessage.FlowMessage) error {
	if len(flow.SrcAddr) == 4 { // IPv4
		return d.writeIPv4FlowData(buf, flow)
	} else if len(flow.SrcAddr) == 16 { // IPv6
		return d.writeIPv6FlowData(buf, flow)
	}
	return fmt.Errorf("unsupported IP version: %d bytes", len(flow.SrcAddr))
}

func (d *NetFlowDriver) writeDataFlowsetBatch(buf *bytes.Buffer, flows []*flowmessage.FlowMessage) error {
	var flowsetBuf bytes.Buffer
	var currentTemplateID uint16

	for _, flow := range flows {
		var templateID uint16
		if len(flow.SrcAddr) == 4 { // IPv4
			templateID = templateIDIPv4
		} else if len(flow.SrcAddr) == 16 { // IPv6
			templateID = templateIDIPv6
		} else {
			return fmt.Errorf("unsupported IP version: %d bytes", len(flow.SrcAddr))
		}

		// If templateID changes or flowset would exceed max size, write current flowset and start a new one
		if templateID != currentTemplateID || flowsetBuf.Len()+flowRecordSize > maxFlowsetSize-dataFlowsetHeaderSize {
			if flowsetBuf.Len() > 0 {
				if err := d.writeFlowset(buf, currentTemplateID, flowsetBuf.Bytes()); err != nil {
					return err
				}
				flowsetBuf.Reset()
			}
			currentTemplateID = templateID
		}

		// Write flow data to the flowset buffer
		if err := d.writeFlowData(&flowsetBuf, flow); err != nil {
			return fmt.Errorf("failed to write flow data: %w", err)
		}
	}

	// Write any remaining data in the buffer
	if flowsetBuf.Len() > 0 {
		if err := d.writeFlowset(buf, currentTemplateID, flowsetBuf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func (d *NetFlowDriver) writeFlowset(buf *bytes.Buffer, templateID uint16, data []byte) error {
	// Write flowset header
	if err := binary.Write(buf, binary.BigEndian, templateID); err != nil {
		return fmt.Errorf("failed to write flowset header template ID: %w", err)
	}
	length := uint16(len(data) + dataFlowsetHeaderSize)
	if err := binary.Write(buf, binary.BigEndian, length); err != nil {
		return fmt.Errorf("failed to write flowset header length: %w", err)
	}

	// Write flowset data
	if _, err := buf.Write(data); err != nil {
		return fmt.Errorf("failed to write flowset data: %w", err)
	}

	return nil
}

func (d *NetFlowDriver) Close() error {
	if err := d.sendBatch(); err != nil {
		return fmt.Errorf("failed to send final batch: %w", err)
	}
	return d.conn.Close()
}

func init() {
	transport.RegisterTransportDriver("netflow", &NetFlowDriver{})
}
