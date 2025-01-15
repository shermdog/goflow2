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
	templateID            = 256
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
		if err := d.writeTemplate(buf); err != nil {
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

func (d *NetFlowDriver) writeTemplate(buf *bytes.Buffer) error {
	template := struct {
		FlowsetID  uint16
		Length     uint16
		TemplateID uint16
		FieldCount uint16
		Fields     [18]struct{ Type, Length uint16 }
	}{
		FlowsetID:  templateFlowsetID,
		Length:     80, // 4 (header) + 4 (template header) + 18 * 4 (fields)
		TemplateID: templateID,
		FieldCount: 18,
		Fields: [18]struct{ Type, Length uint16 }{
			{Type: 1, Length: 4},  // IN_BYTES
			{Type: 2, Length: 4},  // IN_PKTS
			{Type: 4, Length: 1},  // PROTOCOL
			{Type: 5, Length: 1},  // TOS
			{Type: 6, Length: 1},  // TCP_FLAGS
			{Type: 7, Length: 2},  // L4_SRC_PORT
			{Type: 8, Length: 4},  // IPV4_SRC_ADDR
			{Type: 9, Length: 1},  // SRC_NET
			{Type: 10, Length: 2}, // INPUT_SNMP
			{Type: 11, Length: 2}, // L4_DST_PORT
			{Type: 12, Length: 4}, // IPV4_DST_ADDR
			{Type: 13, Length: 1}, // DST_NET
			{Type: 14, Length: 2}, // OUTPUT_SNMP
			{Type: 15, Length: 4}, // IPV4_NEXT_HOP
			{Type: 21, Length: 4}, // LAST_SWITCHED
			{Type: 22, Length: 4}, // FIRST_SWITCHED
			{Type: 23, Length: 2}, // OUT_BYTES (same as IN_BYTES)
			{Type: 24, Length: 2}, // OUT_PKTS (same as IN_PKTS)
		},
	}

	return binary.Write(buf, binary.BigEndian, template)
}

func (d *NetFlowDriver) writeFlowRecord(buf *bytes.Buffer, fm *flowmessage.FlowMessage) error {
	// Convert IP addresses from byte slices to uint32
	srcAddr := ipToUint32(fm.SrcAddr)
	dstAddr := ipToUint32(fm.DstAddr)
	nextHop := ipToUint32(fm.NextHop)

	// Ensure that values fit within their respective field sizes
	bytes := uint32(fm.Bytes)
	packets := uint32(fm.Packets)
	inIf := uint16(fm.InIf)
	outIf := uint16(fm.OutIf)

	// Convert nanoseconds to milliseconds
	timeFlowEnd := uint32(fm.TimeFlowEndNs / 1000000)
	timeFlowStart := uint32(fm.TimeFlowStartNs / 1000000)

	// Write each field of the flow record
	fields := []interface{}{
		bytes,
		packets,
		uint8(fm.Proto),
		uint8(fm.IpTos),
		uint8(fm.TcpFlags),
		uint16(fm.SrcPort),
		srcAddr,
		uint8(fm.SrcNet),
		inIf,
		uint16(fm.DstPort),
		dstAddr,
		uint8(fm.DstNet),
		outIf,
		nextHop,
		timeFlowEnd,
		timeFlowStart,
		uint16(bytes),   // OutBytes (truncated to 16 bits)
		uint16(packets), // OutPackets (truncated to 16 bits)
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return err
		}
	}

	return nil
}

// Helper function to convert IP address from byte slice to uint32
func ipToUint32(ip []byte) uint32 {
	if len(ip) == 4 {
		return binary.BigEndian.Uint32(ip)
	}
	return 0 // Return 0 for invalid IP addresses
}

func (d *NetFlowDriver) writeDataFlowsetBatch(buf *bytes.Buffer, flows []*flowmessage.FlowMessage) error {
	// Write data flowset header
	if err := binary.Write(buf, binary.BigEndian, uint16(templateID)); err != nil {
		return err
	}
	lengthPos := buf.Len()
	if err := binary.Write(buf, binary.BigEndian, uint16(0)); err != nil { // Placeholder for length
		return err
	}

	for _, fm := range flows {
		if err := d.writeFlowRecord(buf, fm); err != nil {
			return err
		}
	}

	// Update flowset length
	length := uint16(buf.Len() - lengthPos + 2)
	binary.BigEndian.PutUint16(buf.Bytes()[lengthPos:], length)

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
