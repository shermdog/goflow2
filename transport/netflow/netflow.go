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
	netflowV9Version  = 9
	templateID        = 256
	templateFlowsetID = 0
)

type NetFlowDriver struct {
	destinationAddr string
	conn            net.Conn
	templateCache   map[uint32]time.Time
	sequenceNum     uint32
	packetCount     uint32
	templateRefresh uint64
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

	// Determine if we need to send a template
	sendTemplate := d.packetCount == 0 || uint64(d.packetCount)%d.templateRefresh == 0

	// Format the flow message as NetFlow v9
	packet, err := d.formatNetflowV9(flowMessage, sendTemplate)
	if err != nil {
		return fmt.Errorf("failed to format NetFlow v9 packet: %w", err)
	}

	// Send the packet
	_, err = d.conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send data to NetFlow destination: %w", err)
	}

	d.packetCount++
	return nil
}

func (d *NetFlowDriver) formatNetflowV9(fm *flowmessage.FlowMessage, sendTemplate bool) ([]byte, error) {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()               // Clear the buffer in case it was used before
	defer bufferPool.Put(buf) // Return the buffer to the pool when we're done

	// Write header
	flowsetCount := uint16(1)
	if sendTemplate {
		flowsetCount++
	}
	if err := d.writeHeader(buf, fm, flowsetCount); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	// Write template flowset if needed
	if sendTemplate {
		if err := d.writeTemplate(buf); err != nil {
			return nil, fmt.Errorf("failed to write template: %w", err)
		}
	}

	// Write data flowset
	if err := d.writeDataFlowset(buf, fm); err != nil {
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
			{Type: 9, Length: 1},  // SRC_MASK
			{Type: 10, Length: 2}, // INPUT_SNMP
			{Type: 11, Length: 2}, // L4_DST_PORT
			{Type: 12, Length: 4}, // IPV4_DST_ADDR
			{Type: 13, Length: 1}, // DST_MASK
			{Type: 14, Length: 2}, // OUTPUT_SNMP
			{Type: 15, Length: 4}, // IPV4_NEXT_HOP
			{Type: 21, Length: 4}, // LAST_SWITCHED
			{Type: 22, Length: 4}, // FIRST_SWITCHED
			{Type: 23, Length: 2}, // OUT_BYTES
			{Type: 24, Length: 2}, // OUT_PKTS
		},
	}

	return binary.Write(buf, binary.BigEndian, template)
}

func (d *NetFlowDriver) writeDataFlowset(buf *bytes.Buffer, fm *flowmessage.FlowMessage) error {
	var tempBuf bytes.Buffer

	fields := []struct {
		value interface{}
		size  int
	}{
		{uint32(fm.Bytes), 4},
		{uint32(fm.Packets), 4},
		{uint8(fm.Proto), 1},
		{uint8(fm.IpTos), 1},
		{uint8(fm.TcpFlags), 1},
		{uint16(fm.SrcPort), 2},
		{fm.SrcAddr[:4], 4},
		{uint8(fm.SrcNet), 1},
		{uint16(fm.InIf), 2},
		{uint16(fm.DstPort), 2},
		{fm.DstAddr[:4], 4},
		{uint8(fm.DstNet), 1},
		{uint16(fm.OutIf), 2},
		{fm.NextHop[:4], 4},
		{uint32(fm.TimeFlowEndNs / 1000000), 4},
		{uint32(fm.TimeFlowStartNs / 1000000), 4},
		{uint16(fm.Bytes), 2},
		{uint16(fm.Packets), 2},
	}

	for _, field := range fields {
		if err := binary.Write(&tempBuf, binary.BigEndian, field.value); err != nil {
			return fmt.Errorf("failed to write field: %v", err)
		}
	}

	// Write data flowset header
	dataFlowsetHeader := struct {
		FlowsetID uint16
		Length    uint16
	}{
		FlowsetID: templateID,
		Length:    uint16(tempBuf.Len() + 4), // +4 for the header itself
	}
	if err := binary.Write(buf, binary.BigEndian, dataFlowsetHeader); err != nil {
		return fmt.Errorf("failed to write data flowset header: %w", err)
	}

	// Write the data
	_, err := buf.Write(tempBuf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write data flowset content: %w", err)
	}

	return nil
}

func (d *NetFlowDriver) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func init() {
	transport.RegisterTransportDriver("netflow", &NetFlowDriver{})
}
