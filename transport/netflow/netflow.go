package netflow

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"time"

	flowmessage "github.com/netsampler/goflow2/v2/pb"
	"github.com/netsampler/goflow2/v2/transport"
	"google.golang.org/protobuf/proto"
)

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
}

func (d *NetFlowDriver) Prepare() error {
	flag.StringVar(&d.destinationAddr, "netflow.destination", "127.0.0.1:2056", "NetFlow destination address")
	return nil
}

func (d *NetFlowDriver) Init() error {
	var err error
	d.conn, err = net.Dial("udp", d.destinationAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to NetFlow destination: %w", err)
	}
	d.templateCache = make(map[uint32]time.Time)
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

	packet, err := d.formatNetflowV9(flowMessage)
	if err != nil {
		return fmt.Errorf("failed to format NetFlow v9 packet: %w", err)
	}

	_, err = d.conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send data to NetFlow destination: %w", err)
	}
	return nil
}

func (d *NetFlowDriver) formatNetflowV9(fm *flowmessage.FlowMessage) ([]byte, error) {
	var buf bytes.Buffer

	// Write header
	if err := d.writeHeader(&buf, fm, 2); err != nil { // 2 flowsets: template and data
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	// Write template flowset
	if err := d.writeTemplate(&buf); err != nil {
		return nil, fmt.Errorf("failed to write template: %w", err)
	}

	// Write data flowset
	if err := d.writeDataFlowset(&buf, fm); err != nil {
		return nil, fmt.Errorf("failed to write data flowset: %w", err)
	}

	return buf.Bytes(), nil
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
	templateHeader := struct {
		FlowsetID uint16
		Length    uint16
	}{
		FlowsetID: templateFlowsetID,
		Length:    80, // Header (4) + TemplateID (2) + FieldCount (2) + 18 fields * 4
	}
	if err := binary.Write(buf, binary.BigEndian, templateHeader); err != nil {
		return err
	}

	templateRecord := struct {
		TemplateID uint16
		FieldCount uint16
	}{
		TemplateID: templateID,
		FieldCount: 18,
	}
	if err := binary.Write(buf, binary.BigEndian, templateRecord); err != nil {
		return err
	}

	fields := []struct {
		Type   uint16
		Length uint16
	}{
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
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return err
		}
	}

	return nil
}

func (d *NetFlowDriver) writeDataFlowset(buf *bytes.Buffer, fm *flowmessage.FlowMessage) error {
	dataHeader := struct {
		FlowsetID uint16
		Length    uint16
	}{
		FlowsetID: templateID,
		Length:    46, // Header (4) + Data (42)
	}
	if err := binary.Write(buf, binary.BigEndian, dataHeader); err != nil {
		return err
	}

	// Write flow data
	if err := binary.Write(buf, binary.BigEndian, uint32(fm.Bytes)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(fm.Packets)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint8(fm.Proto)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint8(fm.IpTos)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint8(fm.TcpFlags)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.SrcPort)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, fm.SrcAddr[:4]); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.InIf)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.DstPort)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, fm.DstAddr[:4]); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.OutIf)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, fm.NextHop[:4]); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(fm.TimeFlowEndNs/1000000)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint32(fm.TimeFlowStartNs/1000000)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.Bytes)); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(fm.Packets)); err != nil {
		return err
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