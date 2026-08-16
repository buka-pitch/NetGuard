package dnsmon

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

type ParsedResponse struct {
	Question string
	Answers  []Answer
}

type Answer struct {
	IP  net.IP
	TTL uint32
}

func ParseResponse(payload []byte) (*ParsedResponse, error) {
	if len(payload) < 12 {
		return nil, fmt.Errorf("packet too short: %d", len(payload))
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 == 0 {
		return nil, fmt.Errorf("not a response")
	}

	qdcount := int(binary.BigEndian.Uint16(payload[4:6]))
	ancount := int(binary.BigEndian.Uint16(payload[6:8]))

	if qdcount == 0 || ancount == 0 {
		return nil, fmt.Errorf("no questions or answers")
	}

	offset := 12
	qname, err := parseName(payload, offset)
	if err != nil {
		return nil, fmt.Errorf("parse question name: %w", err)
	}
	offset += lenEncodedName(payload, offset)
	// skip QTYPE (2) + QCLASS (2)
	offset += 4

	resp := &ParsedResponse{
		Question: qname,
	}

	for i := 0; i < ancount; i++ {
		if offset+10 > len(payload) {
			break
		}
		// skip NAME (possibly compressed)
		skip := lenEncodedName(payload, offset)
		offset += skip

		if offset+10 > len(payload) {
			break
		}
		rtype := binary.BigEndian.Uint16(payload[offset:])
		rclass := binary.BigEndian.Uint16(payload[offset+2:])
		ttl := binary.BigEndian.Uint32(payload[offset+4:])
		rdlength := int(binary.BigEndian.Uint16(payload[offset+8:]))
		offset += 10

		if offset+rdlength > len(payload) {
			break
		}
		rdata := payload[offset : offset+rdlength]
		offset += rdlength

		if rclass != 1 {
			continue
		}

		switch rtype {
		case 1:
			if len(rdata) == 4 {
				resp.Answers = append(resp.Answers, Answer{
					IP:  net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]),
					TTL: ttl,
				})
			}
		case 28:
			if len(rdata) == 16 {
				resp.Answers = append(resp.Answers, Answer{
					IP:  net.IP(rdata),
					TTL: ttl,
				})
			}
		}
	}

	return resp, nil
}

func parseName(data []byte, offset int) (string, error) {
	var labels []string
	max := len(data)
	for offset < max {
		b := data[offset]
		if b == 0 {
			break
		}
		if b&0xC0 == 0xC0 {
			if offset+1 >= max {
				return "", fmt.Errorf("truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			rest, err := parseName(data, ptr)
			if err != nil {
				return "", err
			}
			labels = append(labels, rest)
			return strings.Join(labels, "."), nil
		}
		length := int(b)
		offset++
		if offset+length > max {
			return "", fmt.Errorf("label exceeds packet")
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), nil
}

func lenEncodedName(data []byte, offset int) int {
	start := offset
	max := len(data)
	for offset < max {
		b := data[offset]
		if b == 0 {
			return offset - start + 1
		}
		if b&0xC0 == 0xC0 {
			return offset - start + 2
		}
		offset += int(b) + 1
	}
	return offset - start
}