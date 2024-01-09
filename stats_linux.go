package netlink

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/vishvananda/netlink/nl"
)

// Internal tc_stats representation in Go struct.
// This is for internal uses only to deserialize the payload of rtattr.
// After the deserialization, this should be converted into the canonical stats
// struct, ClassStatistics, in case of statistics of a class.
// Ref: struct tc_stats { ... }
type TcStats struct {
	Bytes      uint64 // Number of enqueued bytes
	Packets    uint32 // Number of enqueued packets
	Drops      uint32 // Packets dropped because of lack of resources
	Overlimits uint32 // Number of throttle events when this flow goes out of allocated bandwidth
	Bps        uint32 // Current flow byte rate
	Pps        uint32 // Current flow packet rate
	Qlen       uint32
	Backlog    uint32
}

func parseTcStatsBase(data []byte) (*TcStats, error) {
	buf := &bytes.Buffer{}
	buf.Write(data)
	tcStats := &TcStats{}
	if err := binary.Read(buf, native, tcStats); err != nil {
		return nil, err
	}

	return tcStats, nil
}

func parseTcStats(data []byte) (*ClassStatistics, error) {
	tcStats, err := parseTcStatsBase(data)
	if err != nil {
		return nil, err
	}

	stats := NewClassStatistics()
	stats.Basic.Bytes = tcStats.Bytes
	stats.Basic.Packets = tcStats.Packets
	stats.Queue.Qlen = tcStats.Qlen
	stats.Queue.Backlog = tcStats.Backlog
	stats.Queue.Drops = tcStats.Drops
	stats.Queue.Overlimits = tcStats.Overlimits
	stats.RateEst.Bps = tcStats.Bps
	stats.RateEst.Pps = tcStats.Pps

	return stats, nil
}

func parseTcStats2(data []byte) (*ClassStatistics, error) {
	rtAttrs, err := nl.ParseRouteAttr(data)
	if err != nil {
		return nil, err
	}
	stats := NewClassStatistics()
	for _, datum := range rtAttrs {
		switch datum.Attr.Type {
		case nl.TCA_STATS_BASIC:
			if err := parseGnetStats(datum.Value, stats.Basic); err != nil {
				return nil, fmt.Errorf("Failed to parse ClassStatistics.Basic with: %v\n%s",
					err, hex.Dump(datum.Value))
			}
		case nl.TCA_STATS_QUEUE:
			if err := parseGnetStats(datum.Value, stats.Queue); err != nil {
				return nil, fmt.Errorf("Failed to parse ClassStatistics.Queue with: %v\n%s",
					err, hex.Dump(datum.Value))
			}
		case nl.TCA_STATS_RATE_EST:
			if err := parseGnetStats(datum.Value, stats.RateEst); err != nil {
				return nil, fmt.Errorf("Failed to parse ClassStatistics.RateEst with: %v\n%s",
					err, hex.Dump(datum.Value))
			}
		case nl.TCA_STATS_BASIC_HW:
			if err := parseGnetStats(datum.Value, stats.BasicHw); err != nil {
				return nil, fmt.Errorf("Failed to parse ClassStatistics.BasicHw with: %v\n%s",
					err, hex.Dump(datum.Value))
			}
		}
	}

	return stats, nil
}
