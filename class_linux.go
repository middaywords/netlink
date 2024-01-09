package netlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// NewHtbClass NOTE: function is in here because it uses other linux functions
func NewHtbClass(attrs ClassAttrs, cattrs HtbClassAttrs) *HtbClass {
	mtu := 1600
	rate := cattrs.Rate / 8
	ceil := cattrs.Ceil / 8
	buffer := cattrs.Buffer
	cbuffer := cattrs.Cbuffer

	if ceil == 0 {
		ceil = rate
	}

	if buffer == 0 {
		buffer = uint32(float64(rate)/Hz() + float64(mtu))
	}
	buffer = Xmittime(rate, buffer)

	if cbuffer == 0 {
		cbuffer = uint32(float64(ceil)/Hz() + float64(mtu))
	}
	cbuffer = Xmittime(ceil, cbuffer)

	return &HtbClass{
		ClassAttrs: attrs,
		Rate:       rate,
		Ceil:       ceil,
		Buffer:     buffer,
		Cbuffer:    cbuffer,
		Level:      0,
		Prio:       cattrs.Prio,
		Quantum:    cattrs.Quantum,
	}
}

// ClassDel will delete a class from the system.
// Equivalent to: `tc class del $class`
func ClassDel(class Class) error {
	return pkgHandle.ClassDel(class)
}

// ClassDel will delete a class from the system.
// Equivalent to: `tc class del $class`
func (h *Handle) ClassDel(class Class) error {
	return h.classModify(unix.RTM_DELTCLASS, 0, class)
}

// ClassChange will change a class in place
// Equivalent to: `tc class change $class`
// The parent and handle MUST NOT be changed.
func ClassChange(class Class) error {
	return pkgHandle.ClassChange(class)
}

// ClassChange will change a class in place
// Equivalent to: `tc class change $class`
// The parent and handle MUST NOT be changed.
func (h *Handle) ClassChange(class Class) error {
	return h.classModify(unix.RTM_NEWTCLASS, 0, class)
}

// ClassReplace will replace a class to the system.
// quivalent to: `tc class replace $class`
// The handle MAY be changed.
// If a class already exist with this parent/handle pair, the class is changed.
// If a class does not already exist with this parent/handle, a new class is created.
func ClassReplace(class Class) error {
	return pkgHandle.ClassReplace(class)
}

// ClassReplace will replace a class to the system.
// quivalent to: `tc class replace $class`
// The handle MAY be changed.
// If a class already exist with this parent/handle pair, the class is changed.
// If a class does not already exist with this parent/handle, a new class is created.
func (h *Handle) ClassReplace(class Class) error {
	return h.classModify(unix.RTM_NEWTCLASS, unix.NLM_F_CREATE, class)
}

// ClassAdd will add a class to the system.
// Equivalent to: `tc class add $class`
func ClassAdd(class Class) error {
	return pkgHandle.ClassAdd(class)
}

// ClassAdd will add a class to the system.
// Equivalent to: `tc class add $class`
func (h *Handle) ClassAdd(class Class) error {
	return h.classModify(
		unix.RTM_NEWTCLASS,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL,
		class,
	)
}

func (h *Handle) classModify(cmd, flags int, class Class) error {
	req := h.newNetlinkRequest(cmd, flags|unix.NLM_F_ACK)
	base := class.Attrs()
	msg := &nl.TcMsg{
		Family:  nl.FAMILY_ALL,
		Ifindex: int32(base.LinkIndex),
		Handle:  base.Handle,
		Parent:  base.Parent,
	}
	req.AddData(msg)

	if cmd != unix.RTM_DELTCLASS {
		if err := classPayload(req, class); err != nil {
			return err
		}
	}
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

func classPayload(req *nl.NetlinkRequest, class Class) error {
	req.AddData(nl.NewRtAttr(nl.TCA_KIND, nl.ZeroTerminated(class.Type())))

	options := nl.NewRtAttr(nl.TCA_OPTIONS, nil)
	switch class.Type() {
	case "htb":
		htb := class.(*HtbClass)
		opt := nl.TcHtbCopt{}
		opt.Buffer = htb.Buffer
		opt.Cbuffer = htb.Cbuffer
		opt.Quantum = htb.Quantum
		opt.Level = htb.Level
		opt.Prio = htb.Prio
		// TODO: Handle Debug properly. For now default to 0
		/* Calculate {R,C}Tab and set Rate and Ceil */
		cellLog := -1
		ccellLog := -1
		linklayer := nl.LINKLAYER_ETHERNET
		mtu := 1600
		var rtab [256]uint32
		var ctab [256]uint32
		tcrate := nl.TcRateSpec{Rate: uint32(htb.Rate)}
		if CalcRtable(&tcrate, rtab[:], cellLog, uint32(mtu), linklayer) < 0 {
			return errors.New("HTB: failed to calculate rate table")
		}
		opt.Rate = tcrate
		tcceil := nl.TcRateSpec{Rate: uint32(htb.Ceil)}
		if CalcRtable(&tcceil, ctab[:], ccellLog, uint32(mtu), linklayer) < 0 {
			return errors.New("HTB: failed to calculate ceil rate table")
		}
		opt.Ceil = tcceil
		options.AddRtAttr(nl.TCA_HTB_PARMS, opt.Serialize())
		options.AddRtAttr(nl.TCA_HTB_RTAB, SerializeRtab(rtab))
		options.AddRtAttr(nl.TCA_HTB_CTAB, SerializeRtab(ctab))
		if htb.Rate >= uint64(1<<32) {
			options.AddRtAttr(nl.TCA_HTB_RATE64, nl.Uint64Attr(htb.Rate))
		}
		if htb.Ceil >= uint64(1<<32) {
			options.AddRtAttr(nl.TCA_HTB_CEIL64, nl.Uint64Attr(htb.Ceil))
		}
	case "hfsc":
		hfsc := class.(*HfscClass)
		opt := nl.HfscCopt{}
		rm1, rd, rm2 := hfsc.Rsc.Attrs()
		opt.Rsc.Set(rm1/8, rd, rm2/8)
		fm1, fd, fm2 := hfsc.Fsc.Attrs()
		opt.Fsc.Set(fm1/8, fd, fm2/8)
		um1, ud, um2 := hfsc.Usc.Attrs()
		opt.Usc.Set(um1/8, ud, um2/8)
		options.AddRtAttr(nl.TCA_HFSC_RSC, nl.SerializeHfscCurve(&opt.Rsc))
		options.AddRtAttr(nl.TCA_HFSC_FSC, nl.SerializeHfscCurve(&opt.Fsc))
		options.AddRtAttr(nl.TCA_HFSC_USC, nl.SerializeHfscCurve(&opt.Usc))
	}
	req.AddData(options)
	return nil
}

// ClassList gets a list of classes in the system.
// Equivalent to: `tc class show`.
// Generally returns nothing if link and parent are not specified.
func ClassList(link Link, parent uint32) ([]Class, error) {
	return pkgHandle.ClassList(link, parent)
}

// ClassList gets a list of classes in the system.
// Equivalent to: `tc class show`.
// Generally returns nothing if link and parent are not specified.
func (h *Handle) ClassList(link Link, parent uint32) ([]Class, error) {
	req := h.newNetlinkRequest(unix.RTM_GETTCLASS, unix.NLM_F_DUMP)
	msg := &nl.TcMsg{
		Family: nl.FAMILY_ALL,
		Parent: parent,
	}
	if link != nil {
		base := link.Attrs()
		h.ensureIndex(base)
		msg.Ifindex = int32(base.Index)
	}
	req.AddData(msg)

	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWTCLASS)
	if err != nil {
		return nil, err
	}

	var res []Class
	for _, m := range msgs {
		msg := nl.DeserializeTcMsg(m)

		attrs, err := nl.ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		base := ClassAttrs{
			LinkIndex:  int(msg.Ifindex),
			Handle:     msg.Handle,
			Parent:     msg.Parent,
			Statistics: nil,
		}

		var class Class
		classType := ""
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case nl.TCA_KIND:
				classType = string(attr.Value[:len(attr.Value)-1])
				switch classType {
				case "htb":
					class = &HtbClass{}
				case "hfsc":
					class = &HfscClass{}
				default:
					class = &GenericClass{ClassType: classType}
				}
			case nl.TCA_OPTIONS:
				switch classType {
				case "htb":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					_, err = parseHtbClassData(class, data)
					if err != nil {
						return nil, err
					}
				case "hfsc":
					data, err := nl.ParseRouteAttr(attr.Value)
					if err != nil {
						return nil, err
					}
					_, err = parseHfscClassData(class, data)
					if err != nil {
						return nil, err
					}
				}
			// For backward compatibility.
			case nl.TCA_STATS:
				base.Statistics, err = parseTcStats(attr.Value)
				if err != nil {
					return nil, err
				}
			case nl.TCA_STATS2:
				base.Statistics, err = parseTcStats2(attr.Value)
				if err != nil {
					return nil, err
				}
			}
		}
		*class.Attrs() = base
		res = append(res, class)
	}

	return res, nil
}

func parseHtbClassData(class Class, data []syscall.NetlinkRouteAttr) (bool, error) {
	htb := class.(*HtbClass)
	detailed := false
	for _, datum := range data {
		switch datum.Attr.Type {
		case nl.TCA_HTB_PARMS:
			opt := nl.DeserializeTcHtbCopt(datum.Value)
			htb.Rate = uint64(opt.Rate.Rate)
			htb.Ceil = uint64(opt.Ceil.Rate)
			htb.Buffer = opt.Buffer
			htb.Cbuffer = opt.Cbuffer
			htb.Quantum = opt.Quantum
			htb.Level = opt.Level
			htb.Prio = opt.Prio
		case nl.TCA_HTB_RATE64:
			htb.Rate = native.Uint64(datum.Value[0:8])
		case nl.TCA_HTB_CEIL64:
			htb.Ceil = native.Uint64(datum.Value[0:8])
		}
	}
	return detailed, nil
}

func parseHfscClassData(class Class, data []syscall.NetlinkRouteAttr) (bool, error) {
	hfsc := class.(*HfscClass)
	detailed := false
	for _, datum := range data {
		m1, d, m2 := nl.DeserializeHfscCurve(datum.Value).Attrs()
		switch datum.Attr.Type {
		case nl.TCA_HFSC_RSC:
			hfsc.Rsc = ServiceCurve{m1: m1 * 8, d: d, m2: m2 * 8}
		case nl.TCA_HFSC_FSC:
			hfsc.Fsc = ServiceCurve{m1: m1 * 8, d: d, m2: m2 * 8}
		case nl.TCA_HFSC_USC:
			hfsc.Usc = ServiceCurve{m1: m1 * 8, d: d, m2: m2 * 8}
		}
	}
	return detailed, nil
}

func parseGnetStats(data []byte, gnetStats interface{}) error {
	buf := &bytes.Buffer{}
	buf.Write(data)
	return binary.Read(buf, native, gnetStats)
}
