package nmapxml

import (
	"encoding/xml"
	"fmt"
)

type NmapXML struct {
	Args  string `xml:"args,attr"`
	Start string `xml:"start,attr"`
	Hosts []host `xml:"host"`
}

type host struct {
	Status  status  `xml:"status"`
	Address address `xml:"address"`
	Ports   []port  `xml:"ports>port"`
}

type status struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type state struct {
	State string `xml:"state,attr"`
}

type port struct {
	Protocol string    `xml:"protocol,attr"`
	ID       string    `xml:"portid,attr"`
	State    state     `xml:"state"`
	Service  service   `xml:"service"`
	Script   []scripts `xml:"script"`
}

type service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OStype    string `xml:"ostype,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
	CPE       string `xml:"cpe"`
}

type scripts struct {
	ID               string   `xml:"id,attr"`
	Output           string   `xml:"output,attr"`
	SupportedMethods []string `xml:"table>elem"`
}

func Parse(data *[]byte) (NmapXML, error) {
	var nmapRun NmapXML
	if data == nil {
		return nmapRun, fmt.Errorf("nil data provided")
	}
	if len(*data) == 0 {
		return nmapRun, fmt.Errorf("empty data provided")
	}

	err := xml.Unmarshal(*data, &nmapRun)
	if err != nil {
		return nmapRun, fmt.Errorf("failed to parse XML: %v", err)
	}

	return nmapRun, nil
}
