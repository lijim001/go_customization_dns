package go_customization_dns

import (
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"fmt"
	"bytes"
	"log"
	"time"
	"context"
)

func ErrPanic(err error){
	if err!=nil{
		panic(err)
	}
}

func main(){

	iface,err := net.InterfaceByName("en0")

	if err != nil {
		panic(err)
	}

	addrs,err:=iface.Addrs()

	if err != nil {
		panic(err)
	}
	var ip net.IP

	for _,Addr := range addrs{
		ipnet,_:=Addr.(*net.IPNet)

		if ip =ipnet.IP.To4(); ip!=nil{
			fmt.Println("use ip:",ipnet.IP.String())
			break
		}

	}

	hwaddr:=iface.HardwareAddr
	fmt.Println("hwaddr:",hwaddr)
	println("-----------------------")
	//addr:=addrs[1]
	//fmt.Println("IP:",addr.String())


	handler, err := pcap.OpenLive("en0", 1024, false, pcap.BlockForever)
	ErrPanic(err)
	defer handler.Close()

	context,_:=context.WithTimeout(context.Background(),time.Second*10)

	go sendArp(handler,hwaddr,ip)

	getReply(context,handler,hwaddr,)

}

func sendArp(handler *pcap.Handle,hwaddr net.HardwareAddr,ip net.IP,){

	for i:=1;i<2;i++{
		dstip := "192.168.1."+fmt.Sprintf("%d",i)
		//println("dstIP:",dstip)


		buf:=gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{ComputeChecksums:true,FixLengths:true}

		arp:=layers.ARP{
			AddrType:layers.LinkTypeEthernet,
			Protocol:layers.EthernetTypeIPv4,
			HwAddressSize:6,
			ProtAddressSize:4,
			Operation:layers.ARPRequest,
			SourceHwAddress:[]byte(hwaddr),
			//SourceProtAddress:[]byte(ip),
			SourceProtAddress:[]byte(net.ParseIP("192.168.1.2").To4()),
			DstHwAddress:[]byte{0x0,0x0,0x0,0x0,0x0,0x0},
			DstProtAddress:[]byte(net.ParseIP(dstip).To4()),
		}

		err := arp.SerializeTo(buf, opts)
		ErrPanic(err)

		ether:=layers.Ethernet{
			SrcMAC:       hwaddr,
			DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			EthernetType: layers.EthernetTypeARP,
		}

		err = ether.SerializeTo(buf, opts)
		ErrPanic(err)

		err=handler.WritePacketData(buf.Bytes())
		ErrPanic(err)

	}

}

func getReply(ctx context.Context,handler *pcap.Handle,myaddr net.HardwareAddr){
	src := gopacket.NewPacketSource(handler, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-ctx.Done():
			return
		case packet = <- in:
			arpLayer:=packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(myaddr), arp.SourceHwAddress) {
				continue
			}
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
		}

	}

}