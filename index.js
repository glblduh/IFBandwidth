/*

	Made by glblduh
	GitHub: https://github.com/glblduh/WebMonitor

*/

let ifname = "enx00e04c6801e4"; // The name of the interface
let buflimit = 30; // The number of packets shown

const express = require("express"), http = require("http"), app = express(), server = http.createServer(app), { Server } = require("socket.io"), io = new Server(server);
let pcap = require("pcap"), pcap_session = pcap.createSession(ifname);
let databuf = [];

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html");
});

pcap_session.on("packet", rp => {
	//Converts raw packets to Object
	let packet = pcap.decode.packet(rp);
	//Store to buffer until reach the limit
	if (databuf.length != buflimit) {
		//Check if addresses are valid and if any value is undefined
		if (packet.payload.payload.saddr != undefined && packet.payload.payload.daddr != undefined && packet.payload.payload.payload != undefined && packet.payload.payload.payload.sport != undefined && packet.payload.payload.payload.dport != undefined && (packet.payload.payload.saddr.addr.join(".").match(/\./g)||[]).length < 4 && (packet.payload.payload.daddr.addr.join(".").match(/\./g)||[]).length < 4) {
			if (!function (){
					//Concatenates size of duplicate packets
					for(let i=0;i<databuf.length;i++) {
						if (databuf[i].saddr === packet.payload.payload.saddr.addr.join(".") && databuf[i].sport === packet.payload.payload.payload.sport && databuf[i].daddr === packet.payload.payload.daddr.addr.join(".") && databuf[i].dport === packet.payload.payload.payload.dport) {
							databuf[i].size += packet.pcap_header.len;
							return true;
						}
					}
			}()) {
				//Push source address, source port, destination address, destination port, size of packet to array
				databuf.push(JSON.parse('{"saddr":"'+packet.payload.payload.saddr.addr.join(".")+'", "sport":'+packet.payload.payload.payload.sport+', "daddr":"'+packet.payload.payload.daddr.addr.join(".")+'", "dport":'+packet.payload.payload.payload.dport+', "proto":'+packet.payload.payload.protocol+', "size":'+packet.pcap_header.len+'}'));
			}
		}
	} else {
		//Sends array to web
		io.emit("databuf", databuf);
		databuf = [];
	}
});

server.listen(6699);