/*

	Made by glblduh
	GitHub: https://github.com/glblduh/WebMonitor

*/

let ifname = "enx00e04c6801e4"; // The name of the interface
let buflimit = 20; // The number of packets shown
let bufconca = true; // If true, concatenates size of duplicates (Slow)

const express = require("express"), http = require("http"), app = express(), server = http.createServer(app), { Server } = require("socket.io"), io = new Server(server);
let pcap = require("pcap"), pcap_session = pcap.createSession(ifname);
let databuf = [];

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html");
});

pcap_session.on("packet", rp => {
	//Converts raw packets to Object
	let packet = pcap.decode.packet(rp);
	let saddr, daddr, sport, dport;
	//Check if any value is undefined
	if (packet.payload.payload.saddr != undefined) {
		saddr = packet.payload.payload.saddr.addr.join(".");
	} else {
		saddr = "NULLADDR";
	}
	if (packet.payload.payload.daddr != undefined) {
		daddr = packet.payload.payload.daddr.addr.join(".");
	} else {
		daddr = "NULLADDR";
	}
	if (packet.payload.payload.payload != undefined && packet.payload.payload.payload.sport != undefined && packet.payload.payload.payload.dport != undefined) {
		sport = packet.payload.payload.payload.sport;
		dport = packet.payload.payload.payload.dport;
	} else {
		sport = 0;
		dport = 0;
	}
	//Store to buffer until reach the limit
	if (databuf.length != buflimit) {
		//Check if addresses are valid
		if ((saddr.match(/\./g)||[]).length < 4 && (daddr.match(/\./g)||[]).length < 4) {
			if (!function (){
				if (bufconca) {
					//Concatenates size of duplicate packets
					for(let i=0;i<databuf.length;i++) {
						if (databuf[i].saddr === saddr && databuf[i].sport === sport && databuf[i].daddr === daddr && databuf[i].dport === dport) {
							databuf[i].size += packet.pcap_header.len;
							return true;
						}
					}
				} else {
					return false;
				}
			}()) {
				//Push source address, source port, destination address, destination port, size of packet to array
				databuf.push(JSON.parse('{"saddr":"'+saddr+'", "sport":'+sport+', "daddr":"'+daddr+'", "dport":'+dport+', "size":'+packet.pcap_header.len+'}'));
			}
		}
	} else {
		//Sends array to web
		io.emit("databuf", databuf);
		databuf = [];
	}
});

server.listen(6699);