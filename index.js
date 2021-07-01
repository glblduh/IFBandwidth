/*

	Made by glblduh
	GitHub: https://github.com/glblduh/WebMonitor

*/

let ifname = "enx00e04c6801e4"; // The name of the interface
let refreshms = 500; // The amount of time to recheck the databuf array (millisecond)

const express = require("express"), http = require("http"), app = express(), server = http.createServer(app), { Server } = require("socket.io"), io = new Server(server);
let pcap = require("pcap"), pcap_session = pcap.createSession(ifname);
let databuf = [];
let sizebuf = 0;

app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html");
});

//Rechecks databuf array to remove old packets and sends data to web
setInterval(() => {
	for(let i=0;i<databuf.length;i++) {
		if (Date.now()-databuf[i].time > 21000) {
			databuf.splice(i, 1);
		}
	}
	databuf = databuf.sort(function(a, b){return b.size - a.size});
	io.emit("databuf", {data: databuf, size: sizebuf});
}, refreshms);

pcap_session.on("packet", rp => {
	//Converts raw packets to Object
	let packet = pcap.decode.packet(rp);
	//Check if addresses are valid and if any value is undefined
	if (packet.payload.payload.saddr != undefined && packet.payload.payload.daddr != undefined && packet.payload.payload.payload != undefined && packet.payload.payload.payload.sport != undefined && packet.payload.payload.payload.dport != undefined && (packet.payload.payload.saddr.addr.join(".").match(/\./g)||[]).length < 4 && (packet.payload.payload.daddr.addr.join(".").match(/\./g)||[]).length < 4) {
		if (!function (){
				//Concatenates size of duplicate packets
				for(let i=0;i<databuf.length;i++) {
					if (databuf[i].saddr === packet.payload.payload.saddr.addr.join(".") && databuf[i].sport === packet.payload.payload.payload.sport && databuf[i].daddr === packet.payload.payload.daddr.addr.join(".") && databuf[i].dport === packet.payload.payload.payload.dport) {
						databuf[i].time = Date.now();
						databuf[i].size += packet.pcap_header.len;
						sizebuf += packet.pcap_header.len;
						return true;
					}
				}
		}()) {
			sizebuf += packet.pcap_header.len;
			//Push source address, source port, destination address, destination port, size of packet to array
			databuf.push(JSON.parse('{"time":'+Date.now()+', "saddr":"'+packet.payload.payload.saddr.addr.join(".")+'", "sport":'+packet.payload.payload.payload.sport+', "daddr":"'+packet.payload.payload.daddr.addr.join(".")+'", "dport":'+packet.payload.payload.payload.dport+', "proto":'+packet.payload.payload.protocol+', "size":'+packet.pcap_header.len+'}'));
		}
	}
});

server.listen(6699);