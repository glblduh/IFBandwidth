/*

	Made by glblduh
	GitHub: https://github.com/glblduh/WebMonitor

	Arguments:
	-i: To specify interface
	-p: To specify port

*/

const express = require("express"), http = require("http"), app = express(), server = http.createServer(app), { Server } = require("socket.io"), io = new Server(server), argv = require("minimist")(process.argv.splice(2)), dns = require("dns").promises;
if (argv.i == undefined || typeof argv.i === "boolean") {console.error("Please enter a interface name using the -i argument"); process.exit();}
let pcap = require("pcap"), pcap_session = pcap.createSession(argv.i);
let databuf = []; // Buffer of packet information
let sizebuf = 0; // Buffer of the total size of all packets
let rdnscache = []; // Cache of the hostname of ip from reverse dns

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
}, 500);

//Handles the reverse dns and handles rejections
async function reversedns(ip) {
	//Checks hostname cache array
	for(let i=0;i<rdnscache.length;i++) {
		if (rdnscache[i].ip === ip && rdnscache[i].hn != "none") {
			return rdnscache[i].hn;
		} else if(rdnscache[i].ip && rdnscache[i].hn == "none") {
			return ip;
		}
	}
	//Does reverse dns and cache the hostname
	try {
		let hn = await dns.reverse(ip);
		rdnscache.push(JSON.parse('{"ip":"'+ip+'", "hn":"'+hn[0]+'"}'));
		return hn[0];
	} catch(e) {
		rdnscache.push(JSON.parse('{"ip":"'+ip+'", "hn":"none"}'));
		return ip;
	}
}

pcap_session.on("packet", async rp => {
	//Converts raw packets to Object
	let packet = pcap.decode.packet(rp);
	//Check if addresses are valid and if any value is undefined
	if (packet.payload.payload.saddr != undefined && packet.payload.payload.daddr != undefined && packet.payload.payload.payload != undefined && packet.payload.payload.payload != null && packet.payload.payload.payload.sport != undefined && packet.payload.payload.payload.dport != undefined && (packet.payload.payload.saddr.addr.join(".").match(/\./g)||[]).length < 4 && (packet.payload.payload.daddr.addr.join(".").match(/\./g)||[]).length < 4) {
		if (!function(){
				//Concatenates size of duplicate packets
				for(let i=0;i<databuf.length;i++) {
					if (databuf[i].saddr === packet.payload.payload.saddr.addr.join(".") && databuf[i].sport === packet.payload.payload.payload.sport && databuf[i].daddr === packet.payload.payload.daddr.addr.join(".") && databuf[i].dport === packet.payload.payload.payload.dport) {
						databuf[i].time = Date.now();
						databuf[i].size += packet.pcap_header.len;
						return true;
					}
				}
		}()) {
			//Push source address, source port, destination address, destination port, size of packet to array
			databuf.push(JSON.parse('{"time":'+Date.now()+', "saddr":"'+packet.payload.payload.saddr.addr.join(".")+'", "shost":"'+await reversedns(packet.payload.payload.saddr.addr.join("."))+'", "sport":'+packet.payload.payload.payload.sport+', "daddr":"'+packet.payload.payload.daddr.addr.join(".")+'", "dhost":"'+await reversedns(packet.payload.payload.daddr.addr.join("."))+'", "dport":'+packet.payload.payload.payload.dport+', "proto":'+packet.payload.payload.protocol+', "size":'+packet.pcap_header.len+'}'));
		}
		sizebuf += packet.pcap_header.len;
	}
});

server.listen(argv.p || 1010);