/*

	Made by glblduh
	GitHub: https://github.com/glblduh/WebMonitor

	Arguments:
	-i: To specify interface
	-p: To specify port
	--auth: To enable authentication (username:password)

*/

const express = require("express"), http = require("http"), app = express(), server = http.createServer(app), { Server } = require("socket.io"), io = new Server(server), argv = require("minimist")(process.argv.splice(2)), dns = require("dns").promises, basicAuth = require("express-basic-auth");
if (argv.i == undefined || typeof argv.i === "boolean") {console.error("Please enter a interface name using the -i argument"); process.exit();}
let pcap = require("pcap"), pcap_session = pcap.createSession(argv.i);
let databuf = []; // Buffer of packet information
let sizebuf = 0; // Buffer of the total size of all packets
let siokey = "webmonitordefaultkey"; // SocketIO authed room key

// Checks if -auth argument is present and checks if value is valid
if (argv.auth != undefined && typeof argv.auth === "string") {
	let cred = argv.auth.split(":");
	app.use(basicAuth({
		users: {[cred[0]]: cred[1]},
		challenge: true
	}));
}

// Authenticate the client based on the siokey variable
io.on("connection", socket => {
	socket.on("auth", key => {
		if (key === siokey) {
			socket.join("authed");
			socket.emit("initinfo", {ifname: argv.i});
		}
	});
});

// Server index.html to client
app.get("/", (req, res) => {
	res.sendFile(__dirname + "/index.html");
});

//Checks the databuf for non-resolved addresses and tries to resolve it
setInterval(async () => {
	if (databuf.length > 1) {
		for(let i=0;i<databuf.length;i++) {
			if (databuf[i].shost === "") {
				try {
					databuf[i].shost = (await dns.reverse(databuf[i].saddr))[0];
				} catch(e) {
					databuf[i].shost = databuf[i].saddr;
				}
			}
			if (databuf[i].dhost === "") {
				try {
					databuf[i].dhost = (await dns.reverse(databuf[i].daddr))[0];
				} catch(e) {
					databuf[i].dhost = databuf[i].daddr;
				}
			}
		}
	}
}, 100);

//Rechecks databuf array to remove old packets and sends data to web
setInterval(() => {
	if (databuf.length > 1) {
		for(let i=0;i<databuf.length;i++) {
			if (Date.now()-databuf[i].time > 21000) {
				databuf.splice(i, 1);
			}
		}
		databuf = databuf.sort(function(a, b){return b.size - a.size});
		io.in("authed").emit("databuf", {data: databuf, size: sizebuf});
	}
}, 500);

pcap_session.on("packet", rp => {
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
			databuf.push(JSON.parse('{"time":'+Date.now()+', "saddr":"'+packet.payload.payload.saddr.addr.join(".")+'", "shost":"", "sport":'+packet.payload.payload.payload.sport+', "daddr":"'+packet.payload.payload.daddr.addr.join(".")+'", "dhost":"", "dport":'+packet.payload.payload.payload.dport+', "proto":'+packet.payload.payload.protocol+', "size":'+packet.pcap_header.len+'}'));
		}
		sizebuf += packet.pcap_header.len;
	}
});

// Start the http server to listen on port
server.listen(argv.p || 1010);