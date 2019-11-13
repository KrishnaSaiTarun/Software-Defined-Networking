# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""



from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp

log = core.getLogger()



class Tutorial (object):
	"""
	A Tutorial object is created for each switch that connects.
	A Connection object for that switch is passed to the __init__ function.
	"""
	def __init__ (self, connection):
		# Keep track of the connection to the switch so that we can
		# send it messages!
		self.connection = connection

		# This binds our PacketIn event listener
		connection.addListeners(self)

		# Use this table to keep track of which ethernet address is on
		# which switch port (keys are MACs, values are ports).
		self.mac_to_port = {}
		self.arpTable = {}
		self.all_ip_table = {1:["10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.2.1", "10.0.2.2"], 2:["10.0.1.1", "10.0.2.1"]}
		self.direct_link = dict()
		self.direct_link[1] = ['10.0.1.2', '10.0.1.3', '10.0.2.1']
		self.direct_link[2] = ['10.0.2.2', '10.0.1.1']
		self.routing_table = dict()
		self.routing_table[1] = {'10.0.1.2': ['10.0.1.2', 's1-eth1', '10.0.1.1', 1], '10.0.1.3': ['10.0.1.3', 's1-eth2', '10.0.1.1', 2], '10.0.2.1': ['10.0.2.1', 's1-eth3', '10.0.1.1', 3], '10.0.2.2': ['10.0.2.1', 's1-eth3', '10.0.1.1', 3]}
		self.routing_table[2] = {'10.0.2.2': ['10.0.2.2', 's2-eth1', '10.0.2.1', 1],'10.0.1.1': ['10.0.2.2', 's2-eth2', '10.0.2.1', 2],'10.0.1.2': ['10.0.1.1', 's2-eth2', '10.0.2.1', 2],'10.0.1.3': ['10.0.1.1', 's2-eth2', '10.0.2.1', 2]}
		self.buffer = None
	

	
	def resend_packet (self, packet_in, out_port):
		"""
		Instructs the switch to resend a packet that it had sent to us.
		"packet_in" is the ofp_packet_in object the switch had sent to the
		controller due to a table-miss.
		"""
		message = of.ofp_packet_out()
		message.data = packet_in

		# Add an action to send to the specified port
		action = of.ofp_action_output(port = out_port)
		message.actions.append(action)

		# Send message to switch
		self.connection.send(message)


	def act_like_hub (self, packet, packet_in):
		"""
		Implement hub-like behavior -- send all packets to all ports besides
		the input port.
		"""

		# We want to output to all ports -- we do that using the special
		# OFPP_ALL port as the output port.  (We could have also used
		# OFPP_FLOOD.)
		self.resend_packet(packet_in, of.OFPP_ALL)

		# Note that if we didn't get a valid buffer_id, a slightly better
		# implementation would check that we got the full data before
		# sending it (len(packet_in.data) should be == packet_in.total_len)).


	def act_like_switch (self, packet, packet_in):
		"""
		Implement switch-like behavior.
		"""

		if packet.src not in self.mac_to_port:
			

		# Here's some psuedocode to start you off implementing a learning
		# switch.  You'll need to rewrite it as real Python code.

		# Learn the port for the source MAC
			self.mac_to_port[packet.src] = packet_in.in_port
			log.debug("mapping unknown mac address to port number...") 

		if packet.dst in self.mac_to_port:
			# Send packet out the associated port
			self.resend_packet(packet_in,self.mac_to_port[packet.dst])

			# Once you have the above working, try pushing a flow entry
			# instead of resending the packet (comment out the above and
			# uncomment and complete the below.)

			log.debug("Installing flow...")
			
		 
		 
			# Maybe the log statement should have source/destination/port?

			message = of.ofp_flow_mod()
			
			## Set fields to match received packet
			message.match = of.ofp_match.from_packet(packet)
			#
			message.idle_timeout = 30
			message.hard_timeout = 90
			
			
			#
			act = of.ofp_action_output(port = self.mac_to_port[packet.dst])
			message.actins.append(act)
			self.connection.send(message)
			

		else:
			# Flood the packet out everything but the input port
			# This part looks familiar, right?
			log.debug('flooding...')

			self.resend_packet(packet_in, of.OFPP_ALL)


	def  generate_arp_response(self, a, packet_in,dpid):
		r = pkt.arp(hwtype = a.hwtype, prototype = a.prototype, hwlen = a.hwlen, protolen = a.protolen, opcode = pkt.arp.REPLY, hwdst = a.hwsrc, protodst = a.protosrc, protosrc = a.protodst, hwsrc = adr.EthAddr('EF:EF:EF:EF:EF:EF'))
		e = ethernet(type = pkt.ethernet.ARP_TYPE, src = adr.EthAddr('EF:EF:EF:EF:EF:EF'), dst=a.hwsrc, payload = r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port = packet_in.in_port))
		log.debug(" answering for arp from %s: MAC for %s is %s", str(a.protosrc), str(r.protosrc), str(r.hwsrc))
		self.connection.send(msg)
		log.debug('ARP Reply Sent...')



	def upload_arpTable(self, packet, packet_in):
		self.arpTable[packet.next.protosrc] = packet.src
		log.debug(str(self.arpTable))
		 


	def send_arp(self, packet, dpid):
		Ip_dst = packet.payload.dstip
		port_num = self.routing_table[dpid][str(Ip_dst)][3]
		#generating flow
		self.send_packet(packet, dpid)

	def send_icmp_packet(self, icmp_reply, packet, packet_in):
	 data = packet.payload
	 ip_packet = pkt.ipv4(srcip = data.dstip, dstip = data.srcip, protocol = pkt.ipv4.ICMP_PROTOCOL, payload = icmp_reply)
	 e_frame = ethernet(type = pkt.ethernet.IP_TYPE, src = packet.dst, dst=packet.src, payload = ip_packet)
	 message = of.ofp_packet_out()
	 message.data = e_frame.pack()
	 message.actions.append(of.ofp_action_output(port = packet_in.in_port))
	 # Send message to switch
	 self.connection.send(message)
	 log.debug("ICMP: reply sent")

	def destination_unreachable_icmp(self, packet, packet_in):        
		data = packet.payload
		log.debug("ICMP: destination unreachable")
		dst_unreach = pkt.unreach()
		dst_unreach.payload = data
		icmp_reply = pkt.icmp()
		icmp_reply.type = pkt.TYPE_DEST_UNREACH
		icmp_reply.payload = dst_unreach

		self.send_icmp_packet(icmp_reply, packet, packet_in)



	def icmp_echo_reply(self, icmp_data, packet, packet_in):
		log.debug("ICMP: router get request")

		icmp_echo = pkt.echo(seq = icmp_data.payload.seq + 1, id = icmp_data.payload.id)
		icmp_reply = pkt.icmp(type = pkt.TYPE_ECHO_REPLY, payload = icmp_echo)
		self.send_icmp_packet(icmp_reply, packet, packet_in)




	def send_arp_request(self, port_num, packet, packet_in, dpid):
		arp_data = arp(hwdst = ETHER_BROADCAST, hwlen = 6, protodst = packet.payload.dstip, hwsrc = adr.EthAddr('EF:EF:EF:EF:EF:EF'), protosrc = adr.IPAddr(self.routing_table[dpid][str(packet.payload.dstip)][2]))
		arp_data.hwtype = arp_data.HW_TYPE_ETHERNET
		arp_data.prototype = arp_data.PROTO_TYPE_IP
		arp_data.protolen = arp_data.protolen
		arp_data.opcode = arp_data.REQUEST
		e = ethernet(type=ethernet.ARP_TYPE, src=adr.EthAddr('EF:EF:EF:EF:EF:EF'), dst=ETHER_BROADCAST)
		e.set_payload(arp_data)
		message = of.ofp_packet_out()
		message.data = e.pack()
		message.actions.append(of.ofp_action_output(port = port_num))
		message.in_port = packet_in.in_port
		self.connection.send(message)

		log.debug("ARP: request sent")

	def send_packet(self, packet, dpid):
		port_num = self.routing_table[dpid][str(packet.payload.dstip)][3]

		message = of.ofp_packet_out()
		action = of.ofp_action_output(port = port_num)

		packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')
		packet.dst = self.arpTable[packet.payload.dstip]
		message.data = packet.pack()
		message.actions.append(action)
		self.connection.send(message)
		log.debug("IPv4: sent")


	def send_packet_broadcast(self, port_num, packet, dpid):
		message = of.ofp_packet_out()
		action = of.ofp_action_output(port = port_num)
		packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')
		packet.dst = ETHER_BROADCAST
		message.data = packet.pack()
		message.actions.append(action)
		self.connection.send(message)
		log.debug("IPv4: sent")
			 
	def act_like_router(self, packet, packet_in, dpid):
		if packet.type == pkt.ethernet.ARP_TYPE:
			log.debug('it is an ARP packet...')
			log.debug('protodst is %s' , str(packet.payload.protodst) )
			if packet.payload.opcode == arp.REQUEST and packet.payload.protodst in self.all_ip_table[2]:
				log.debug('generate arp reply...')
				self.generate_arp_response(packet.payload, packet_in, dpid)
				log.debug('arp reply done')
			elif packet.payload.opcode == arp.REPLY and packet.payload.protodst in self.all_ip_table[2]:
				log.debug('processing ARP reply...')
				self.upload_arpTable(packet, packet_in)
				log.debug('arp table updated...')
				self.send_arp(self.buffer[0],dpid)
				self.buffer = None
			elif packet.payload.protodst in self.all_ip_table[1]:
				log.debug("ARP: trasfer request start")
				port_no = self.routing_table[dpid][str(packet.payload.protodst)][3]
				msg = of.ofp_packet_out()
				msg.data = packet.pack()
				action = of.ofp_action_output(port = port_no)
				msg.actions.append(action)
				self.connection.send(msg)
				log.debug("ARP: trasfer request sent")

			else:
				log.debug('error ARP packet')

		if packet.type == pkt.ethernet.IP_TYPE:
			log.debug('It is a IP pkt')
			if packet.payload.dstip not in self.all_ip_table[1]:
				log.debug('Destination Network not reachable: Generating ICMP destination unreachable message')
				self.destination_unreachable_icmp(packet, packet_in)

			elif packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL and packet.payload.payload.type == pkt.TYPE_ECHO_REQUEST and str(packet.payload.dstip) == self.all_ip_table[2][dpid - 1]:
				icmp_data = packet.payload.payload
				log.debug('ICMP echo type received, and IP address valid in the network')
				self.icmp_echo_reply(icmp_data, packet, packet_in)

			elif packet.payload.dstip in self.direct_link[dpid]:
				log.debug("...")
				port_num = self.routing_table[dpid][str(packet.payload.dstip)][3]
				if packet.payload.dstip not in self.arpTable.keys():
					log.debug('Storing packet in buffer')
					self.buffer = (packet,packet_in)
					
					log.debug('Generating arp request after storing packet in buffer')
					self.send_arp_request(port_num, packet, packet_in, dpid)

				elif packet.payload.dstip in self.arpTable.keys():
					self.send_packet(packet,dpid)

			else:
				log.debug("The packet goes to next hop")
				next_hop_ip = self.routing_table[dpid][str(packet.payload.dstip)][0]
				port_num = self.routing_table[dpid][str(packet.payload.dstip)][3]
				self.send_packet_broadcast(port_num, packet, dpid)


		 
	def _handle_PacketIn (self, event):
		packet = event.parsed # This is the parsed packet data.
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return

		packet_in = event.ofp # The actual ofp_packet_in message.

		# Comment out the following line and uncomment the one after
		# when starting the exercise.
		#self.act_like_hub(packet, packet_in)
		#self.act_like_switch(packet, packet_in)
		self.act_like_router(packet, packet_in, event.connection.dpid)



def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Tutorial(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
