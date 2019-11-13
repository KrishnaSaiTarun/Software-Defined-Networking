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
		self.arptable = {}
		self.routerip = ["10.0.1.1", "10.0.2.1", "10.0.3.1"]
		self.routing_table = {'10.0.1.0/24': ['10.0.1.100', 's1-eth1', '10.0.1.1', 1], '10.0.2.0/24': ['10.0.2.100', 's1-eth2', '10.0.2.1', 2], '10.0.3.0/24': ['10.0.3.100', 's1-eth3', '10.0.3.1', 3]}
		self.buffer = None

		



	def resend_packet (self, packet_in, out_port):
		"""
		Instructs the switch to resend a packet that it had sent to us.
		"packet_in" is the ofp_packet_in object the switch had sent to the
		controller due to a table-miss.
		"""
		msg = of.ofp_packet_out()
		msg.data = packet_in

		# Add an action to send to the specified port
		action = of.ofp_action_output(port = out_port)
		msg.actions.append(action)

		# Send message to switch
		self.connection.send(msg)


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

			msg = of.ofp_flow_mod()
			
			## Set fields to match received packet
			msg.match = of.ofp_match.from_packet(packet)
			#
			msg.idle_timeout = 30
			msg.hard_timeout = 90
			
			
			#
			act = of.ofp_action_output(port = self.mac_to_port[packet.dst])
			msg.actins.append(act)
			self.connection.send(msg)
			

		else:
			# Flood the packet out everything but the input port
			# This part looks familiar, right?
			log.debug('flooding...')

			self.resend_packet(packet_in, of.OFPP_ALL)

	def  generate_arp_response(self, a, packet_in):
		r = pkt.arp(hwtype = a.hwtype, prototype = a.prototype, hwlen = a.hwlen, protolen = a.protolen, opcode = pkt.arp.REPLY, hwdst = a.hwsrc, protodst = a.protosrc, protosrc = a.protodst, hwsrc = adr.EthAddr('EF:EF:EF:EF:EF:EF'))
				
		e = ethernet(type = pkt.ethernet.ARP_TYPE, src=adr.EthAddr('EF:EF:EF:EF:EF:EF'), dst=a.hwsrc)
		e.payload = r
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		action = of.ofp_action_output(port = packet_in.in_port)
		msg.actions.append(action)
		self.connection.send(msg)
		log.debug('ARP Reply Sent...')



	def upload_arptable(self, packet, packet_in):
		self.arptable[packet.next.protosrc] = packet.src
		log.debug(str(self.arptable))
		 


	def send_arp(self, packet):
		Ip_dst = packet.payload.dstip
		subnet = 0
		for key in self.routing_table.keys():
			if str(Ip_dst) in self.routing_table[key]:
				subnet = key
		self.generate_flow(packet,subnet)

	def send_icmp_packet(self, icmp_reply, packet, packet_in):
	 data = packet.payload
	 ip_packet = pkt.ipv4(srcip = data.dstip, dstip = data.srcip, protocol = pkt.ipv4.ICMP_PROTOCOL, payload = icmp_reply)
	 e_frame = pkt.ethernet(type = pkt.ethernet.IP_TYPE, src = packet.dst, dst=packet.src, payload = ip_packet)
	 message = of.ofp_packet_out()
	 message.data = e_frame.pack()
	 # Add an action to send to the specified port
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

	def send_arp_request(self, port_num, packet, packet_in):

		arp_data = arp(hwlen = 6, hwdst = ETHER_BROADCAST, protodst = packet.payload.dstip, hwsrc = adr.EthAddr('EF:EF:EF:EF:EF:EF'), protosrc = packet.next.srcip)
		arp_data.hwtype = arp_data.HW_TYPE_ETHERNET
		arp_data.prototype = arp_data.PROTO_TYPE_IP
		arp_data.protolen = arp_data.protolen
		arp_data.opcode = arp_data.REQUEST
		e = ethernet(type=ethernet.ARP_TYPE, src=adr.EthAddr('EF:EF:EF:EF:EF:EF'),dst=ETHER_BROADCAST)
		e.set_payload(arp_data)
		message = of.ofp_packet_out()
		message.data = e.pack()
		message.actions.append(of.ofp_action_output(port = port_num))
		message.in_port = packet_in.in_port
		self.connection.send(message)

		log.debug("ARP: request sent")

	def generate_flow(self, packet, network):
		message = of.ofp_packet_out()

		action = of.ofp_action_output(port = self.routing_table[network][3])

		packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')
		packet.dst = self.arptable[packet.payload.dstip]
		message.data = packet.pack()
		message.actions.append(action)
		self.connection.send(message)
		log.debug("ICMP: sent")

		message = of.ofp_flow_mod()
		message.match.nw_dst = packet.payload.dstip
		message.match.dl_type = 0x800
				
		message.actions.append(of.ofp_action_dl_addr.set_src(packet.src))
		message.actions.append(of.ofp_action_dl_addr.set_dst(packet.dst))
		message.actions.append(of.ofp_action_output(port = self.routing_table[network][3]))
		log.debug("Flow Mode install  Successfully")
		self.connection.send(message)

	def send_ipv4(self, network, packet):
		dst_port = self.routing_table[network][3]
		# dst_mac = adr.EthAddr('EF:EF:EF:EF:EF:EF')

		message = of.ofp_packet_out()
		action = of.ofp_action_output(port = dst_port)
		packet.dst = adr.EthAddr('EF:EF:EF:EF:EF:EF')
		packet.src = adr.EthAddr('EF:EF:EF:EF:EF:EF')
				
		message.data = packet.pack()
		message.actions.append(action)
		self.connection.send(message)
		log.debug("IPv4: sent")

					
		message = of.ofp_flow_mod()
		message.match.nw_dst = dst_ip
		message.match.dl_type = 0x800
		message.actions.append(of.ofp_action_dl_addr.set_src(adr.EthAddr('EF:EF:EF:EF:EF:EF')))
		message.actions.append(of.ofp_action_dl_addr.set_dst(adr.EthAddr('EF:EF:EF:EF:EF:EF')))
		message.actions.append(of.ofp_action_output(port = dst_port))
		log.debug("Flow Mode install  Successfully")
		self.connection.send(message)



	
			 
	def act_like_router(self, packet, packet_in):

		if packet.type == pkt.ethernet.ARP_TYPE:
			log.debug('it is an ARP packet...')
			if packet.payload.opcode == arp.REQUEST and packet.payload.protodst in self.routerip:
				log.debug('generate arp reply...')
				self.generate_arp_response(packet.payload, packet_in)
			elif packet.payload.opcode == arp.REPLY:
				log.debug('processing ARP reply...')
				self.upload_arptable(packet, packet_in)
				log.debug('arp table updated...')
				self.send_arp(self.buffer[0])
				self.buffer = None

			else:
				log.debug('error ARP packet')

		if packet.type == pkt.ethernet.IP_TYPE:
			network = 0     
			for key in self.routing_table.keys():
				if packet.payload.dstip.inNetwork(key):
					network = key
					break
			if network == 0:
				log.debug('Destination Network not reachable: Generating ICMP destination unreachable message')
				self.destination_unreachable_icmp(packet, packet_in)

			elif packet.payload.protocol == pkt.ipv4.ICMP_PROTOCOL:
				icmp_data = packet.payload.payload

				if icmp_data.type == pkt.TYPE_ECHO_REQUEST and packet.payload.dstip in self.routerip:
					log.debug('ICMP echo type received')
					self.icmp_echo_reply(icmp_data, packet, packet_in)

				elif packet.payload.dstip not in self.arptable.keys():
					log.debug('Storing packet in buffer')
					self.buffer = (packet,packet_in)
					log.debug('getting port number from routing table')
					port_num = self.routing_table[network][3]
					log.debug('Generating arp request after storing packet in buffer')
					self.send_arp_request(port_num, packet, packet_in)

				elif packet.payload.dstip in self.arptable.keys():
					self.generate_flow(packet, network)

			else:
				log.debug("IPv4: received")

				if network != 0:
					self.send_ipv4(network, packet)
		 
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
		self.act_like_router(packet, packet_in)



def launch ():
	"""
	Starts the component
	"""
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Tutorial(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
