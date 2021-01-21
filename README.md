:: DNStap Reader

dnstap_reader contains developing software for read dnstap data (from file or socket)

What is it dnstap? 

Read this :

# DNS Logging 
_(from https://www.vanimpe.eu/2018/12/27/dnstap-for-improved-dns-logging-on-ubuntu/)_

DNS logging and monitoring is important! Monitoring DNS logs allows you to analyze and detect C&C traffic and have access to crucial information to reduce the dwell time and detect breaches. Combined with Passive DNS it’s a very valuable data source to be used during incident response.

But DNS logging comes at a price. Every log operation requires the system to write out an entry to disk (besides also properly formatting the log string). This is a slow I/O-operation and limits the maximum amount of queries that your system can answer. A graph (https://www.vanimpe.eu/wp-content/uploads/2018/12/bind9-300x236.jpg) from a presentation from Farsight Security shows the difference of running BIND9 with or without query logging.

![graph] (https://www.vanimpe.eu/wp-content/uploads/2018/12/bind9-300x236.jpg)

Another way of capturing DNS logs is via packet capture. This is a good solution if you do not have direct access to the DNS server. If you manage the DNS server then doing packet capture is not the most efficient solution though. Packet capture is in essence re-doing the same stuff as the things your DNS server is already doing, for example packet reassembly and session management. Although this approach makes it more difficult to tie individual responses to queries, as default query logging doesn’t log the responses it’s your best best to keep track of the DNS answers (for example via Bro) based on your traffic.

All this will probably not be a big issue in smaller environments but if you scale up there will be a time when you hit the system limits. Does this mean you should then give up on DNS logging? Not at all!

# Dnstap

An alternative to DNS query logging is dnstap. Dnstap is a flexible, structured binary log format for DNS software that uses Protocol Buffers to encode events in an implementation-neutral format. Dnstap exists for most open source DNS servers as Bind, Knot and Unbound. The major advantage of Dnstap is demonstrated via its architecture schema.

![schema] (https://www.vanimpe.eu/wp-content/uploads/2018/12/512x378-dnstap-300x221.png)

The encoding of events and writing to disk happens outside the DNS handling system on a “copy” of the DNS message. This means that slow disk performance during log operations will have less of a negative impact on the system as a whole. The generation of the messages is done from within the DNS handling system, meaning that all relevant DNS information can be included and does not need to be reconstructed from observing the traffic.

Speed isn’t the only advantage of dnstap. In case of a very high load or peak, the system can start dropping the log messages but still process the queries. Additionally, the logged information contains all the details of the request making it a treasure-cave for future research.
