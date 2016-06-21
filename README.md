# DiffProbe

End-to-end traffic discrimination detection tool.

The goal of DiffProbe is to detect if an ISP is classifying certain kinds of traffic as "low priority", providing different levels of service for them. DiffProbe actively (and non-intrusively) probes the network path and tries to diagnose the nature and extent of traffic discrimination:
Has the ISP deployed priority-based scheduling mechanisms such as priority queueing or weighted fair queueing (as opposed to treating all traffic as equal)?
Is the ISP doing discriminatory buffer management, or in other words, preferential dropping of packets from different flows?
Is the ISP rate-limiting certain types of traffic?
These practices are commonly considered to be net neutrality violations by ISPs.

Functionality:
Diffprobe currently detects the following traffic discrimination mechanisms:
- Traffic Shaping / Rate-limiting: We detect token bucket traffic shapers, and characterize the shaping (token) rate and burst size (bucket depth) - and compare it with the path (access-link) capacity.
- Delay discrimination: We detect if a given application's traffic is being delayed compared to other traffic. Examples of delay discrimination practices include Strict Priority and Weighted Fair Queueing - compared to First Come First Served scheduling across all traffic.
- Loss discrimination: We detect if a given application's traffic is being dropped more, on an average, compared to other traffic. Examples of loss discrimination practices include Weighted Random Early Detect and drop-from-longest-queue policies - compared to drop-tail across all traffic.

Sample Output:
The following is an example output, not taken from any particular ISP:
./prober -a 2
DiffProbe alpha release. April 2009.

Using tracefile skype-upstream.pcap.
Using device: eth0.
sleep time resolution: 1.99 ms.
Connected to server 123.231.123.231.

Estimating capacity:
 Upstream: 10800.39 Kbps.
 Downstream: 37127.07 Kbps.

Checking for traffic shapers:
 Upstream: Burst size: 5402 KB; Shaping rate: 1008.00 Kbps.
 Downstream: No shaper detected.

*** Upstream *** 
 ......
 sending measurement data to server..done.
 Analyzing measurements.

 Results:
 --------
 Delay discrimination:
 Delay discrimination detected.
 Application traffic classified low priority: delay between flows: 6.24 ms.

 Loss discrimination:
 No loss discrimination detected.

*** Downstream *** 
 ......
 sending measurement data to server..done.
 Analyzing measurements.

 Results:
 --------
 Delay discrimination:
 No delay discrimination detected.

 Loss discrimination:
 Not detectable.

For more information, visit: http://www.cc.gatech.edu/~partha/diffprobe

The first few lines show some pre-processing by DiffProbe. The tool estimates the path's capacity next. This is followed by detecting of traffic shaping on the path in both upstream and downstream directions. Diffprobe then tries to detect delay and loss discrimination on the selected application (Skype or Vonage), when compared to other traffic.

Output messages:
- Burst size: ...; Shaping rate: ...: This quantifies the rate-limiting (if any) done by the ISP at the time of measurement. Shaping rate is the rate-limiting rate.
- ... discrimination detected.: This means that the selected application has been discriminated against or towards, in terms of delay or loss, at the time of measurement. A following line (if any) describes the extent of discrimination.
- Not detectable.: This is specific to the time when the measurement was made. In the context of delays, this means that the traffic on the path was not large enough to infer delay discrimination. In the context of losses, this means that there were no losses or that the loss rate was too small to infer loss discrimination.
