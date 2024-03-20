# Network Traffic Analysis Lab

## Objective

The primary goal of conducting this home lab was to enhance my understanding of Wireshark and its functionalities. Specifically, I aimed to sharpen my skills in utilizing Wireshark for packet analysis by exploring the following key areas such display filters, TCP/TLS streams, and malware detection.

### Skills Learned

- Understanding of tools to utilize in wireshark
- Proficiency in analyzing and interpreting network logs.
- Ability to recognize IoC through traffic analysis.
- Decryption process to view TLS data.
  
### Tools Used

- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Established communication between Metasploitable2 Linux and Kali Linux virtual machines to facilitate packet analysis in Wireshark.
- Utilized Virustotal to analyze malware files.

## Steps

To begin this lab, I booted up a Kali linux vm through VMware Workstation and authenticated with my credentials.

Since wireshark is already installed in Kali linux, I opened up a terminal and typed out the command sudo wireshark. I utilized sudo because wireshark doesn't allow you to capture packets without elavated privilages. It needs elavated privilages because wireshark requires access to the network interface which typically requires elavated permissions. 

Ref 1: Wireshark home page:
![Screenshot (192)](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/3019b282-93dd-4e10-9927-ddd0ad620e0e)
After executnig the command "sudo wireshark", wireshark will open up and I was prompted with these options. I selected the option "eth0" which is the name of my network adapter. To find out the name of your network adapter, you can utilize the ifconfig command and it will prompt you with that information. 

<br>
<br>
<br>

Ref 2 & 3: Wireshark's default columns and preferences window:
![Screenshot 2024-03-20 123215](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/d9806d30-b3ee-43a2-ad7c-cdabc92f315a) <br> ![Screenshot 2024-03-20 122042](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/cd7394f2-9fa4-47bc-9469-b4b353b63416)
Before we start capturing packets, we need to edit our column preferences so we can see two columns: Destination port and Source Port and change our time to a more understanding time. To edit the preferences, hover over "Edit," then go all the way down to "Preferences" and select the "Columns" category. To begin editing, we need to change our Time from default to UTC time so we can know what time that packet was sent. Next, we need to add two columns, which we do by selecting the "+" icon. This allows us to add the columns with the titles "Source Port" and "Destination port." After creating those two columns, we must select the type for each title. We do so by choosing the option "Src port (unresolved)" for Source port and "Dest port (unresolved)" for Destination port. Afterwards, we drag the "Source Port" column underneath "Source" and do the same for the Destination port column, then hit OK.

<br>
<br>
<br>

Ref 4: Updated Wireshark's columns:
![Screenshot 2024-03-20 121139](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/9ab6fabd-f2a2-4f4b-82ed-40218ccd3a66)
As you can see now we can see the Source Port and the destination port as well as understand the time the packet was set in a more understanding time format. This is critical information for a SOC analyst because it provides us with many critical information. It helps determine the type of network traffic because we can associate port 80 with http traffic and port 443 indicates https traffic which allows for quick identification for the type of communication occuring on the network. To add on, it helps with the detection of suspecious activity because unusual or unexpected port usage can indicate potential security threats. For instance, seeing traffic on uncommon ports or ports associated with known vulnerabilities could indicate malicious activity such as port scanning, malware communication, or unauthorized access attempts.

<br>
<br>
<br> Ref 5: Pinging Google:

![ping](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/c326ed65-fd6f-4588-929f-5f9aec10341b) 

To begin, I wanted to ping google.com to observe the information displayed in both the packet list pane and packet details pane for the DNS conversation initiated by the ping.

<br>
<br>

Ref 6: Wireshark output: 
![result](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/785743d7-4ecc-4133-8a92-3e984b3a5bc5)
To begin analyzing the packets, I applied a Display filter to only see DNS information because I pinnged google's public dns server which was 8.8.8.8. What I noticed was my virtual machine (vm) which has a ip address 192.168.68.128 sent out two standard queries to google's DNS server which asks for two record types which are "A" and "AAAA" which translates to asking for google's ipv4 and ipv6 addresses. You can tell because both queries came from my vm's source port of 33366 and sent to google's destination port 53 (DNS). When I analyze the third and fourth packet, those packets are "standard query response" from google.com telling my DNS that google's ipv4 ip address is 142.250.65.206 and ipv6 address is 2607:f8b0:4006:817::200e. You can also tell it was a response because google's servers sent that response from their port 33366 to my DNS's source port 53. 

<br>
<br>
<br>

![Screenshot 2024-03-20 134646](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/ece35682-94e5-4889-87d0-a1f453692c13)

















