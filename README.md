# Network Traffic Analysis Project

## Objective

The primary goal of conducting this project is to enhance my understanding of Wireshark and its functionalities. Specifically, I aimed to sharpen my skills in utilizing Wireshark for packet analysis by exploring the following key areas such display filters, TCP/TLS streams, and malware detection.

### Skills Learned

- Understanding of tools to utilize in wireshark
- Proficiency in analyzing and interpreting network logs.
- Ability to recognize IoC through traffic analysis.
- Decryption process to view malicous TLS data.
  
### Tools Used

- Wireshark.
- Metasploitable2 Linux and Kali Linux.
- Virustotal.

## Steps

To begin this project, I booted up a Kali linux vm through VMware Workstation and authenticated with my credentials.

Since wireshark is already installed in Kali linux, I opened up a terminal and typed out the command sudo wireshark. I utilized sudo because wireshark doesn't allow you to capture packets without elavated privilages. It needs elavated privilages because wireshark requires access to the network interface which typically requires elavated permissions. 

Ref 1: Wireshark home page:
![Screenshot (192)](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/3019b282-93dd-4e10-9927-ddd0ad620e0e)
After executing the command "sudo wireshark", wireshark will open up and I was prompted with these options. I selected the option "eth0" which is the name of my network adapter. To find out the name of your network adapter, you can utilize the ifconfig command and it will prompt you with that information. 

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

Ref 7: Establishing FTP Connection to Metaspoitable2:
![Screenshot 2024-03-20 134646](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/ece35682-94e5-4889-87d0-a1f453692c13)
Next, I will analyze the traffic that goes towards the Metaspoitable2 machine when I authenticate in the clear and see the process in Wireshark.

<br>
<br>
<br>

Ref 8 & 9: Wireshark FTP authentication capture and TCP stream:
![Screenshot 2024-03-18 204151](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/2abde1f8-3741-4f59-845a-a37a2a4631ca)
![Screenshot 2024-03-18 205148](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/603920ac-c739-42e5-a20d-e23262c1bd60)
Looking at the authentication process packet by packet through wireshark, it shows how important it is to authenticate through an encrypted tunnel such as using SFTP or FTPS. As you can see since I only authenticated via FTP, I was able to clearly see the authentication details  when I follow the TCP stream. Looking at the TCP stream, sometimes the data can be a litle hard to see such as the username. The data shows multiple letters but if you look on Ref 8, you can see the username clear as day.

<br>
<br>
<br>

Ref 10: Viewing a pcap file for malware analysis:
![Screenshot 2024-03-18 212245](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/a1b5e130-6552-40ca-bbf5-2b2b929b78b6)
Scenario: I am working as a Cybersecurity Analyst on the blueteam and I was tasked to analyze this pcap file from my supervisor because a user's computer in the finances department got infected with malware and they need to know what happend. To analyze pcap files with wireshark, I don't need sudo privilages because sudo is only for when I need to capture packets. This time I will be analzying a packet capture that was already captured. First I will conduct changes to the time and column preferences just like I did in Ref 3. 

<br>
<br>


Ref 11 & 12: Utilizing display filter:
![tlshandshake](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/8fefe737-c9fa-4c2b-8ecf-0c7b5e202716)
As an analyst, my initial approach to analyzing the pcap file involves utilizing display filters, specifically "tls.handshake.type eq 1". This filter targets 'ClientHello' messages, marking the inception of the TLS handshake process, which establishes secure communication between a client and server. This step is crucial as TLS is commonly employed to secure various network communications, such as web browsing and email. Filtering for TLS handshake messages aids in uncovering potential malicious activities concealed within encrypted traffic, particularly if the malware utilized secure connections.

Ref 13: TCP stream:
![encrypted tcp stream](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/ae87cfe3-f2ae-42d5-8e5f-f6f94aa2d452)
Looking at the TCP stream, there isn't much information you can see because all the information is encrypted due to the SSL certificate in place. So to view this TCP stream I will need the SSL keys to decrypt the data.

<br>
<br>


Ref 13: TLS decryption Process:
![Screenshot 2024-03-18 213223](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/66f1cd32-6b45-470d-9c2f-f956454d3624)

Let's say I recieved the decryption keys to be able to view this data. To utilize the decryption key into wireshark, I selected the "edit" icon then I clicked on "preferences". Once I'm in the preferences window, I typed "TLS" to filter that I only want to decrypt TLS traffic, then where it says "(Pre)-Master-Secret log filename", I will insert the .txt file that holds the decryption keys to analyze the traffic. 

<br>
<br>
<br>

Ref 14: TLS stream:
![POST](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/6f988a92-39ad-4d80-a440-cf732074a90b)
Now that some of the data is decrypted, we can see there was a POST request that was sent from the computer to a third party server. To add a litle bit of background, a POST request is one of the HTTP (Hypertext Transfer Protocol) methods used for sending data to a server to create or update a resource. In a POST request, the client sends data in the request body to the server, typically to submit form data or upload a file. This is crutial information as a analyst because POST requests often involve the transmission of sensitive information, such as personally identifiable information (PII), login credentials, or financial data. Monitoring and analyzing POST requests  can help detect potential data leakage incidents, such as inadvertent exposure of confidential information or unauthorized data exfiltration by malicious actors.

<br>
<br>
<br>

Ref 15: Taking advantage of display filter:
![Screenshot 2024-03-18 220441](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/e37a14ce-5f6b-49dc-bb74-88e00d018809)
Now that we know a POST request was made via HTTP, we can utilize the display filter to specifically find the packets that were involved in this event. In the filter I wrote '(http.request or tls.handshake.type eq 1) and !(ssdp)'. To explain this display filter: since we know there was an HTTP request made, I included 'http.request'. I utilized the 'or' logical operator, which means either this condition or the other condition, and I wrote 'tls.handshake.type eq 1' because that condition filters for packets that are part of TLS (Transport Layer Security) handshakes and have a handshake type equal to 1. In TLS, handshake type 1 corresponds to 'ClientHello' messages, which are the initial messages sent by clients to initiate a TLS handshake with a server. As for 'and', this means I want to add another condition to the filter. '!' represents the NOT operator, which means to negate a condition. Now, for SSDP, this condition filters for packets related to the Simple Service Discovery Protocol (SSDP), which is used for discovering network services. We want to exclude those types of packets because SSDP is used for discovering network services, such as printers, media servers, or smart devices, within a local network. For our scenario, we want to exclude that type of traffic because SSDP traffic is not relevant to the analysis objective.

<br>
<br>
<br>

Ref 16: Suspicious GET request:
![Screenshot 2024-03-21 100513](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/c763aebc-1963-4f10-bc5a-e4309cbb823d)
Taking a closer look at the results from the display filter, I can see that there was a interesting packet that is requesting a "GET / invest_20.dll. DLL also known as dynamic link library is a file that contains a collection of functions and data that can be used by multiple programs simultaneously. Instead of each program having its own copy of these functions and data, they can all share the same DLL file. "GET" is the HTTP method used in the request. It indicates that the client (such as a web browser or another program) is requesting data from the server. Combining these two together, we can assume the client is asking the server to provide the content of the "invest_20.dll" file. This typically occurs in the context of web browsing or web-based applications where the client (a web browser) sends an HTTP request to the server to retrieve a specific resource, in this case, a DLL file.

<br>
<br>
<br>

Ref 17: Following the HTTP stream:
![GET](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/456ecee7-3e97-4c50-bbed-9d271c52e194)
Since this GET request is coming from HTTP, we can follow the HTTP stream to get a better understanding of what's happening. Looking at the HTTP stream we can see see the GET request being made from the red text, and we can see the server approving that request by saying "HTTP/1.1 200 OK. Everything else after that the actual dll. As a threat hunter or malware analyst, my next step is to download the contents within the dll as a dll file and then analyze it through a utility such a virustotal.

<br>
<br>
<br>

Ref 18: Exporting dll packet:
![Screenshot 2024-03-18 215516](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/0860813f-f290-490e-96cb-808628c0d7b9)
The next thing I would want to do is to analyze this dll packet. The really cool thing about wireshark is it allows you to export specific packets which is super helpful because I can save the file and open up the file in virustotal to learn more about it. 

<br>
<br>
<br>

Ref 19: Virustotal general information:
![Screenshot 2024-03-18 215743](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/20bb4b22-996d-4fb1-a230-107668623a6f)
We are dealing with a malware called the Drydex malware. Drydex is a sophisticated banking trojan that primarily targets Windows users. It spreads through phishing emails and malicious attachments, aiming to steal sensitive financial information such as banking credentials and personal data. Once this malware is installed on a victim's computer, Drydex can silently capture login credentials, perform fraudulent transactions, and even download additional malware. Looking at the information provided from VirusTotal, the detection ratio score is 57/71. This means 57 out of 71 security vendors that perform vulnerability scans flagged this .dll file as malicious. We can also see that the common file size for this malicious DLL file is 453.00 KB, which is an extremely small file size. This small file size can indicate why 100% of the security vendors didn't identify the file as malicious.

<br>
<br>

Ref 20: Common file name:

![file type](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/037f465c-12d6-400a-bda9-f01be5cf5359)

Looking at the data provided from VirusTotal, the Drydex malware can come in three file types. It can come in a zipfile called invest_20.zip, which is the file type that the victim in our scenario opened. Other names include invoice.doc and investments.doc, which are Office Open XML documents. For the XML document file type, the malware is triggered when the victim opens the .doc file extension, running a malicious script embedded within the document.

<br>
<br>

Conclusion:
In conclusion, I can report to my supervisor that the user who got infected with the malware downloaded a malware called the Drydex malware, and it was a zip file called invest_20.zip that triggered it. They most likely downloaded and received the zip file contents through email, which led them to download an Excel document. They opened it with Excel and executed a macro, which then executed code to download a malicious DLL, subsequently infecting the system.


## Lab finished.




































