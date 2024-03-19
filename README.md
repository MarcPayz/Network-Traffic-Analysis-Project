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

![Screenshot (192)](https://github.com/MarcPayz/Network-Traffic-Analysis-Lab/assets/163923336/3019b282-93dd-4e10-9927-ddd0ad620e0e)

After executnig the command "sudo wireshark", wireshark will open up and I was prompted with these options. I selected the option "eth0" which is the name of my network adapter. To find out the name of your network adapter, you can utilize the ifconfig command and it will prompt you with that information. 




