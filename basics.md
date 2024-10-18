These are the same of the tools we are going to use


 Reverse Engineering
 RAT Tools
 Web Crawling
 Payload Injector
 Multitor Tools update
 Added Tool in wifijamming
 Added Tool in steganography

Anonymously Hiding Tools
Information gathering tools
Wordlist Generator
Wireless attack tools
SQL Injection Tools
Phishing attack tools
Web Attack tools
Post exploitation tools
Forensic tools
Payload creation tools
Exploit framework
Reverse engineering tools
DDOS Attack Tools
Remote Administrator Tools (RAT)
XSS Attack Tools
Steganograhy tools
Other tools
SocialMedia Bruteforce
Android Hacking tools
IDN Homograph Attack
Email Verify tools
Hash cracking tools
Wifi Deauthenticate
SocialMedia Finder
Payload Injector
Web crawling
Mix tools
Anonymously Hiding Tools
Anonmously Surf
Multitor
Information gathering tools
Network Map (nmap)
Dracnmap
Port scanning
Host to IP
Xerosploit
RED HAWK (All In One Scanning)
ReconSpider(For All Scanning)
IsItDown (Check Website Down/Up)
Infoga - Email OSINT
ReconDog
Striker
SecretFinder (like API & etc)
Find Info Using Shodan
Port Scanner - rang3r (Python 2.7)
Port Scanner - Ranger Reloaded (Python 3+)
Breacher
Wordlist Generator
Cupp
WordlistCreator
Goblin WordGenerator
Password list (1.4 Billion Clear Text Password)
Wireless attack tools
WiFi-Pumpkin
pixiewps
Bluetooth Honeypot GUI Framework
Fluxion
Wifiphisher
Wifite
EvilTwin
Fastssh
Howmanypeople
SQL Injection Tools
Sqlmap tool
NoSqlMap
Damn Small SQLi Scanner
Explo
Blisqy - Exploit Time-based blind-SQL injection
Leviathan - Wide Range Mass Audit Toolkit
SQLScan
Phishing attack tools
Setoolkit
SocialFish
HiddenEye
Evilginx2
I-See_You(Get Location using phishing attack)
SayCheese (Grab target's Webcam Shots)
QR Code Jacking
ShellPhish
BlackPhish
Web Attack tools
Web2Attack
Skipfish
SubDomain Finder
CheckURL
Blazy(Also Find ClickJacking)
Sub-Domain TakeOver
Dirb
Post exploitation tools
Vegile - Ghost In The Shell
Chrome Keylogger
Forensic tools
Autopsy
Wireshark
Bulk extractor
Disk Clone and ISO Image Acquire
Toolsley
Volatility3
Payload creation tools
The FatRat
Brutal
Stitch
MSFvenom Payload Creator
Venom Shellcode Generator
Spycam
Mob-Droid
Enigma
Exploit framework
RouterSploit
WebSploit
Commix
Web2Attack
Reverse engineering tools
Androguard
Apk2Gold
JadX
DDOS Attack Tools
SlowLoris
Asyncrone | Multifunction SYN Flood DDoS Weapon
UFOnet
GoldenEye
Remote Administrator Tools (RAT)
Stitch
Pyshell
XSS Attack Tools
DalFox(Finder of XSS)
XSS Payload Generator
Extended XSS Searcher and Finder
XSS-Freak
XSpear
XSSCon
XanXSS
Advanced XSS Detection Suite
RVuln
Cyclops
Steganograhy tools
SteganoHide
StegnoCracker
StegoCracker
Whitespace
Other tools
SocialMedia Bruteforce
Instagram Attack
AllinOne SocialMedia Attack
Facebook Attack
Application Checker
Android Hacking tools
Keydroid
MySMS
Lockphish (Grab target LOCK PIN)
DroidCam (Capture Image)
EvilApp (Hijack Session)
HatCloud(Bypass CloudFlare for IP)
IDN Homograph Attack
EvilURL
Email Verify tools
Knockmail
Hash cracking tools
Hash Buster
Wifi Deauthenticate
WifiJammer-NG
KawaiiDeauther
SocialMedia Finder
Find SocialMedia By Facial Recognation System
Find SocialMedia By UserName
Sherlock
SocialScan | Username or Email
Payload Injector
Debinject
Pixload
Web crawling
Gospider
Mix tools
Terminal Multiplexer



Hello, aspiring Ethical Hackers. In this blogpost, you will learn about different security technologies that are used in an organization to protect the network against cyber-attacks. Various devices and software come into play while protecting the organization from a variety of threats. Let’s learn about each of them.
![Security_technologies_1-1](https://github.com/user-attachments/assets/d76a9292-a592-422e-9233-3f974c75107a)

1. Firewall:

A firewall is the most common defensive measure that is used in organizations against cyber attacks. It can be considered the first layer of defense against hackers. Just as its name implies, it works as a wall between two networks thus preventing malicious traffic from entering the network of the organization. Learn more about firewalls here.

2. Anti-Malware:

In one of our previous articles, you learnt about virus and malware. Anti virus protects the computers and other devices in the network from this malicious software. Learn more about Antivirus.

3. Intrusion Detection System (IDS):

An Intrusion Detection System (IDS) monitors the entire traffic of the network and as soon as it sees any traffic that it considers malicious, it raises an alert. Learn more about IDS.

4. Intrusion Prevention System (IPS):

An Intrusion Prevention System (IPS) is one step above IDS. It performs the functions just like an IDS, but whenever it detects malicious traffic, it tries to prevent the connection by dropping the packets. Learn more about Intrusion Prevention System (IPS).

5. Endpoint Detection & Response (EDR):

Endpoint Detection and Response is used to monitor end user devices on the network for malware and acts against them if needed.

6. Honeypot:

Sometimes, organizations need to understand what hackers would be interested in once they are in their network. A honeypot serves this purpose. A honeypot acts as a juicy target and attracts towards thus preventing them from hacking anything in the original network. A honeypot designed with a lot of vulnerabilities that can keep the hackers constantly interested. Learn more about honeypots.

7. Demilitarized Zone (DMZ):

A demilitarized zone is a network used to add an external layer of security to the organization’s network. Usually placed at the perimeter, it has access to the external network. It usually contains an external facing service.

8. Data-Loss Prevention (DLP):

Data Loss Prevention (DLP) ensures that no confidential data is being sent out of the organization’s network. Confidential data refers to data that once exposed to the internet can harm the security of the network.

9. Security Incident & Event manager (SIEM):

A security Incident & Event Manager raises an alert if it detects any malicious activity. That’s all about the various security technologies.

Category: Basics
Posted on January 1, 2024 by kanishka10
Beginners guide to Steganography
Hello aspiring Ethical Hackers. In this blogpost, you will learn about steganography. Before you learn what is it, you need to learn why are we learning about it. In Feb 2023, Red Eyes Hacking Group (APT37) used a jpg image as attachment in one of their spear phishing email. When victims clicked on this image, it triggered an exploit that ran shellcode on the victim’s computer to download and execute a malicious payload that is stored within the jpg file mentioned above. But how was the malicious payload was hidden inside the jpg image?

What is Steganography?

It is an art or technique of hiding secret or any precious information inside something that looks common & ordinary. This information is hidden in such a manner that its presence is not evident to the human inspection. The word stegano graphy came from Greek word steganographic, that is combination of words steganos (meaning hidden or concealed) and graphia (writing).

In ancient and medieval times, kings used steganography to forward messages secretly. Greeks were the fist to use it. Coming to modern times, hackers are using it to hide malicious code in images, text, files, audio, video film and any other medium that looks benign.

Types of Steganography

There are five types of stegano graphy. They are,

Text stegano graphy
Image stegano graphy
Video stegano graphy
Audio stegano graphy
Network Stegano graphy
steganography
1. Text Steganography::

In text steganography, the secret information is hidden in a piece of text. For example, let’s say a text contains “Indians love Unity”. This may look like an ordinary or normal text. But just take the first letter of these three words. That becomes “ILU” a shortcut for I Love You message used by youngsters.

2. Image Steganography:

As you might have already expected, when the secret information is hidden in an image (digital image) it is known as Image steganography.

3. Audio Steganography:

If the information we want to hide is hidden in an audio, it is known as audio steganography. Humans can hear sound that only contains certain frequencies. So, by altering the properties of audio like frequency, amplitude etc. secret messages can be hidden. However, to be able to receive and understand this secret information, the receiver needs to have smart listening devices to decipher the hidden information.

4. Video Steganography:

If the secret information is hidden in a video, it is called video steganography. A video is simply a representation of a sequence of consecutive images. So, we can say that this is an advanced version of Image steganography.

5. Network Steganography:

Considered to be more advanced and practically useful to Black Hat Hackers, in Network steganography information is hidden in network traffic. For example, it can be hidden in the TCP/IP headers etc.

Examples of Steganography attacks in hacking

In September 2022, researchers at ESET discovered a previously unknown Threat actor they named Worok hiding malicious payload in PNG files.
In 2019, researchers at Symantec observed a Russian cybersecurity group waterbug (also known as just the malicious) delivering a publicly known backdoor by hiding it in a WAV file.
In the same year, security researchers at Cylance observed a hacking campaign that was delivering XMRIG Monero CPU miner by hiding them in WAV files.
PLATINUM hacker group, that usually targets Governments of South Asia and South East Asia, embedded their malware commands in the HTML code of a website. They achieved this by encoding malware commands in a specific sequence of “TAB” and “SPACE” bar.
In future steganography is going to increase in cyber security.

Category: Basics
Posted on December 25, 2023 by kanishka10
Privilege Escalation guide for beginners
Hello aspiring Ethical Hackers. In this blogpost, you will learn in detail and clearly about Privilege escalation. Privilege escalation is an act of gaining elevated access to resources that are normally restricted to an application or user. To understand privilege escalation better, you need to first understand about privileges. Since hacking mostly deals with exploiting of operating systems, let me explain you about how privileges in a operating system are assigned.

Since Operating Systems (OS) are meant for user interaction and perform some specific functions you should have noticed that different users are assigned different privileges on a system.

Let’s see the example of the Windows operating system. Windows OS has generally 7 types of accounts. When I am talking about accounts, I am talking about local user accounts instead of remote or online accounts. A local user account is defined locally on a device (computer) and are assigned rights and permissions on that particular device only. The types of Windows user accounts are given below.


When you do a fresh installation of Windows (Windows 7 to 11), the first user account that is created during setup is the Administrator account, As the name suggests, the Administrator account is a default local user account (account created during Windows installation) used for system administration. This account has full control of the files, directories, services and other resources on the local device. As you might have experienced by now, an administrator account can create, delete and assign permissions to other users.

This default Administrator account can neither be deleted or locked but it can be disabled or renamed. Windows setup disables the built-in administrator account after installation of Windows and creates another local account that is a member of the administrators group.




The newly created user belonging to the Administrator group has same powers as the default administrator account. Since this is too risky if some malicious user gains access to the system as Administrator user, Windows provides option to create an account called standard account. Most organization provide their workers a standard account. A standard account on Windows can run almost all application on a Windows system and perform all other day-to-day computing tasks.

However, to perform some tasks like installing programs or applications, making changes to the registry etc and other operations that require elevated privileges, the standard user is asked for credentials of Administrator of the system through the user Account control. Simply put, you cannot make any major changes to the operating system with standard account.


Apart from these two accounts, Windows has some default local user accounts that are automatically created while operating system is installed. They first one you need to learn about is the “SYSTEM” account. This account is used by the operating system and its services running under Windows. This account doesn’t show up in user manager which means you cannot login with this account.

It belongs to Windows and used by all Windows processes. You can view the processes running with this “SYSTEM” privileges from details tab of the Window Task Manager.


The ms08_067 vulnerability affected a process svchost.exe that runs with SYSTEM privileges. So, once you exploit it, you automatically get SYSTEM privileges. It can be exploited remotely and grant SYSTEM PRIVILEGS to attackers. No wonder it is considered very CRITICAL.

Another local default user account is the “Network service” account. This account is used by the service control manager (SCM). It is used to present the computer credentials while it is communicating with remote servers. Similarly, Windows has an account called “Local Service” which is also used by the service control manager. It has minimum privileges on the local computer.


Linux systems too have different types of user accounts. They are 1) Super user account 2) Regular account 3) System account 4) Service accounts.


On Linux, the Super User account is the most powerful account and is the default administrator of the Linux system. This account is popularly known as root account. The root account has unlimited control on the Linux system and you can literally do anything you want with this account.


The root user in Linux has (#) symbol on their terminal. All other users who are later added are together known as regular accounts. Regular accounts are similar to “standard account” on Windows and to perform administrative actions on the OS, they need to use sudo or su command. Apart from these two accounts, Linux has “system account” and “service account” that are created during the installation of the OS and are by OS processes just like “SYSTEM account on Windows. However, these accounts don’t run with superuser privileges. Service accounts are created whenever a service is installed on the system.



Since you are now accustomed with privileges and user accounts with different privileges, you can now understand privilege escalation.

What is privilege escalation?

Privilege escalation is an act or process of gaining access to privileges of the other user account using any means or techniques. Normally privileges of user account with higher privileges are targeted by hackers.


Privilege escalation is of two types: They are,

Horizontal privilege escalation.
Vertical privilege escalation.
1. Horizontal Privilege Escalation:

In horizontal privilege escalation, an attacker gaining access to the privileges of another user with same rights as him but with access to some other resources. For example, imagine on a Linux system, you gained access as a regular user (user_1). On the same system, there is another regular user (user_2) with same rights as him but with access to the MySQL databases. Elevating privileges to this user (user_2) can give you access to MySQL database.



2. Vertical Privilege escalation:

In cyber security or hacking, when anyone says “privilege escalation”, they are talking about this type of privilege escalation most of the time. In vertical privilege escalation, an attacker with low privileges tries to gain access to higher privileges.



Techniques used for Privilege escalation

Attackers use various techniques to elevate privileges. Some of the most general techniques are given below.

1. Social Engineering:

In Social Engineering, attackers somehow convince high privileges users to give access their credentials. These techniques include phishing, spear phishing attacks etc. For example, let’s say the attackers gained access to the email of the user with low privileges. From this email, he/she can send an email to the user with high privileges and somehow convince him/her to give any credentials.

In the first week top of September 2023, Okta, a company providing Identity services warned its users of social engineering attacks to obtain super administrator privileges on the organizations using Okta’s services. In these attacks, attackers performed social engineering attacks against IT service desk personnel by calling them and convincing them to reset multi-factor authentication (MFA’s) of high privileged users. Then attackers (allegedly APT Muddled Libra) abused these high privileged super admin accounts to impersonate users of the compromised organizations.

2. Password cracking:

Sometimes attackers crack the passwords of high privileged users to be used in privilege escalation.

3. Exploiting vulnerabilities:

This is one of the popular methods of escalating privileges. In this technique, attackers exploit vulnerability in software installed on the target system to elevate privileges. For example, PrintNightmare, Zerologon, Fodhelper etc in Windows and Dirtypipe, DirtyCow, PWNKIT, Netfilter, Heartbleed and Looney Tunables.

4. Misconfigurations:

In this type of attack, attackers use any misconfiguration on the target system for privilege escalation. These misconfigurations can include weak passwords, setting empty string as password, unsecured network service, open ports and exposed services etc. Examples are exploiting cronjobs and exploiting SetUID bits etc.

Many APT’s and Threat Actors exploit the recently (before patches are applied) released local privilege escalation vulnerabilities to elevate their privileges.

Categories: Basics, Privilege Escalation
Posted on December 3, 2023 by kanishka10
Beginners guide to Computer Virus
Hello aspiring Ethical Hackers. In this blogpost, you will learn in detail about computer virus. In our previous article on malware, you have read that virus is one type of malicious software.

What is a VIRUS?

Virus stands for Vital Information Resources Under Seize (VIRUS). Once a computer virus infects any system it tries to seize is resources. Like it’s pathological name sake, a virus attaches itself to an executable or program to propagate or infect computers. VIRUS always requires human action or interaction to infect systems. Let’s now study about different types of Virus and what resources they affect.


Types of Computer VIRUS

1. Browser Hijacker:

Have you ever opened your browser and noticed that all of its settings have changed? These settings include but not restricted to the URL of the home page, favorites and even the default search engine. Well, this is the case of a Browser Hijacker. It is called so because it simply hijacks your browser to alter its settings and also redirect to a phishing site or to display advance.

Browser hijackers are used by hackers to earn some good amount of money. For example, a browser hijacker named CoolWebSearch infected victim’s browsers and redirected the homepage and search results to the links the hackers wanted. Every time a victim clicked on these links, the hacker was paid money.

2. Web scripting virus:

A web scripting is a virus that exploits vulnerabilities in browser to infect web pages or websites and inject malicious code. This virus is useful to send spam or for stealing cookies.

3. File Infector virus:

One of the most common viruses, file infector virus infects files and copies itself into other executable programs such as .COM and EXE files. Some file infecting viruses infect critical system files too thus affecting the operating system.

4. Macro virus:

Macro virus is a virus that is written in the language of Microsoft Office macros or Excel Macros. They are embedded into a Word document on Excel file

5. Direct Action virus:

Also known as Non-resident virus, this type of virus directly connects itself to executables like EXE and COM file. This virus is also known as Non-resident Virus as it doesn’t install itself on the target system. Direct Action Virus becomes active only when the victim executes the file.

6. Resident virus:

Resident virus install itself in the memory to the system and then from there, infects other files while they are opened by the users.

7. Boot Sector virus:

This type of virus infects the Master Boot Sector of the hard disk or a USB drive. Master Boots Record (MBR) is the boot sector that is located at the very beginning of partition table. It contains information about operating system’s location and how it can be booted. Once this section is infected, the infected system will face bootup problems etc.

8. Multipartite virus:

A virus that uses multiple methods to infect the target system is known as multipartite virus.

9. Polymorphic virus:

A polymorphic virus or metamorphic virus is a virus that constantly changes its appearance or signature files to avoid detection.

Categories: Basics, Hacking, Gaining Access
Posted on November 24, 2023 by kanishka10
Malware guide for absolute beginners
Hello, aspiring ethical hackers. This blogpost is intended to be a beginner’s guide to malware. This blogpost will teach you what is malware, its purpose, types of malware and functions of malware.

What is Malware?

Malware stands for malicious software. So, any software that performs malicious actions on a computer or mobile is called as malware. These malicious actions include showing persistent popups, encrypting data, stealing data, deleting data, capturing sensitive information and making the target system completely unusable etc. Based on its functions, and purpose malware can be classified into various types.


Types of Malware

VIRUS

Often used interchangeably with malware, virus is the most popular malware you may encounter in cyber security. Just like its pathological namesake, virus attaches itself to an executable or program to propagate or infect computer. Virus always requires human action to infect system.

According to Discovery, the first virus is the Creeper program. It was created by Bob Thomas in 1971. It was actually designed as a security test to see if a self-replicating program will be successful. The function of Creeper was to just display a simple message on computer if infected.


The most popular (or should I say unpopular) virus should be ILOVEYOU virus. Released in 2000, ILOVEYOU infected over ten million Windows computers. It started spreading as an email message with subject line “I LOVE YOU” and contained an attachment with name “LOVE-LETTER-FOR-YOU.TXT.VBS. When the recipient clicked on this attachment, a Visual Basic script activated and over writes files on the infected system. Then, it sent itself to all the email addresses in the Windows Address Book. It is estimate that the cost of this simple virus was at least $15 billion.


WORM

A computer worm is a type of malware that unlike virus doesn’t need any human action or interaction to infect target systems. Usually a computer worm spreads by exploiting vulnerability on the target systems. They also have no need to attach themselves to any program or executable.


Morris worm is considered to be the first worm to spread over the internet. It was created by Robert Tappan Morris and it caused a loss of over $100,000 and $10,000,000. It infected over 2000 computers within 15 hours. Morris worm spread by exploiting vulnerabilities like holes in the debug mode of the Unix send mail program, a buffer overflow vulnerability in finger network service. Rexec and Rsh accounts with weak or no password at all.


The most unpopular worm should definitely be Stuxnet. Released in 2010 and accused of sabotaging nuclear program of Iran, Stuxnet was designed to target programmable logic controllers (PLCs). These PLC’s allow automation of electromechanical process used by control machines and industrial processes (for example, gas centrifuge that are used to separate nuclear material). Stuxnet spread by exploiting 4 Zero-day vulnerabilities in Siemens setup7 software installed on Windows systems. Stuxnet infected almost over 2,00,000 computers and destroyed at least 100 machines.


TROJAN

A Trojan acts as some other file (usually benign, genuine and harmless) but performs malicious actions. The name is a reference to the Trojan horse (the large wooden horse) assumed by Trojans as gift given by Greeks to Troy. However, when the horse was let into the kingdom, Greek soldiers hiding inside the horse came out and ransacked Troy. (you should watch Troy movie).


Just like viruses, Trojans also need victims to click on Trojan to be activated and most users fall victim to trojans thinking that they are genuine files. ANIMAL, a program released in 1975 is generally considered the world’s first Trojan. It fooled victims by presenting itself as a simple game of 20 questions. When user clicked on it, it copied itself to shared directories to be found by other victims.


According to me, the most dangerous Trojan was Zeus. Zeus is a banking Trojan used to steal banking information. It is spread by drive by downloads and phishing in 2003. It is estimated that Zeus infected over 74,000 FTP accounts.


ADWARE

Adware stands for Advertising malware. Have you ever experienced you are viewing something in your favorite browser and you are being incessantly bombarded with ads, especially ads which you did not and never wanted? If you had that experience you have encountered adware and if you didn’t it is thanks to ad blockers enabled by almost all browsers. Note that Adware is sometimes genuine too.

SPYWARE

Spyware is short for spying software and now you know what it does. It spies and gathers information about a user or organization. Spyware may be present in even legitimate software. The first recorded spyware is considered to be a freeware game called “Elf Bowling” as it came bundled with tracking software.

The most popular spyware seen recently should be Pegasus spyware. This spyware developed by Israeli cyber arms firm NSO Group installs not just covertly but remotely on mobile phones running IOS and Android and that too using a Zero-click exploit. Once installed on a device, Pegasus can read text messages, snoop on calls, collect credentials, track location of the device, access device’s cameras and microphone and harvest information from apps installed on the target device.


KEYLOGGER

Keylogger is a malicious software that records keystrokes a user types into computer on mobiles. The first keylogger used in real world was allegedly distributed with Grand Theft Auto V mod in 2015. Recently, a keylogger named Snake keylogger was detected being distributed with Microsoft Excel sample. Snake keylogger first appeared in late 2020.


ROOTKIT

Rootkit is a malicious software that is designed to enable access to a computer in a way that is not usually possible to an authorized user. Simply put, Rootkit gives SYSTEM level access. As if this is not enough, Rootkit is undetectable once installed, unlike other types of malware. The term “Rootkit” is a combination of root (the most privileged account on Unix system and “kit”. This is because rootkits usually give ‘root’ level access to the target system.

The first malicious rootkit appeared in 1999 and it affected Windows NT OS. In 2012, a rootkit named Flame was detected. Flame affected over 80 servers around the world and is considered one of the dangerous rootkits.


BACKDOOR


A backdoor is a type of malware that provides access to a system bypassing normal security measures that usually prevent access. For example, if you can access a system without providing any login or need of credentials, you have a Backdoor access. Usually, hackers install backdoor after gaining complete access to the system to have unhindered and continuous access in future.

In 1998, a U.S hacker group “Cult of the Dead cow” designed a backdoor named “Back Orifice” that enables a user to control a computer remotely. In 2014, multiple backdoors were detected in WordPress. These backdoors were WordPress plugins with an obfuscated JavaScript code.

BOT

A BOT is a shortcut for Robot and it is an automated piece of code that performs predefined tasks. Malicious Bots as normally used to infect a system and make them a part of a Botnet which can then be used to perform DDOS attacks.


In 2007, all botnet attack called Cutwail attacked Windows systems using a trojan named Pushdo which infected Windows systems to make them part of the Cutwail botnet. This botnet had over 1.5 to 2 million computers. The most famous BOT malware should be MIRAI. MIRAI is designed to infect smart devices that run on ARC processes.


RANSOMWARE

Ransomware is a malicious software that locks victim’s computers or encrypts the victim’s files or permanently block access to the victim’s system. Its called ransomware as the key to decrypt the data or access the system is not provided unless a ransom is paid.

The first known ransomware was AIDS Trojan. It’s payload hid the files on the victim’s hard drive and encrypted their names. The most dangerous & popular ransomware attack was WannaCry in 2017. WannaCry ransomware spread by exploiting EternalBlue vulnerability and it infected over 2,30,000 computers within one day.


This score depends on the additional work that has to be put by attacker to exploit the vulnerability. For example, exploiting EternalBlue does not need any additional work by attacker whereas to performing a Man-In middle attack requires additional work from the attacker. Usually, the additional work the attacker puts depends on factors which are out of control of the attacker.

CRYPTO MINER

Crypto mining malware or cryptojacker is a malicious software that targets computer sources and mines crypto currencies like Bitcoin. Cryptominers are rather new in the evolution of malware. Their growth directly grew with the growth in popularity of crypto currencies.
