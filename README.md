# 2IC80 Default Project
Implemenation of the default project. <br/>
<sup><sub>Disclaimer, this is a project for the course 2IC80 (2022-4) Lab on offensive computer security at the Eindhoven University of Technology.<sub/><sup/>
## Goals
Implementation of:
- ARP Poisoning Attack
- DNS Spoofing Attack
- SSL Stripping Attack
## Team
- Ayudh Haldar
- Salaheldin Salaheldin Mokhtar Diaa Abdelmoneim Nounou
- Divo Gede Arya Divo Abimanyu
- Aqiel Oostenbrug
## General Execution
```python
sudo python dp <victimip> <interface>
```
## ARP Poisoning Attack
```python
sudo python dp <victimip> <interface> -a -vtip <victimtwoip>
```
## DNS Spoofing Attack
```python
sudo python dp <victimip> <interface> -da -g <gatewayip> -dnsl <dnslist> -dnsil <dnsiplist>
```
## SSL Stripping Attack
```python
sudo python dp <victimip> <interface> -sa -g <gatewayip>
```
