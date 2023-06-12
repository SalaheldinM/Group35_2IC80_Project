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
Leads to the welcome and (attack) selection screen.
```python
sudo python dp <victimip> <interface>
```
## ARP Poisoning Attack
Direct execution form.
```python
sudo python dp <victimip> <interface> -a -vtip <victimtwoip>
```
## DNS Spoofing Attack
Direct execution form.
```python
sudo python dp <victimip> <interface> -da -g <gatewayip> -dnsl <dnslist> -dnsil <dnsiplist>
```
## SSL Stripping Attack
Direct execution form.
```python
sudo python dp <victimip> <interface> -sa -g <gatewayip>
```
