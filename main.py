#!/usr/local/bin/python3

import requests
import subprocess
import sys
import datetime
import time
import psutil
import json

version = "1.0.0"


def azire_get_ports(ip, tkn):
    url = 'https://api.azirevpn.com/v3/portforwardings?internal_ipv4={}'.format(ip)
    token = {'Authorization': 'Bearer {}'.format(tkn)}
    resp = requests.get(url, headers=token)
    resp_json = resp.json()
    status = resp_json['status']
    if status == "success":
        return resp_json["data"]["ports"][0]["port"]
    else:
        return azire_open_port(ip, token)


def azire_open_port(ip, token):
    url = 'https://api.azirevpn.com/v3/portforwardings'
    #token = {'Authorization': 'Bearer {}'.format(tkn)}
    body = {
        "internal_ipv4": ip,
        "hidden": False,
        "expires_in": 0
    }
    resp = requests.post(url, headers=token, json=body)
    resp_json = resp.json()
    status = resp_json['status']

    if status == "success":
        port = resp_json['data']['port']
        return str(port)
    else:
        message = resp_json['message']
        if message == "Input data is invalid":
            return ""

        print(message)
        return ""


def qbit_auth(config):
    url = f'http://{config["qbit_server_ip"]}:{config["qbit_server_port"]}/api/v2/auth/login'
    login_data = {
        'username': f'{config["username"]}',
        'password': f'{config["password"]}'
    }
    headers = {
        'Referer': f'{config["qbit_server_ip"]}:{config["qbit_server_port"]}'
    }
    session = requests.Session()

    response = session.post(url, data=login_data, headers=headers)

    return session.cookies


def qbit_set_port(config):
    cookies = qbit_auth(config)

    url = f'http://{config["qbit_server_ip"]}:{config["qbit_server_port"]}/api/v2/app/setPreferences'
    data = {
        'json': f'{{"listen_port": "{config["torrent_port"]}"}}'
    }
    response = requests.post(url, data=data, cookies=cookies)


def qbit_get_port(config):
    cookies = qbit_auth(config)
    url = f'http://{config["qbit_server_ip"]}:{config["qbit_server_port"]}/api/v2/app/preferences'
    try:
        response = requests.post(url, cookies=cookies)

        return response.json()["listen_port"]
    except:
        return ""


def write_log(config, message):
    print(message)
    if config["log_file"]:
        with open(config["log_file"],"a") as file:
            file.write(f"{datetime.datetime.now()} - {message}\n")


def qbit_check_running():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == "qbittorrent":
            return True
    return False


def qbit_start():
    subprocess.run(['service', 'qbittorrent', 'onerestart'])


def run():

    with open('config.json') as f:
        cfg = json.load(f)

    write_log(cfg, f"Starting Script v{version}")

    while True:
        port = cfg['qbit_torrent_port']

        if not port:
            try:
                port = azire_get_ports(cfg['azire_ip'], cfg['azire_token'])
                if not port:
                    write_log(cfg, "Failed getting port from azire")
                    time.sleep(300)
            except:
                write_log(cfg, "Failed communicating with azire")
                time.sleep(300)
                continue

        config = {
            "qbit_server_ip": cfg['qbit_server_ip'],
            "qbit_server_port": cfg['qbit_server_port'],
            "username": cfg['username'],
            "password": cfg['password'],
            "torrent_port": port,
            "azire_ip": cfg['azire_ip'],
            "azire_token": cfg['azire_token'],
            "log_file": cfg['log_file']
        }

        qbit_port = qbit_get_port(config)

        try:
            if str(qbit_port) != config["torrent_port"]:
                qbit_set_port(config)
                write_log(config, f'old port: {qbit_port} new port: {config["torrent_port"]}')
        except:
            write_log(config, "Failed to set qbit port")
            break
        time.sleep(60)


if __name__ == '__main__':
    run()
