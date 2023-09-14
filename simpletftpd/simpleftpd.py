import sys
import socket
import random
from typing import Dict, Tuple

modes = {"netascii", "octet", "mail"}
block_size = 512

class SimpleTFTPd:
    def __init__(self, ip:str, port:int):
        self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listening_socket.bind((ip, port))

    def process_packets(self):
        while True:
            data, client_pair = self.listening_socket.recvfrom(1024)
            packet = self._decode_data(data)
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.settimeout(5)
            if packet['opcode'] == "RRQ":
                self._handle_read(packet, udp_socket, client_pair)
                print("[*] Read complete")
            elif packet['opcode'] == "WRQ":
                self._handle_write(packet, udp_socket, client_pair)
            else:
                raise Exception("[!] Invalid Initial opcode")

    def _handle_read(self, rrq:Dict[str,any], udp_socket:socket, client_pair:Tuple[str, int]):
        print(rrq)
        if rrq['mode'] != "octet":
            print("[!] Invalid Mode")
            self._handle_error(udp_socket, client_pair, 0, err_msg="Mode not supported.")
            return
        try:
            with open(rrq['filename'], 'rb') as file:
                content = file.read()
        except FileNotFoundError:
            print(f"[!] File not found {rrq['filename']}")
            self._handle_error(udp_socket, client_pair, 1, err_msg="File not found.")
            return
        print(f"[*] Read file {rrq['filename']}")
        
        # if content is less than block size just send it all and don't wait for an ack
        if len(content) < block_size:
            block = content
            self._send_block(udp_socket, client_pair, block, 1)
            return

        for i in range(0, len(content)+1, block_size):
            block_num = int(i/block_size) + 1
            print(f"[*] Sending block {block_num}")
            block = content[i:i+block_size]
            print(f"[*] Block size {len(block)}")
            for i in range(3):
                try:
                    self._send_block(udp_socket, client_pair, block, block_num)
                    self._recive_ack(udp_socket, client_pair, block_num)
                    break
                except socket.timeout:
                    print("[!] Connect timed out")
                    continue
        block_num += 1
        print(f"[*] Sent {i} bytes of {len(content)}")
        block = content[i:]
        print(f"[*] Block size {len(block)}")
        self._send_block(udp_socket, client_pair, block, block_num)
        print("[*] Read complete?")
        

    def _send_block(self, udp_socket:socket, client_pair:Tuple[str, int], block, block_num):
        packet = {'opcode':"DATA", 'block_num':block_num, 'data':block}
        print(packet)
        data = self._encode_packet(packet)
        udp_socket.sendto(data, client_pair)

    def _recive_ack(self, udp_socket:socket, client_pair:Tuple[str, int], block_num:int):
        for i in range(10):
            ack_data, ack_client_pair = udp_socket.recvfrom(1024)
            if client_pair == ack_client_pair:
                break
            print("[-] Received misaddressed packet from {ack_client_pair}") 
        if i == 10:
            raise Exception("Received too many misaddressed packets")
        ack_packet = self._decode_data(ack_data)
        print(ack_packet)
        if ack_packet['opcode'] != "ACK":
            print("[!] Not an ACK")
            raise Exception(f"Received invalid packet type {ack_packet['opcode']}, expected ACK")
        if ack_packet['block_num'] != block_num:
            print("[!] Wrong ACK")
            # handle error, or perhpas drop, check rfc 

    def _handle_write(self, wrq:Dict[str,any], udp_socket:socket, client_pair:Tuple[str, int]):
        self._send_ack(udp_socket, client_pair, 0)
        with open(wrq['filename'], "wb") as file:
            block_num = 1
            while True:
                packet = self._recive_data_packet(udp_socket, client_pair, block_num)
                self._send_ack(udp_socket, client_pair, block_num)
                file.write(packet['data'])
                print(packet)
                print(f"[*] Packet len: {len(packet['data'])}")
                if len(packet['data']) != 512:
                    break
                block_num += 1
        print("[+] Write complete")


    def _recive_data_packet(self, udp_socket:socket, client_pair:Tuple[str, int], block_num:int):
        for i in range(10):
            data, packet_client_pair = udp_socket.recvfrom(1024)
            if client_pair == packet_client_pair:
                break
            print("[-] Received misaddressed packet from {packet_client_pair}") 
        if i == 10:
            raise Exception("Received too many misaddressed packets")
        packet = self._decode_data(data)
        if packet['opcode'] != "DATA":
            print("[!] Not an DATA packet")
            raise Exception(f"Received invalid packet type {packet['opcode']}, expected DATA")
        if packet['block_num'] != block_num:
            print("[!] Wrong DATA packet")
            # handle error, or perhpas drop, check rfc handle error
        return packet

    def _send_ack(self, udp_socket:socket, client_pair:Tuple[str, int], block_num):
        packet = {'opcode': "ACK", 'block_num': block_num}
        data = self._encode_packet(packet)
        udp_socket.sendto(data, client_pair)


    def _handle_error(self, udp_socket:socket, client_pair:Tuple[str, int], error_code:int, err_msg:str = ""):
        packet = {'opcode': "ERROR", 'error_code': error_code}
        packet['err_msg'] = err_msg 
        data = self._encode_packet(packet)
        udp_socket.sendto(data, client_pair)

    def _decode_data(self, data:bytes) -> Dict[str, any]:
        opcode = int.from_bytes(data[0:2], 'big')
        if opcode == 1 or opcode == 2:
            return self._decode_rq_packet(data, opcode)
        elif opcode == 3:
            return self._decode_data_packet(data)
        elif opcode == 4:
            return self._decode_ack_packet(data)
        elif opcode == 5:
            return self._decode_error_packet(data)
        else:
            raise Exception(f"Invalid Packet: Invalid opcode {opcode}")
    
    def _decode_rq_packet(self, data:bytes, opcode:int) -> Dict[str,any]:
        packet = {}
        packet['opcode'] = "RRQ" if opcode == 1 else "WRQ"
        filename_terminator_index = data[2:].find(b'\x00') + 2
        # Should probably make sure these indices are within the length of 
        if filename_terminator_index == -1:
            raise Exception("Invalid Packet: Unterminated filename")
        packet['filename'] = data[2:filename_terminator_index].decode('ascii')
        mode_terminator_index = data[filename_terminator_index+1:].find(b'\x00') + filename_terminator_index + 1
        if mode_terminator_index == -1:
            raise Exception("Invalid Packet: Unterminated mode")
        mode = data[filename_terminator_index+1:mode_terminator_index].decode('ascii')
        if mode not in modes:
            raise Exception("Invalid Packet: Invalid mode")
        if mode == "mail":
            # Should send error packet 
            raise Exception("Invalid Packet: Mail mode unsupported")
        packet['mode'] = mode
        return packet

    def _decode_data_packet(self, data:bytes) -> Dict[str,any]:
        packet = {}
        packet['opcode'] = "DATA"
        if len(data) < 4:
            raise Exception("Invalid Packet: DATA packet too short")
        packet['block_num'] = int.from_bytes(data[2:4], 'big')
        packet['data'] = data[4:]
        if len(packet['data']) > 512:
            raise Exception("Invalid Packet: DATA packet too long")
        return packet

    def _decode_ack_packet(self, data:bytes) -> Dict[str,any]:
        packet = {}
        packet['opcode'] = "ACK"
        if len(data) != 4:
            raise Exception("Invalid Packet: ACK packet has incorrect length") 
        packet['block_num'] = int.from_bytes(data[2:4], 'big')
        return packet

    def _decode_error_packet(self, data:bytes) -> Dict[str,any]:
        packet = {}
        packet['opcode'] = "ERROR"
        if len(packet) < 5:
            raise Exception("Invalid Packet: ERROR packet too short")
        packet['error_code'] = int.from_bytes(data[2:4], 'big')
        err_msg_terminator_index = data[4:].find(b'\x00') + 4
        if err_msg_terminator_index == -1:
            raise Exception("Invalid Packet: Unterminated error string")
        packet['err_msg'] = data[1:err_msg_terminator_index].decode('ascii')
        return packet

    def _encode_packet(self, packet:Dict[str, any]) -> bytes:
        if packet['opcode'] == "RRQ" or packet['opcode'] == "WRQ":
            return self._encode_rq_packet(packet)
        elif packet['opcode'] == "DATA":
            return self._encode_data_packet(packet)
        elif packet['opcode'] == "ACK":
            return self._encode_ack_packet(packet)
        elif packet['opcode'] == "ERROR":
            return self._encode_error_packet(packet)
        else:
            raise Exception(f"Invalid Packet: Invalid opcode {packet['opcode']}")

    def _encode_rq_packet(self, packet:Dict[str,any]):
        data = b'\x00\x01' if packet['opcode'] == "RRQ" else b'\x00\x02'
        data += packet['filename'].encode('ascii')
        data += b'\x00'
        if packet['mode'] not in modes:
            raise Exception("Invalid Packet: Invalid mode")
        data += packet['mode'].encode('ascii')
        data += b'\x00'
        return data

    def _encode_data_packet(self, packet:Dict[str,any]):
        data = b'\x00\x03'
        if packet['block_num'] >= 2**16 or packet['block_num'] < 0:
            raise Exception("Invalid Packet: Invalid block number")
        data += packet['block_num'].to_bytes(2, 'big', signed=False)
        if len(packet['data']) > 512:
            raise Exception("Invalid Packet: DATA packet too long")
        data += packet['data']
        return data

    def _encode_ack_packet(self, packet:Dict[str,any]):
        data = b'\x00\x04'
        if packet['block_num'] >= 2**16 or packet['block_num'] < 0:
            raise Exception("Invalid Packet: Invalid block number")
        data += packet['block_num'].to_bytes(2, 'big', signed=False)
        return data

    def _encode_error_packet(self, packet:Dict[str,any]):
        data = b'\x00\x05'
        if packet['error_code'] >= 2**16 or packet['error_code'] < 0:
            raise Exception("Invalid Packet: Invalid error code")
        data += packet['error_code'].to_bytes(2, 'big', signed=False)
        data += packet['err_msg'].encode('ascii')
        data += b'\x00'
        return data

    def close(self):
        self.listening_socket.close()


def main(argv:[str]) -> int:
    # Add some arg parse magic here
    server = SimpleTFTPd("127.0.0.1", 69)
    server.process_packets()
    return 0

if __name__ == "__main__":
    exit(main(sys.argv))
