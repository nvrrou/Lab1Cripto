from scapy.all import IP, ICMP, Raw, send
import struct
import time
import os

destino = input("IP de destino: ")
mensaje = input("Mensaje cifrado: ")

icmp_id = os.getpid() & 0xffff
ip_id = int(time.time()) & 0xffff

# 10 11 12 ... 37
padding = bytes(range(0x10, 0x38))

for i, caracter in enumerate(mensaje):

    ahora = time.time()

    segundos = int(ahora)
    microsegundos = int(
        (ahora - segundos) * 1_000_000
    )

    # 8 bytes de timestamp
    timestamp = (
        struct.pack("!I", segundos & 0xffffffff)
        + b"\x00" * 4
    )

    micro = microsegundos.to_bytes(
        3,
        byteorder="little"
    )

    # 3 bytes:
    # [letra][2 bytes relacionados al tiempo]
    datos_3 = (
        caracter.encode("ascii")
        + micro[1:3]
    )

    # 5 bytes 00
    ceros = b"\x00" * 5

    # 8 + 3 + 5 + 40 = 56 bytes
    payload = (
        timestamp
        + datos_3
        + ceros
        + padding
    )

    paquete = (
        IP(
            dst=destino,
            ttl=64,
            id=(ip_id + i) & 0xffff
        )
        /
        ICMP(
            type=8,
            code=0,
            id=icmp_id,
            seq=i + 1
        )
        /
        Raw(load=payload)
    )

    send(
        paquete,
        verbose=False
    )

    print(
        f"Enviado {i + 1}/{len(mensaje)} "
        f"seq={i + 1}"
    )

    time.sleep(1)

print("Envío terminado.")