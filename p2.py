from scapy.all import IP, ICMP, send, Raw

destino = input("IP de destino: ")
mensaje = input("Mensaje: ")

cantidad = len(mensaje)

#Pasamos la data de un ping normal a ASCII
hexadecimal = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"

datos = bytes.fromhex(hexadecimal)

for i in range(cantidad):
    #encriptamo el icmp, y le añadimos los datos, uwu
    paquete = IP(dst=destino) / ICMP() / Raw(load=mensaje[i].encode()) / datos

    print(
        f"Enviando paquete {i + 1}/{cantidad}: "
        f"{paquete.summary()}"
    )

    send(paquete, verbose=False)

print("Envío terminado.")
