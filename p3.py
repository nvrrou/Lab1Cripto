from scapy.all import rdpcap, IP, ICMP, Raw
from colorama import Fore, Style, init
import re

init(autoreset=True)

archivo = input("Archivo .pcap: ")
IP_DESTINO = "8.8.8.8"

paquetes = rdpcap(archivo)

mensaje = ""

# ---------------------------------
# Extraer mensaje del PCAP
# ---------------------------------
for paquete in paquetes:

    if (
        paquete.haslayer(IP)
        and paquete.haslayer(ICMP)
        and paquete.haslayer(Raw)
        and paquete[IP].dst == IP_DESTINO
        and paquete[ICMP].type == 8
    ):
        data = bytes(paquete[Raw].load)

        if len(data) >= 1:
            try:
                caracter = data[:1].decode("ascii")
                mensaje += caracter
            except UnicodeDecodeError:
                pass


print("\nMensaje cifrado:")
print(mensaje)

# ---------------------------------
# César
# ---------------------------------
def cesar_descifrar(texto, corrimiento):
    resultado = ""

    for caracter in texto:

        if 'A' <= caracter <= 'Z':
            resultado += chr(
                (ord(caracter) - ord('A') - corrimiento) % 26
                + ord('A')
            )

        elif 'a' <= caracter <= 'z':
            resultado += chr(
                (ord(caracter) - ord('a') - corrimiento) % 26
                + ord('a')
            )

        else:
            resultado += caracter

    return resultado


# ---------------------------------
# Evaluar qué resultado parece español
# ---------------------------------

palabras = [
    "el", "la", "los", "las", "un", "una",
    "de", "del", "que", "en", "es", "por",
    "para", "con", "como", "no", "se",
    "su", "mensaje", "hola", "este",
    "esta", "muy", "y", "o", "a"
]

def puntuar(texto):
    texto_lower = texto.lower()

    puntuacion = 0

    # Palabras frecuentes en español
    for palabra in palabras:
        coincidencias = re.findall(
            r'\b' + re.escape(palabra) + r'\b',
            texto_lower
        )
        puntuacion += len(coincidencias) * 5

    # Favorecer espacios
    puntuacion += texto.count(" ") * 0.5

    # Penalizar caracteres extraños
    for caracter in texto:
        if not (
            caracter.isalpha()
            or caracter.isspace()
            or caracter in ".,;:!?¿¡"
        ):
            puntuacion -= 2

    return puntuacion


# ---------------------------------
# Probar los 26 corrimientos
# ---------------------------------

resultados = []

for corrimiento in range(26):
    texto = cesar_descifrar(mensaje, corrimiento)
    puntuacion = puntuar(texto)

    resultados.append(
        (puntuacion, corrimiento, texto)
    )

# Ordenar de mayor a menor puntuación
resultados.sort(reverse=True)

mejor_puntuacion = resultados[0][0]

print("\nPosibles mensajes:")
print("=" * 70)

for puntuacion, corrimiento, texto in resultados:

    if puntuacion == mejor_puntuacion:
        print(
            Fore.GREEN
            + f"> Corrimiento {corrimiento:2d}: {texto}"
            + f"  [PUNTUACIÓN: {puntuacion}]"
            + Style.RESET_ALL
        )
    else:
        print(
            f"  Corrimiento {corrimiento:2d}: {texto}"
            f"  [PUNTUACIÓN: {puntuacion}]"
        )

print("=" * 70)

print(
    Fore.GREEN
    + f"\nMensaje más probable: {resultados[0][2]}"
    + Style.RESET_ALL
)
print(f"{resultados[0][1]}")
