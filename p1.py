import argparse


def cifrado_cesar(texto, corrimiento):
    resultado = ""

    for caracter in texto:
        if caracter.isalpha():
            # Determinar si es mayúscula o minúscula
            inicio = ord('A') if caracter.isupper() else ord('a')

            # Aplicar el corrimiento y volver al inicio del alfabeto
            nuevo_caracter = chr(
                (ord(caracter) - inicio + corrimiento) % 26 + inicio
            )

            resultado += nuevo_caracter
        else:
            # Mantener espacios, números y signos
            resultado += caracter

    return resultado


parser = argparse.ArgumentParser(description="Cifrado César")

parser.add_argument(
    "texto",
    type=str,
    help="Texto que se desea cifrar"
)

parser.add_argument(
    "corrimiento",
    type=int,
    help="Cantidad de posiciones que se desplazará el texto"
)

args = parser.parse_args()

texto_cifrado = cifrado_cesar(args.texto, args.corrimiento)

print("Texto cifrado:", texto_cifrado)