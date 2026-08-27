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


# Parámetros de entrada
texto = input("Ingrese el texto a cifrar: ")
corrimiento = int(input("Ingrese el corrimiento: "))

# Cifrar el texto
texto_cifrado = cifrado_cesar(texto, corrimiento)

print("Texto cifrado:", texto_cifrado)
